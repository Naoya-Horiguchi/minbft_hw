// Copyright (c) 2018 NEC Laboratories Europe GmbH.
//
// Authors: Sergey Fedorov <sergey.fedorov@neclab.eu>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package messagelog provides a storage for an ordered set of
// messages.
package messagelog

import (
	"time"
	"sync"
	"bytes"

	"fmt"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"

	"github.com/spf13/viper"
	"github.com/hyperledger-labs/minbft/api"
	// "github.com/hyperledger-labs/minbft/core/internal/messagelog"
	"github.com/hyperledger-labs/minbft/messages"
)

// MessageLog represents the message storage. It allows to
// asynchronously append messages, as well as to obtain multiple
// independent asynchronous streams to receive new messages from. Each
// of the streams provides an ordered sequence of all messages as they
// appear in the log. All methods are safe to invoke concurrently.
//
// Append appends a new message to the log. It will never be blocked
// by any of the message streams.
//
// Stream returns an independent channel to receive all messages as
// they appear in the log. Closing the channel passed to this function
// indicates the returned channel should be closed. Nil channel may be
// passed if there's no need to close the returned channel.
type MessageLog interface {
	Append(msg messages.ReplicaMessage, id uint32, peerID uint32)
	SaveAuthenticator(id uint32, seq uint64, auth []byte)
	AppendPRlog(send int, replicaID uint32, msgbyte []byte) (messages.PeerReviewMessage, uint64)
	VerifyAuthenticator(msgaudit messages.PeerReviewMessage, send uint32) error
	GenerateAuthenticator(int, uint32, []byte) (uint64, []byte, []byte, []byte)
	Stream(id uint32, done <-chan struct{}) <-chan messages.ReplicaMessage
	DumpAuthenticators()
	GenerateLogHistory(seq, len uint64) ([]byte, []byte)
	VerifyLogHistory(replicaID uint32, seq uint64, loghist []byte, hash []byte) error
	StopAckTimer(id uint32, seq uint64)
	SetFaulty(id, faulty uint32)
	FindSeqFromMsg(msg []byte) (uint64, []byte, []byte)
	FaultSimulator(peerID uint32) bool

	GetSequence() uint64
	GetLatestHash(i uint64) []byte
	GetWitnesses(i uint32) []uint32
}

type logEntry struct {
	Seq uint64
	MsgType int
	MsgHash []byte
}

type authenticator struct {
	stub int
}

type prlogAppender func(log *messageLog, send int, replicaID uint32, msg []byte) (messages.PeerReviewMessage, uint64)

type messageLog struct {
	lock sync.RWMutex

	// Messages in order added
	msgs map[uint32]([]messages.ReplicaMessage)

	// Buffered channels to notify about new messages
	newAdded map[uint32]chan<-bool

	appendPRlog prlogAppender

	n uint32
	id uint32
	logseq uint64
	entries []logEntry
	hashValue map[uint64][]byte

	// 0: trusted, 1:suspected, 2:exposed
	faultTable map[uint32]uint32
	// maintain authenticators from other replicas
	authenticators map[uint32]map[uint64][]byte
	auth api.Authenticator
	msgImpl messages.MessageImpl

	witnesses map[uint32]([]uint32)
	witnessed map[uint32]([]uint32)
	ackTimers map[uint32]map[uint64]*time.Timer
	auditTimers map[uint32]*time.Timer
	expireTable map[uint64]uint32
	// maintain log entries from witness replicas
	witnessLogHistory map[uint32]map[uint64][]byte
	witnessLogConfirmed map[uint32]uint64
	starttime time.Time
}

func GetMsgHash(msg []byte) []byte {
	h := sha1.New()
	h.Write(msg)
	bs := h.Sum(nil)
	return bs
}

func GetNumBytes(i uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(1))
	return b
}

// New creates a new instance of the message log.
func New(n, id uint32, authenticator api.Authenticator, messageImpl messages.MessageImpl) MessageLog {
	appendPRlog := makePRlogAppender(id, authenticator, messageImpl)
	msgLog := &messageLog{appendPRlog: appendPRlog}
	msgLog.msgs = make(map[uint32]([]messages.ReplicaMessage))
	msgLog.n = n
	msgLog.id = id
	msgLog.newAdded = make(map[uint32](chan<-bool))
	msgLog.logseq = uint64(0)
	msgLog.hashValue = make(map[uint64][]byte)
	msgLog.hashValue[uint64(0)] = GetMsgHash([]byte("seed"))
	// TODO: make this extensible
	msgLog.entries = make([]logEntry, 1024*100)
	msgLog.faultTable = make(map[uint32]uint32)
	msgLog.authenticators = make(map[uint32]map[uint64][]byte)
	msgLog.witnesses = make(map[uint32]([]uint32))
	msgLog.witnessed = make(map[uint32]([]uint32))
	msgLog.ackTimers = make(map[uint32]map[uint64]*time.Timer)
	msgLog.auditTimers = make(map[uint32]*time.Timer)
	msgLog.expireTable = make(map[uint64]uint32)
	msgLog.witnessLogConfirmed = make(map[uint32]uint64)
	msgLog.starttime = time.Now()
	nr_witnesses := uint32(viper.GetInt("replica.witnesses"))
	fmt.Printf("nr of witnesses: %d\n", nr_witnesses)
	for i := uint32(0); i < n; i++ {
		msgLog.faultTable[i] = 0
		msgLog.authenticators[i] = make(map[uint64][]byte)
		// TODO: control witness number from parameter.
		for j := uint32(0); j < nr_witnesses; j++ {
			msgLog.witnesses[i] = append(msgLog.witnesses[i], (i+1+j)%n)
			msgLog.witnessed[(i+1+j)%n] = append(msgLog.witnessed[(i+1+j)%n], i)
		}
		msgLog.ackTimers[i] = make(map[uint64]*time.Timer)
		msgLog.witnessLogConfirmed[i] = uint64(0)
	}
	fmt.Printf("witnesses %v\n", msgLog.witnesses)
	fmt.Printf("witnessed %v\n", msgLog.witnessed)
	msgLog.auth = authenticator
	msgLog.msgImpl = messageImpl
	// Initialize timer for each witness replicas
	audittime := viper.GetDuration("replica.audittime")
	for _, v := range msgLog.witnessed[id] {
		fmt.Printf("my audit target replica: %d\n", v)
		go func() {
			i := uint32(0)
			quit := make(chan struct{})
			ticker := time.NewTicker(audittime * time.Millisecond)
			time.Sleep(1000 * time.Millisecond)
			for {
				select {
				case <- ticker.C:
					i++
	        		periodicFunction(msgLog, id, v, messageImpl)
				case <- quit:
					ticker.Stop()
					return
				}
				// TODO: better final condition
				if i == uint32(50000) {
					close(quit)
				}
			}
		}()
	}
	return msgLog
}

func periodicFunction(log *messageLog, id, replica uint32, messageImpl messages.MessageImpl) {
	fmt.Printf("Send AUDIT message to replica %d, since %d\n", replica, log.witnessLogConfirmed[replica])
	auditmsg := messageImpl.NewAudit(id, replica, []byte{}, []byte{}, log.witnessLogConfirmed[replica], []byte{})
	log.Append(auditmsg, id, replica)
	// log.DumpAuthenticators()

	// 20/02/02 00:43 move this to message stream handler
	// if log.faultTable[replica] > 0 {
	// 	et := messageImpl.NewEvidenceTransfer(id, replica, replica, log.faultTable[replica], []byte{})
	// 	fmt.Printf("KKK: broadcast EvidenceTransfer replica %d, fault %d\n", replica, log.faultTable[replica])
	// 	log.Append(et, id, 100)
	// }
}

func (log *messageLog) Append(msg messages.ReplicaMessage, id uint32, peerID uint32) {
	log.lock.Lock()
	defer log.lock.Unlock()

	var idx uint32
	if peerID > log.n {
		for idx = 0; idx < log.n ; idx++ {
			log.msgs[idx] = append(log.msgs[idx], msg)
		}
		for _, newAdded := range log.newAdded {
			select {
			// TODO: no need to send boolean
			case newAdded <- true:
			default:
			}
		}
	} else {
		log.msgs[peerID] = append(log.msgs[peerID], msg)
		select {
		case log.newAdded[peerID] <- true:
		default:
		}
	}
}

func (log *messageLog) GetSequence() uint64 {
	log.lock.Lock()
	defer log.lock.Unlock()
	// lock?
	return log.logseq
}

func (log *messageLog) GetLatestHash(i uint64) []byte {
	log.lock.Lock()
	defer log.lock.Unlock()
	// TODO: null check
	return log.hashValue[log.logseq - i]
}

func (log *messageLog) GetWitnesses(i uint32) []uint32 {
	log.lock.Lock()
	defer log.lock.Unlock()
	// TODO: null check
	return log.witnesses[i]
}

func (log *messageLog) SaveAuthenticator(id uint32, seq uint64, auth []byte) {
	log.lock.Lock()
	defer log.lock.Unlock()
	log.saveAuthenticator(id, seq, auth)
}

func (log *messageLog) saveAuthenticator(id uint32, seq uint64, auth []byte) {
	log.authenticators[id][seq] = auth
}

func (log *messageLog) AppendPRlog(send int, replicaID uint32, msg []byte) (messages.PeerReviewMessage, uint64) {
	log.lock.Lock()
	defer log.lock.Unlock()
	msg2, seq := log.appendPRlog(log, send, replicaID, msg)
	return msg2, seq
}

func makePRlogAppender(id uint32, authenticator api.Authenticator, messageImpl messages.MessageImpl) prlogAppender {
	return func (log *messageLog, send int, replicaID uint32, msg []byte) (messages.PeerReviewMessage, uint64) {
		var prwmsg messages.PeerReviewMessage

		if replicaID == id {
			return nil, log.logseq
		}

		// latestHash := log.GetLatestHash(uint64(1))
		latestHash := log.hashValue[log.logseq]
		log.logseq++
		x := append(latestHash, GetNumBytes(log.logseq)...)
		x = append(x, GetNumBytes(uint64(send))...)
		x = append(x, GetMsgHash(msg)...)
		newHash := GetMsgHash(x)

		if send == 1 {
			b := make([]byte, 8)
			binary.LittleEndian.PutUint64(b, log.logseq)
			b = append(b, newHash...)
			// fmt.Printf("CCC: sigpayload:%v\n", b)
			signature, err := authenticator.GenerateMessageAuthenTag(api.ReplicaAuthen, b)
			if err != nil {
				fmt.Printf("failed to generate signature %s\n", err)
				panic(err) // Supplied Authenticator must be able to sing
			}
			// fmt.Printf("CCC: signature:%v\n", signature[0:20])
			// prwmsg = messageImpl.NewPRWrapped(id, replicaID, msg, latestHash, log.logseq, signature)
			prwmsg = messageImpl.NewPRWrapped(id, uint32(log.logseq), msg, latestHash, log.logseq, signature)
			// fmt.Printf("### SaveAuthenticator from AppendPRlog id:%d, seq:%d\n", id, log.logseq)
			log.saveAuthenticator(id, log.logseq, signature)
			// Set timer which expires if no ack receives
			log.startAckTimer(id, replicaID, log.logseq, msg)
			// log.startAckTimer(uint32(0), log.logseq)
		}
		fmt.Printf("=== Append PRlog seq:%d, send:%d, peerID:%d\n", log.logseq, send, replicaID)
		// fmt.Printf("CCC: lhash:%v, hashseed:%v\n", latestHash, x)
		entry := &logEntry{
			Seq: log.logseq,
			MsgType: send,
			MsgHash: msg,
		}
		log.entries[log.logseq] = *entry
		log.hashValue[log.logseq] = newHash
		// log.logseq++
		return prwmsg, log.logseq
	}
}

func (log *messageLog) GenerateAuthenticator(send int, replicaID uint32, msgBytes []byte) (uint64, []byte, []byte, []byte) {
	log.lock.Lock()
	defer log.lock.Unlock()

	_, seq := log.appendPRlog(log, send, replicaID, msgBytes)
	hash := log.hashValue[seq]
	c := make([]byte, 8)
	binary.LittleEndian.PutUint64(c, seq)
	c = append(c, hash...)
	// fmt.Printf("CCC: seq:%d\n", seq)
	// fmt.Printf("CCC: sigpayload:%v\n", c)
	signature, err := log.auth.GenerateMessageAuthenTag(api.ReplicaAuthen, c)
	// fmt.Printf("CCC: signature:%v\n", signature[0:20])
	if err != nil {
		panic(err) // Supplied Authenticator must be able to sign
	}
	log.authenticators[log.id][seq] = signature
	return seq, hash, log.hashValue[seq-1], signature
}

func (log *messageLog) VerifyAuthenticator(msgaudit messages.PeerReviewMessage, send uint32) error {
	rid := msgaudit.ReplicaID()
	seq := msgaudit.Sequence()
	// need to get next hash from msgaudit.PrevHash()
	x := append(msgaudit.PrevHash(), GetNumBytes(seq)...)
	x = append(x, GetNumBytes(uint64(send))...)
	x = append(x, GetMsgHash(msgaudit.ExtractMessage())...)
	verifyHash := GetMsgHash(x)

	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, seq)
	b = append(b, verifyHash...)
	// fmt.Printf("-- from %d, hash1 %v, hash2 %v\n", rid, msgaudit.PrevHash(), verifyHash)
	if err := log.auth.VerifyMessageAuthenTag(api.ReplicaAuthen, rid, b, msgaudit.Authenticator()); err != nil {
		return fmt.Errorf("Failed verifying authenticator: C %s", err)
	}
	return nil
}

func (log *messageLog) Stream(id uint32, done <-chan struct{}) <-chan messages.ReplicaMessage {
	ch := make(chan messages.ReplicaMessage)
	go log.supplyMessages(id, ch, done)

	return ch
}

func (log *messageLog) DumpAuthenticators() {
	fmt.Printf("@@@ ---\n")
	for i := uint32(0); i < log.n; i++ {
		for k, v := range log.authenticators[i] {
			fmt.Printf("@@@ id:%d, seq:%d auth:%v\n", i, k, v[0:20])
		}
	}
}

func (log *messageLog) GenerateLogHistory(seq uint64, len uint64) ([]byte, []byte) {
	// TODO: need locking
	// fmt.Printf("aaaA: %v\n", log.entries[0:3])
	// s, err := json.Marshal(log.entries[0:3])
	if seq == log.logseq {
		// TODO: timeout/challenge check
		fmt.Printf("AAA: no new log entries since %d\n", seq)
		return []byte{}, nil
	}
	fmt.Printf("AAA: generate log history, from %d to %d\n", seq, log.logseq)
	s, err := json.Marshal(log.entries[(seq+1):log.logseq+1])
	if err != nil {
		fmt.Printf("failed to get byte array of log entries\n")
		return []byte{}, nil
	}
	// fmt.Printf("aaaA: %s\n", s)
	// return s, log.GetLatestHash(seq)
	return s, log.hashValue[seq]
}

// return hash_k, and auth payload
func nextHashValue(seq uint64, send uint32, msghash []byte, basehash []byte) ([]byte, []byte) {
	x := append(basehash, GetNumBytes(seq)...)
	x = append(x, GetNumBytes(uint64(send))...)
	x = append(x, GetMsgHash(msghash)...)
	verifyHash := GetMsgHash(x)
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, seq)
	b = append(b, verifyHash...)
	return verifyHash, b
}

func (log *messageLog) VerifyLogHistory(id uint32, seq uint64, logHist []byte, hash []byte) error {
	var entries []logEntry
	json.Unmarshal(logHist, &entries)
	tmphash := hash
	var tmpauthpayload []byte
	var i int
	// fmt.Printf("BBB: verifyLogHistory id:%d, seq:%d, len:%d\n", id, seq, len(entries))
	for i = 0; i < len(entries); i++ {
		tmpseq := seq + uint64(i + 1)
		tmphash, tmpauthpayload = nextHashValue(tmpseq, uint32(entries[i].MsgType), entries[i].MsgHash, tmphash)
		if log.authenticators[id][tmpseq] == nil {
			fmt.Printf("BBB: Authenticator id:%d, seq:%d not found\n", id, tmpseq)
			break // continue
		}
		if err := log.auth.VerifyMessageAuthenTag(api.ReplicaAuthen, id, tmpauthpayload, log.authenticators[id][tmpseq]); err != nil {
			log.DumpAuthenticators()
			fmt.Printf("SSS: EXPOSED replica:%d seq:%d time:%d : failed to verify LogHistory.\n", id, tmpseq, time.Now().UnixNano())
			log.faultTable[id] = 2
			return fmt.Errorf("Failed verifying authenticator: C id:%d, seq:%d, %s", id, tmpseq, err)
		}
	}
	// TODO: message replay for Audit protocol
	fmt.Printf("BBB: id:%d entries since seq:%d\n", i, log.witnessLogConfirmed[id])
	// maybe shouldn't be clear faulty status if it's once exposed.
	// TODO: this should be additional check
	// if log.faultTable[id] == 1 {
	// 	fmt.Printf("SSS: TRUSTED replica:%d time:%d : LogHistory Verified 1.\n", id, time.Now().UnixNano())
	// 	log.faultTable[id] = 0
	// }
	// if log.faultTable[id] == 2 {
	// 	fmt.Printf("SSS: TRUSTED replica:%d time:%d : LogHistory Verified 2.\n", id, time.Now().UnixNano())
	// 	log.faultTable[id] = 0
	// }
	log.witnessLogConfirmed[id] += uint64(i)
	return nil
}

func (log *messageLog) startAckTimer(myid, id uint32, seq uint64, msg []byte) {
	timeout := time.Duration(viper.GetDuration("replica.acktimeout"))*time.Millisecond
	fmt.Printf(">>> start acktimer [%d][%d]\n", id, seq)
	log.ackTimers[id][seq] = time.AfterFunc(timeout, func() {
		// EXPOSED is more important thant SUSPECTED so don't override it
		if log.faultTable[id] == 2 { return }

		log.expireTable[seq] = id
		// TODO: send challenge to witness replicas
		fmt.Printf("SSS: SUSPECTED replica:%d seq:%d time:%d : AckTimer expired.\n", id, seq, time.Now().UnixNano())
		// ?? need lock?
		var change uint32
		if log.faultTable[id] == 0 {
			change = uint32(1)
			log.faultTable[id] = 1
		}
		for _, wid := range log.GetWitnesses(id) {
			if myid != wid {
				fmt.Printf(">>> send 'audit challenge' to %d for suspecting %d\n", wid, id)
				// This is a audit challenge
				// challenge にはもう一つ引数が必要でステータスの変更があったかどうかチェックする必要がある。
				// NOTE: 第２引数、本来は peerID だが一時的に status change の有無を指定するようにする。
				log.Append(log.msgImpl.NewChallenge(myid, change, id, 1, uint32(1), msg, seq), myid, wid)
			} else {
				// TODO: if witness node detected the acktimer expiration!!
			}
		}

		// send challenge
		fmt.Printf(">>> send 'send challenge' to %d\n", id)
		log.Append(log.msgImpl.NewChallenge(myid, change, id, 0, uint32(1), msg, seq), myid, id)
	})
}

func (log *messageLog) SetFaulty(id, fault uint32) {
	if viper.GetInt("replica.faultsim") == 4 && log.id == uint32(2) && id == uint32(1) {
		fmt.Printf("UUU: ignore challenge against node %d, %d, %d.\n", log.id, id, log.faultTable[id])
		return
	}

	if (log.id == id) {
		return
	}

	if fault == uint32(1) {
		fmt.Printf("SSS: SUSPECTED replica:%d time:%d : received audit challenge %d.\n", id, time.Now().UnixNano(), fault)
	} else if fault == uint32(2) {
		fmt.Printf("SSS: EXPOSED replica:%d time:%d : received EvidenceTransfer %d.\n", id, time.Now().UnixNano(), fault)
	} else if fault == uint32(0) {
		fmt.Printf("SSS: TRUSTED replica:%d time:%d : received EvidenceTransfer %d.\n", id, time.Now().UnixNano(), fault)
	}
	log.faultTable[id] = fault
}

func (log *messageLog) FindSeqFromMsg(msg []byte) (uint64, []byte, []byte) {
	log.lock.Lock()
	defer log.lock.Unlock()

	for i := log.logseq; i > uint64(0); i-- {
		if bytes.Equal(log.entries[i].MsgHash, msg) {
			// return sequence, *previous* hash, and authenticator
			return i, log.hashValue[i-1], log.authenticators[log.id][i]
		}
	}
	return uint64(0), []byte{}, []byte{}
}

func (log *messageLog) findExpireTimerByID(id uint32) bool {
	for _, value := range log.expireTable {
		if value == id {
			return true;
		}
	}
	return false;
}

func (log *messageLog) StopAckTimer(id uint32, seq uint64) {
	if log.ackTimers[id][seq] != nil {
		if log.ackTimers[id][seq].Stop() {
			fmt.Printf(">>> Stop timer for replica:%d, seq:%d\n", id, seq)
		}
		delete(log.ackTimers[id], seq)
	}

	if id == log.expireTable[seq] {
		fmt.Printf(">>> unset expired timer flag %d:%d\n", id, seq)
		delete(log.expireTable, seq)
		// if all expired timer flag from id is cleared, the state is no longer suspected
		if log.faultTable[id] == 1 && log.findExpireTimerByID(id) == false {
			fmt.Printf("SSS: TRUSTED replica:%d seq:%d time:%d : received and verified acknowledgement.\n", id, seq, time.Now().UnixNano())
			log.faultTable[id] = 0

			for _, wid := range log.GetWitnesses(id) {
				if log.id != wid {
					fmt.Printf(">>> send 'audit challenge' to %d (witness of %d)\n", wid, id)
					change := uint32(1)
					log.Append(log.msgImpl.NewChallenge(log.id, change, id, 1, uint32(0), []byte{}, uint64(0)), log.id, wid)
				} else {
					// TODO: if witness node detected the acktimer expiration!!
				}
			}
			// log.Append(log.msgImpl.NewChallenge(log.id, 1, id, 1, uint32(0), []byte{}, uint64(0)), log.id, id)
		}
	}
}

func (log *messageLog) FaultSimulator(peerID uint32) bool {
	faultsim := viper.GetInt("replica.faultsim")

	// fmt.Printf("UUU: fault simulator %d\n", faultsim)
	if faultsim == 0 { return false }
	// one replica intentionally ignore another specific replica
	if faultsim == 1 && time.Now().After(log.starttime.Add(time.Second)) && log.id == uint32(1) && peerID == uint32(3) {
		return true
	}
	// one replica intentionally ignore one specific witness replica
	if faultsim == 5 && time.Now().After(log.starttime.Add(time.Second)) && log.id == uint32(1) && peerID == uint32(2) {
		return true
	}
	// one replica intentionally ignore all other replica (crash fault)
	if faultsim == 2 && time.Now().After(log.starttime.Add(time.Second)) && log.id == uint32(1) {
		fmt.Printf("UUU: filtered sending.\n")
		return true
	}
	// one replica intentionally ignore all other replica (crash fault) for 4 seconds
	if faultsim == 7 && log.id == uint32(1) && time.Now().After(log.starttime.Add(time.Second)) && time.Now().Before(log.starttime.Add(4*time.Second))  {
		time.Sleep(2*time.Second)
		return false
	}
	if faultsim == 8 && log.id == uint32(1) && peerID == uint32(2) && time.Now().After(log.starttime.Add(time.Second)) && time.Now().Before(log.starttime.Add(4*time.Second))  {
		time.Sleep(2*time.Second)
		return false
	}
	if faultsim == 9 && log.id == uint32(1) && peerID == uint32(3) && time.Now().After(log.starttime.Add(time.Second)) && time.Now().Before(log.starttime.Add(4*time.Second))  {
		time.Sleep(2*time.Second)
		return false
	}
	if faultsim == 3 && time.Now().After(log.starttime.Add(time.Second)) && log.id == uint32(1) {
		fmt.Printf("YTT: faultsim 3 works!\n")
		log.entries[log.logseq].MsgType += 10
		log.entries[log.logseq].MsgHash = []byte("ABC€")
	}
	// 共謀のケース。f=2 以上でないと気づけない。
	if faultsim == 4 && time.Now().After(log.starttime.Add(time.Second)) && log.id == uint32(1) && peerID == uint32(4) {
		return true
	}

	return false
}

func (log *messageLog) supplyMessages(id uint32, ch chan<- messages.ReplicaMessage, done <-chan struct{}) {
	defer close(ch)

	newAdded := make(chan bool, 1)
	log.lock.Lock()
	log.newAdded[id] = newAdded
	log.lock.Unlock()

	// fmt.Printf("asdf supplyMessage %d\n", len(log.msgs))
	next := 0
	for {
		log.lock.RLock()
		msgs := log.msgs[id][next:]
		next = len(log.msgs[id])
		log.lock.RUnlock()

		for _, msg := range msgs {
			select {
			case ch <- msg:
			case <-done:
				return
			}
		}

		select {
		case b := <-newAdded:
			// fmt.Printf("newAdded event %v for id:%d\n", b, id)
			if b != true {
				// log.lock.RLock()
				next++
				// log.lock.RUnlock()
			}
		case <-done:
			return
		}
	}
}
