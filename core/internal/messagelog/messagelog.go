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

	"fmt"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"

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
	GenerateAuthenticator() (uint64, []byte, []byte)
	Stream(id uint32, done <-chan struct{}) <-chan messages.ReplicaMessage
	DumpAuthenticators()
	GenerateLogHistory(seq, len uint64) []byte
	VerifyLogHistory([]byte) error
	StopAckTimer(id uint32, seq uint64)

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
	ackTimers map[uint32]map[uint64]*time.Timer
	auditTimers map[uint32]*time.Timer
	// maintain log entries from witness replicas
	witnessLogHistory map[uint32]map[uint64][]byte
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
	msgLog.newAdded = make(map[uint32](chan<-bool))
	msgLog.logseq = uint64(0)
	msgLog.hashValue = make(map[uint64][]byte)
	msgLog.hashValue[uint64(0)] = GetMsgHash([]byte("seed"))
	// TODO: make this extensible
	msgLog.entries = make([]logEntry, 1024)
	msgLog.faultTable = make(map[uint32]uint32)
	msgLog.authenticators = make(map[uint32]map[uint64][]byte)
	msgLog.witnesses = make(map[uint32]([]uint32))
	msgLog.ackTimers = make(map[uint32]map[uint64]*time.Timer)
	msgLog.auditTimers = make(map[uint32]*time.Timer)
	for i := uint32(0); i < n; i++ {
		msgLog.faultTable[i] = 0
		msgLog.authenticators[i] = make(map[uint64][]byte)
		// TODO: control witness number from parameter.
		msgLog.witnesses[i] = append(msgLog.witnesses[i], (i+1)%n)
		msgLog.ackTimers[i] = make(map[uint64]*time.Timer)
	}
	fmt.Printf("%v\n", msgLog.witnesses)
	msgLog.auth = authenticator
	msgLog.msgImpl = messageImpl
	// Initialize timer for each witness replicas
	for _, v := range msgLog.witnesses[id] {
		fmt.Printf("my witness replica: %d\n", v)
		go func() {
			i := uint32(0)
			quit := make(chan struct{})
			ticker := time.NewTicker(1000 * time.Millisecond)
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
	fmt.Printf("Send AUDIT message to replica %d\n", replica)
	auditmsg := messageImpl.NewAudit(id, 0, []byte{}, []byte{}, 0, []byte{})
	log.Append(auditmsg, id, replica)
	// log.DumpAuthenticators()
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
			signature, err := authenticator.GenerateMessageAuthenTag(api.ReplicaAuthen, b)
			if err != nil {
				fmt.Printf("failed to generate signature %s\n", err)
				panic(err) // Supplied Authenticator must be able to sing
			}
			// prwmsg = messageImpl.NewPRWrapped(id, replicaID, msg, latestHash, log.logseq, signature)
			prwmsg = messageImpl.NewPRWrapped(id, uint32(log.logseq), msg, latestHash, log.logseq, signature)
			fmt.Printf("### SaveAuthenticator from AppendPRlog id:%d, seq:%d\n", id, log.logseq)
			log.SaveAuthenticator(id, log.logseq, signature)
			// Set timer which expires if no ack receives
			log.startAckTimer(replicaID, log.logseq)
			// log.startAckTimer(uint32(0), log.logseq)
		}
		fmt.Printf("Append PRlog seq:%d, send:%d, peerID:%d\n", log.logseq, send, replicaID)
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

func (log *messageLog) GenerateAuthenticator() (uint64, []byte, []byte) {
	// log.lock.Lock()
	// defer log.lock.Unlock()

	myseq := log.GetSequence()
	mylhash := log.GetLatestHash(uint64(0))
	c := make([]byte, 8)
	binary.LittleEndian.PutUint64(c, myseq)
	c = append(c, mylhash...)
	signature, err := log.auth.GenerateMessageAuthenTag(api.ReplicaAuthen, c)
	if err != nil {
		panic(err) // Supplied Authenticator must be able to sign
	}
	return myseq, mylhash, signature
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
	// logger.Debugf("-- from %d, hash1 %v, hash2 %v\n", rid, msgaudit.PrevHash(), verifyHash)
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

func (log *messageLog) GenerateLogHistory(seq uint64, len uint64) []byte {
	// fmt.Printf("aaaA: %v\n", log.entries[0:3])
	// s, err := json.Marshal(log.entries[0:3])
	s, err := json.Marshal(log.entries[seq:len+1])
	if err != nil {
		fmt.Printf("failed to get byte array of log entries\n")
	}
	fmt.Printf("aaaA: %s\n", s)
	return s
}

func (log *messageLog) VerifyLogHistory(logHist []byte) error {
	var entries []logEntry
	json.Unmarshal(logHist, &entries)
	for i := 0; i < len(entries); i++ {
		fmt.Printf("aaaB: %d %d %d %v\n", i, entries[i].Seq, entries[i].MsgType, entries[i].MsgHash)
	}
	// TODO: 具体的な検証処理
	return nil
}

func (log *messageLog) startAckTimer(id uint32, seq uint64) {
	timeout := time.Duration(100)*time.Millisecond
	if seq == uint64(2) {
		timeout = time.Duration(1)*time.Nanosecond
	}
	fmt.Printf(">>> start acktimer [%d][%d]\n", id, seq)
	log.ackTimers[id][seq] = time.AfterFunc(timeout, func() {
		// TODO: send challenge to witness replicas
		fmt.Printf(">>> AckTimer for seq %d expired and replica %d is now 'suspended'.\n", seq, id)
		log.faultTable[id] = 1
	})
}

func (log *messageLog) StopAckTimer(id uint32, seq uint64) {
	if log.faultTable[id] == 1 {
		fmt.Printf(">>> Received Ack message from 'suspended' replica %d, so set its status as 'trusted'.\n", id)
		log.faultTable[id] = 0
	}

	fmt.Printf(">>> stop acktimer [%d][%d]\n", id, seq)
	if log.ackTimers[id][seq] != nil {
		fmt.Printf(">>> Stop timer for replica:%d, seq:%d\n", id, seq)
		log.ackTimers[id][seq].Stop()
	}
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
