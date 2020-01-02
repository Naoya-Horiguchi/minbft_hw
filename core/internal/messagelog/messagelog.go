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
	"sync"

	"fmt"
	"crypto/sha1"
	"encoding/binary"

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
	AppendPRlog(send int, replicaID uint32, msgbyte []byte) messages.AuditMessage
	Stream(id uint32, done <-chan struct{}) <-chan messages.ReplicaMessage

	GetSequence() uint64
	GetLatestHash(i uint64) []byte
}

type logEntry struct {
	msgType int
	otherNode uint32
	msgHash []byte
}

type authenticator struct {
	stub int
}

type prlogAppender func(log *messageLog, send int, replicaID uint32, msg []byte) messages.AuditMessage

type messageLog struct {
	lock sync.RWMutex

	// Messages in order added
	msgs map[uint32]([]messages.ReplicaMessage)

	// Buffered channels to notify about new messages
	newAdded map[uint32]chan<-bool

	appendPRlog prlogAppender

	n uint32
	logseq uint64
	entries map[uint64]logEntry
	hashValue map[uint64][]byte
	// 0: trusted, 1:suspected, 2:exposed
	faultTable map[uint32]uint32
	// authenticators map[uint64]authenticator
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
	// for i := 0; i < n; i++ {
	// }
	msgLog.n = n
	msgLog.newAdded = make(map[uint32](chan<-bool))
	msgLog.logseq = uint64(1)
	msgLog.hashValue = make(map[uint64][]byte)
	msgLog.hashValue[uint64(0)] = GetMsgHash([]byte("seed"))
	// fmt.Printf("<<<%x>>>\n", msgLog.hashValue[0])
	msgLog.entries = make(map[uint64]logEntry)
	msgLog.faultTable = make(map[uint32]uint32)
	for i := uint32(0); i < n; i++ {
		msgLog.faultTable[i] = 0
	}
	return msgLog
}

func (log *messageLog) Append(msg messages.ReplicaMessage, id uint32, peerID uint32) {
	log.lock.Lock()
	defer log.lock.Unlock()

	var idx uint32
	if peerID > log.n {
// fmt.Printf("broadcast message %d > %d\n", peerID, log.n)
		for idx = 0; idx < log.n ; idx++ {
			log.msgs[idx] = append(log.msgs[idx], msg)
		}
		for _, newAdded := range log.newAdded {
			// fmt.Printf("abc %v\n", newAdded)
			select {
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

	// for key, newAdded := range log.newAdded {
	// 	if peerID < 100 && key != peerID {
	// 		// fmt.Printf("--> Filter msg for replica: %d\n", key)
	// 		select {
	// 		case newAdded <- false:
	// 		default:
	// 		}
	// 		// continue
	// 	// } else {
	// 	// 	fmt.Printf("--> Send msg to replica %d\n", peerID)
	// 	} else {
	// 		// fmt.Printf("abc %v\n", newAdded)
	// 		select {
	// 		case newAdded <- true:
	// 		default:
	// 		}
	// 	}
	// }
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

func (log *messageLog) AppendPRlog(send int, replicaID uint32, msg []byte) messages.AuditMessage {
	log.lock.Lock()
	defer log.lock.Unlock()
	// lock?
	return log.appendPRlog(log, send, replicaID, msg)
}

func makePRlogAppender(id uint32, authenticator api.Authenticator, messageImpl messages.MessageImpl) prlogAppender {
	return func (log *messageLog, send int, replicaID uint32, msg []byte) messages.AuditMessage {
		// lock?

		if replicaID == id {
			return nil
		}

		// latestHash := log.GetLatestHash(uint64(1))
		latestHash := log.hashValue[log.logseq - 1]
		x := append(latestHash, GetNumBytes(log.logseq)...)
		x = append(x, GetNumBytes(uint64(send))...)
		x = append(x, GetMsgHash(msg)...)
		newHash := GetMsgHash(x)

		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, log.logseq)
		b = append(b, newHash...)
		signature, err := authenticator.GenerateMessageAuthenTag(api.ReplicaAuthen, b)
		if err != nil {
			fmt.Printf("failed to generate signature %s\n", err)
			panic(err) // Supplied Authenticator must be able to sing
		}
		// do this only when send == 1
		auditmsg := messageImpl.NewAudit(id, replicaID, msg, latestHash, log.logseq, signature)

		fmt.Printf("Append PRlog seq:%d, send:%d, peerID:%d\n", log.logseq, send, replicaID)
		entry := &logEntry{
			msgType: send,
			otherNode: replicaID,
			msgHash: msg,
		}
		log.entries[log.logseq] = *entry
		log.hashValue[log.logseq] = newHash
		log.logseq++
		// for k, v := range log.entries {
		// 	fmt.Printf("??? log[%d] is %x\n", k, v)
		// }
		// for k, v := range log.hashValue {
		// 	fmt.Printf("??? hash[%d] is %x\n", k, v)
		// }
		return auditmsg
	}
}

func (log *messageLog) Stream2(id uint32, done <-chan struct{}) <-chan messages.ReplicaMessage {
	ch := make(chan messages.ReplicaMessage)
	// go log.supplyMessages2(id, ch, done)

	return ch
}

func (log *messageLog) Stream(id uint32, done <-chan struct{}) <-chan messages.ReplicaMessage {
	ch := make(chan messages.ReplicaMessage)
	go log.supplyMessages(id, ch, done)

	return ch
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
// fmt.Printf("NNN log.msgs.len %d, next %d\n", len(log.msgs), next)
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
