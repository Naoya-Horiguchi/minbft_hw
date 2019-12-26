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
	AppendPRlog(send int, replicaID uint32, msgbyte []byte)
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

type prlogAppender func(log *messageLog, send int, replicaID uint32, msg []byte)

type messageLog struct {
	lock sync.RWMutex

	// Messages in order added
	msgs []messages.ReplicaMessage

	// Buffered channels to notify about new messages
	newAdded map[uint32]chan<-struct{}

	appendPRlog prlogAppender

	logseq uint64
	entries map[uint64]logEntry
	hashValue map[uint64][]byte
	// authenticators map[uint64]authenticator
}

func getMsgHash(msg []byte) []byte {
	h := sha1.New()
	h.Write(msg)
	bs := h.Sum(nil)
	return bs
}

func getNumBytes(i uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(1))
	return b
}

// New creates a new instance of the message log.
func New(id uint32) MessageLog {
	appendPRlog := makePRlogAppender(id)
	msgLog := &messageLog{appendPRlog: appendPRlog}
	msgLog.newAdded = make(map[uint32](chan<-struct{}))
	msgLog.logseq = uint64(1)
	msgLog.hashValue = make(map[uint64][]byte)
	msgLog.hashValue[uint64(0)] = getMsgHash([]byte("seed"))
	// fmt.Printf("<<<%x>>>\n", msgLog.hashValue[0])
	msgLog.entries = make(map[uint64]logEntry)
	return msgLog
}

func (log *messageLog) Append(msg messages.ReplicaMessage, id uint32, peerID uint32) {
	log.lock.Lock()
	defer log.lock.Unlock()

	log.msgs = append(log.msgs, msg)

	for key, newAdded := range log.newAdded {
		if peerID < 100 && key != peerID {
			// fmt.Printf("--> Filter msg for replica: %d\n", key)
			continue
		// } else {
		// 	fmt.Printf("--> Send msg to replica %d\n", peerID)
		}
		// fmt.Printf("abc %v\n", newAdded)
		select {
		case newAdded <- struct{}{}:
		default:
		}
	}
}

func (log *messageLog) GetSequence() uint64 {
	// lock?
	return log.logseq
}

func (log *messageLog) GetLatestHash(i uint64) []byte {
	// lock?
	// TODO: null check
	return log.hashValue[log.logseq - i]
}

func (log *messageLog) AppendPRlog(send int, replicaID uint32, msg []byte) {
	// lock?
	log.appendPRlog(log, send, replicaID, msg)
}

func makePRlogAppender(id uint32) prlogAppender {
	return func (log *messageLog, send int, replicaID uint32, msg []byte) {
		// lock?

		if replicaID == id {
			return
		}

		entry := &logEntry{
			msgType: send,
			otherNode: replicaID,
			msgHash: msg,
		}
		log.entries[log.logseq] = *entry
		x := append(log.hashValue[log.logseq - 1], getNumBytes(log.logseq)...)
		x = append(x, getNumBytes(uint64(send))...)
		x = append(x, getMsgHash(msg)...)
		log.hashValue[log.logseq] = getMsgHash(x)
		fmt.Printf("Append PRlog seq:%d, send:%d, peerID:%d\n", log.logseq, send, replicaID)
		log.logseq++
		// for k, v := range log.entries {
		// 	fmt.Printf("??? log[%d] is %x\n", k, v)
		// }
		// for k, v := range log.hashValue {
		// 	fmt.Printf("??? hash[%d] is %x\n", k, v)
		// }
	}
}

func (log *messageLog) Stream(id uint32, done <-chan struct{}) <-chan messages.ReplicaMessage {
	ch := make(chan messages.ReplicaMessage)
	go log.supplyMessages(id, ch, done)

	return ch
}

func (log *messageLog) supplyMessages(id uint32, ch chan<- messages.ReplicaMessage, done <-chan struct{}) {
	defer close(ch)

	newAdded := make(chan struct{}, 1)
	log.lock.Lock()
	log.newAdded[id] = newAdded
	log.lock.Unlock()

	// fmt.Printf("asdf supplyMessage %d\n", len(log.msgs))
	next := 0
	for {
		log.lock.RLock()
		msgs := log.msgs[next:]
		next = len(log.msgs)
		log.lock.RUnlock()

		for _, msg := range msgs {
			select {
			case ch <- msg:
			case <-done:
				return
			}
		}

		select {
		case <-newAdded:
		case <-done:
			return
		}
	}
}
