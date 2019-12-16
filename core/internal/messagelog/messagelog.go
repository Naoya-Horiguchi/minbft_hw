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
	Append(msg messages.ReplicaMessage)
	AppendPRlog(msgbyte []byte)
	Stream(done <-chan struct{}) <-chan messages.ReplicaMessage
}

type logEntry struct {
	msgType int
	otherNode int
	msgHash []byte
}

type authenticator struct {
	stub int
}

type messageLog struct {
	lock sync.RWMutex

	// Messages in order added
	msgs []messages.ReplicaMessage

	// Buffered channels to notify about new messages
	newAdded []chan<- struct{}

	LogSeq uint64
	entries map[uint64]logEntry
	authenticators map[uint64]authenticator
}

func getMsgHash(msg []byte) []byte {
	h := sha1.New()
	h.Write(msg)
	bs := h.Sum(nil)
	return bs
}

// New creates a new instance of the message log.
func New() MessageLog {
	entries := make(map[uint64]logEntry)
	authenticators := make(map[uint64]authenticator)
	s := "teststring"
	h := sha1.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	// fmt.Printf("---> s:%s, bs:%x, getmsghash:%x\n", s, bs, getMsgHash(s))
	fmt.Printf("---> s:%s, bs:%x\n", s, bs)
	return &messageLog{entries: entries, authenticators: authenticators, LogSeq: uint64(3)}
}

func (log *messageLog) Append(msg messages.ReplicaMessage) {
	log.lock.Lock()
	defer log.lock.Unlock()

	log.msgs = append(log.msgs, msg)

	for _, newAdded := range log.newAdded {
		select {
		case newAdded <- struct{}{}:
		default:
		}
	}
}

func makePRlogAppender() func() {
	var (
		logseq uint64
		entries map[uint64]logEntry
		authenticators map[uint64]authenticator
	)

	return func (msg []byte) {
		// lock?

		entry := &logEntry{
			msgType: 0,
			otherNode: 1,
			msgHash: getMsgHash(msg),
		}
		entries[logseq] = *entry
		logseq++
		for k, v := range entries { 
			fmt.Printf("??? log[%d] is %x\n", k, v)
		}
	}
}

func (log messageLog) AppendPRlog(msg []byte) {
	log.lock.Lock()
	defer log.lock.Unlock()

	// entry := &logEntry{
	// 	msgType: 0,
	// 	otherNode: 1,
	// 	msgHash: getMsgHash(msg),
	// }
	// log.entries[log.LogSeq] = *entry
	// for k, v := range log.entries { 
	// 	fmt.Printf("??? log[%d] is %x\n", k, v)
	// }
	// fmt.Printf("??? LogSeq %x\n", log.LogSeq)
	// log.LogSeq++
	// fmt.Printf("??? LogSeq %x\n", log.LogSeq)
}

func (log *messageLog) Stream(done <-chan struct{}) <-chan messages.ReplicaMessage {
	ch := make(chan messages.ReplicaMessage)
	go log.supplyMessages(ch, done)

	return ch
}

func (log *messageLog) supplyMessages(ch chan<- messages.ReplicaMessage, done <-chan struct{}) {
	defer close(ch)

	newAdded := make(chan struct{}, 1)
	log.lock.Lock()
	log.newAdded = append(log.newAdded, newAdded)
	log.lock.Unlock()

	fmt.Printf("asdf supplyMessage %d\n", len(log.msgs))
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
