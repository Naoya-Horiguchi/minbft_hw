// Copyright (c) 2019 NEC Laboratories Europe GmbH.
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

// Package messages defines interface for the protocol messages.
package messages

import (
	"encoding"
)

// MessageImpl provides an implementation of the message representation.
type MessageImpl interface {
	NewFromBinary(data []byte) (Message, error)
	NewRequest(clientID uint32, sequence uint64, operation []byte) Request
	NewPrepare(replicaID uint32, view uint64, request Request) Prepare
	NewCommit(replicaID uint32, prepare Prepare) Commit
	NewReply(replicaID, clientID uint32, sequence uint64, result []byte) Reply
}

type Message interface {
	encoding.BinaryMarshaler
}

// ClientMessage represents a message generated by a client.
type ClientMessage interface {
	Message
	ClientID() uint32
	ImplementsClientMessage()
}

// ReplicaMessage represents a message generated by a replica.
//
// EmbeddedMessages method returns a sequence of messages embedded
// into this one.
type ReplicaMessage interface {
	Message
	ReplicaID() uint32
	ImplementsReplicaMessage()
}

// CertifiedMessage represents a message certified with a UI.
//
// CertifiedPayload returns the serialized message content certified
// by its UI.
type CertifiedMessage interface {
	ReplicaMessage
	CertifiedPayload() []byte
	UIBytes() []byte
	SetUIBytes(ui []byte)
}

// SignedMessage represents a message signed with a normal signature.
//
// SginedPayload returns serialized message content signed with its
// signature.
type SignedMessage interface {
	SignedPayload() []byte
	Signature() []byte
	SetSignature(signature []byte)
}

type Request interface {
	ClientMessage
	SignedMessage
	Sequence() uint64
	Operation() []byte
	ImplementsRequest()
}

type Prepare interface {
	CertifiedMessage
	View() uint64
	Request() Request
	ImplementsPrepare()
}

type Commit interface {
	CertifiedMessage
	Prepare() Prepare
	ImplementsCommit()
}

type Reply interface {
	ReplicaMessage
	SignedMessage
	ClientID() uint32
	Sequence() uint64
	Result() []byte
	ImplementsReply()
}
