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

package protobuf

import (
	// "fmt"

	"github.com/golang/protobuf/proto"

	// "github.com/hyperledger-labs/minbft/messages"
)

type audit struct {
	Audit
}

func newAudit() *audit {
	return &audit{}
}

// use seq as "lastest log-confirmed sequence"
func (m *audit) init(r, peerID uint32, msg []byte, prevhash []byte, seq uint64, auth []byte) {
	m.Audit = Audit{Msg: &Audit_M{
		ReplicaId: r,
		PeerId: peerID,
		Msg: msg,
		Prevhash: prevhash,
		Sequence: seq,
		Authenticator: auth,
	}}
}

func (m *audit) set(pbMsg *Audit) {
	m.Audit = *pbMsg
}

func (m *audit) MarshalBinary() ([]byte, error) {
	return proto.Marshal(&Message{Type: &Message_Audit{Audit: &m.Audit}})
}

func (m *audit) ReplicaID() uint32 {
	return m.Msg.GetReplicaId()
}

func (m *audit) PeerID() uint32 {
	return m.Msg.GetPeerId()
}

func (m *audit) PrevHash() []byte {
	return m.Msg.GetPrevhash()
}

func (m *audit) Sequence() uint64 {
	return m.Msg.GetSequence()
}

func (m *audit) Authenticator() []byte {
	return m.Msg.GetAuthenticator()
}

func (m *audit) ExtractMessage() []byte {
	return m.Msg.Msg
}

func (audit) ImplementsReplicaMessage() {}
func (audit) ImplementsAuditMessage() {}
