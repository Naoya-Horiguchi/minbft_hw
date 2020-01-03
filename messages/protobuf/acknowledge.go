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

type acknowledge struct {
	Acknowledge
}

func newAcknowledge() *acknowledge {
	return &acknowledge{}
}

func (m *acknowledge) init(r, peerID uint32, prevhash []byte, seq uint64, auth []byte, msg []byte) {
	m.Acknowledge = Acknowledge{Msg: &Acknowledge_M{
		ReplicaId: r,
		PeerId: peerID,
		Prevhash: prevhash,
		Sequence: seq,
		Authenticator: auth,
		Msg: msg,
	}}
}

func (m *acknowledge) set(pbMsg *Acknowledge) {
	m.Acknowledge = *pbMsg
}

func (m *acknowledge) MarshalBinary() ([]byte, error) {
	return proto.Marshal(&Message{Type: &Message_Acknowledge{Acknowledge: &m.Acknowledge}})
}

func (m *acknowledge) ReplicaID() uint32 {
	return m.Msg.GetReplicaId()
}

func (m *acknowledge) PeerID() uint32 {
	return m.Msg.GetPeerId()
}

func (m *acknowledge) PrevHash() []byte {
	return m.Msg.GetPrevhash()
}

func (m *acknowledge) Sequence() uint64 {
	return m.Msg.GetSequence()
}

func (m *acknowledge) Authenticator() []byte {
	return m.Msg.GetAuthenticator()
}

func (m *acknowledge) ExtractMessage() []byte {
	return m.Msg.Msg
}

func (acknowledge) ImplementsReplicaMessage() {}
func (acknowledge) ImplementsAcknowledge() {}
