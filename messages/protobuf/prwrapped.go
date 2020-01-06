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
	"github.com/golang/protobuf/proto"
)

type prwrapped struct {
	PRWrapped
}

func newPRWrapped() *prwrapped {
	return &prwrapped{}
}

func (m *prwrapped) init(r, peerID uint32, msg []byte, prevhash []byte, seq uint64, auth []byte) {
	m.PRWrapped = PRWrapped{Msg: &PRWrapped_M{
		ReplicaId: r,
		PeerId: peerID,
		Msg: msg,
		Prevhash: prevhash,
		Sequence: seq,
		Authenticator: auth,
	}}
}

func (m *prwrapped) set(pbMsg *PRWrapped) {
	m.PRWrapped = *pbMsg
}

func (m *prwrapped) MarshalBinary() ([]byte, error) {
	return proto.Marshal(&Message{Type: &Message_Prwrapped{Prwrapped: &m.PRWrapped}})
}

func (m *prwrapped) ReplicaID() uint32 {
	return m.Msg.GetReplicaId()
}

func (m *prwrapped) PeerID() uint32 {
	return m.Msg.GetPeerId()
}

func (m *prwrapped) PrevHash() []byte {
	return m.Msg.GetPrevhash()
}

func (m *prwrapped) Sequence() uint64 {
	return m.Msg.GetSequence()
}

func (m *prwrapped) Authenticator() []byte {
	return m.Msg.GetAuthenticator()
}

func (m *prwrapped) ExtractMessage() []byte {
	return m.Msg.Msg
}

func (prwrapped) ImplementsReplicaMessage() {}
func (prwrapped) ImplementsPRWrapped() {}
