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

type forwardauth struct {
	ForwardAuth
}

func newForwardAuth() *forwardauth {
	return &forwardauth{}
}

// using r as generator replica of authenticator
func (m *forwardauth) init(r, peerID uint32, seq uint64, auth []byte) {
	m.ForwardAuth = ForwardAuth{Msg: &ForwardAuth_M{
		ReplicaId: r,
		PeerId: peerID,
		Sequence: seq,
		Authenticator: auth,
	}}
}

func (m *forwardauth) set(pbMsg *ForwardAuth) {
	m.ForwardAuth = *pbMsg
}

func (m *forwardauth) MarshalBinary() ([]byte, error) {
	return proto.Marshal(&Message{Type: &Message_Forwardauth{Forwardauth: &m.ForwardAuth}})
}

func (m *forwardauth) ReplicaID() uint32 {
	return m.Msg.GetReplicaId()
}

func (m *forwardauth) PeerID() uint32 {
	return m.Msg.GetPeerId()
}

func (m *forwardauth) PrevHash() []byte {
	return []byte{}
}

func (m *forwardauth) Sequence() uint64 {
	return m.Msg.GetSequence()
}

func (m *forwardauth) Authenticator() []byte {
	return m.Msg.GetAuthenticator()
}

func (m *forwardauth) ExtractMessage() []byte {
	return []byte{}
}

// func (m *forwardauth) Logs() []byte {
// 	return m.Msg.GetLogs()
// }

func (forwardauth) ImplementsReplicaMessage() {}
func (forwardauth) ImplementsForwardAuth() {}
