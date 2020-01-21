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

type challenge struct {
	Challenge
}

func newChallenge() *challenge {
	return &challenge{}
}

// using r as generator replica of authenticator
func (m *challenge) init(r, peerID, fault uint32) {
	m.Challenge = Challenge{Msg: &Challenge_M{
		ReplicaId: r,
		PeerId: peerID,
		FaultyId: fault,
	}}
}

func (m *challenge) set(pbMsg *Challenge) {
	m.Challenge = *pbMsg
}

func (m *challenge) MarshalBinary() ([]byte, error) {
	return proto.Marshal(&Message{Type: &Message_Challenge{Challenge: &m.Challenge}})
}

func (m *challenge) ReplicaID() uint32 {
	return m.Msg.GetReplicaId()
}

func (m *challenge) PeerID() uint32 {
	return m.Msg.GetPeerId()
}

func (m *challenge) PrevHash() []byte {
	return []byte{}
}

func (m *challenge) Sequence() uint64 {
	return uint64(0)
}

func (m *challenge) Authenticator() []byte {
	return []byte{}
}

func (m *challenge) ExtractMessage() []byte {
	return []byte{}
}

func (m *challenge) FaultID() uint32 {
	return m.Msg.GetFaultyId()
}

func (challenge) ImplementsReplicaMessage() {}
func (challenge) ImplementsChallenge() {}
