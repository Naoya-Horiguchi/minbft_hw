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

type evidencetransfer struct {
	EvidenceTransfer
}

func newEvidenceTransfer() *evidencetransfer {
	return &evidencetransfer{}
}

// using r as generator replica of authenticator
func (m *evidencetransfer) init(r, peerID, fault, ftype uint32, msg []byte) {
	m.EvidenceTransfer = EvidenceTransfer{Msg: &EvidenceTransfer_M{
		ReplicaId: r,
		PeerId: peerID,
		FaultyId: fault,
		Faulttype: ftype,
		Proof: msg,
	}}
}

func (m *evidencetransfer) set(pbMsg *EvidenceTransfer) {
	m.EvidenceTransfer = *pbMsg
}

func (m *evidencetransfer) MarshalBinary() ([]byte, error) {
	return proto.Marshal(&Message{Type: &Message_Evidencetransfer{Evidencetransfer: &m.EvidenceTransfer}})
}

func (m *evidencetransfer) ReplicaID() uint32 {
	return m.Msg.GetReplicaId()
}

func (m *evidencetransfer) PeerID() uint32 {
	return m.Msg.GetPeerId()
}

func (m *evidencetransfer) FaultID() uint32 {
	return m.Msg.GetFaultyId()
}

func (m *evidencetransfer) Ftype() uint32 {
	return m.Msg.GetFaulttype()
}

func (m *evidencetransfer) Proof() []byte {
	return m.Msg.GetProof()
}

func (m *evidencetransfer) ExtractMessage() []byte {
	return []byte{}
}

func (m *evidencetransfer) Authenticator() []byte {
	return []byte{}
}

func (m *evidencetransfer) PrevHash() []byte {
	return []byte{}
}

func (m *evidencetransfer) Sequence() uint64 {
	return uint64(0)
}

func (evidencetransfer) ImplementsReplicaMessage() {}
func (evidencetransfer) ImplementsEvidenceTransfer() {}
