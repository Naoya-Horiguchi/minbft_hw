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

	// "github.com/hyperledger-labs/minbft/messages"
)

type audit struct {
	Audit
}

func newAuditMessage() *audit {
	return &audit{}
}

func (m *audit) init(msg *Message, prevhash []byte, seq uint64, auth []byte) {
	m.Audit = Audit{
		Msg: msg,
		Prevhash: prevhash,
		Sequence: seq,
		Authenticator: auth,
	}
}

func (m *audit) set(pbMsg *Audit) {
	m.Audit = *pbMsg
}

func (m *audit) MarshalBinary() ([]byte, error) {
	return proto.Marshal(m)
}

// func (m *audit) ReplicaID() uint32 {
// 	return m.Msg.GetReplicaId()
// }

// func (m *audit) View() uint64 {
// 	return m.Msg.GetView()
// }

// func (m *audit) Request() messages.Request {
// 	req := newRequest()
// 	req.set(m.Msg.GetRequest())
// 	return req
// }

// func (m *audit) CertifiedPayload() []byte {
// 	return MarshalOrPanic(m.Msg)
// }

// func (m *audit) UIBytes() []byte {
// 	return m.ReplicaUi
// }

// func (m *audit) SetUIBytes(uiBytes []byte) {
// 	m.ReplicaUi = uiBytes
// }
