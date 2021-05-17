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

// Package protobuf implements protocol message interface using
// Protocol Buffers as serialization mechanism.
package protobuf

import (
	"golang.org/x/xerrors"

	"google.golang.org/protobuf/proto"

	"github.com/hyperledger-labs/minbft/messages"
	"github.com/hyperledger-labs/minbft/messages/protobuf/pb"
)

type impl struct{}

// NewImpl returns the package's implementation of protocol messages.
func NewImpl() messages.MessageImpl {
	return &impl{}
}

func (*impl) NewFromBinary(data []byte) (messages.Message, error) {
	pbMsg := &pb.Message{}
	if err := proto.Unmarshal(data, pbMsg); err != nil {
		return nil, xerrors.Errorf("failed to unmarshal message wrapper: %w", err)
	}

	return typedMessageFromPb(pbMsg)
}

func (*impl) NewHello(r uint32) messages.Hello {
	return newHello(r)
}

func (*impl) NewRequest(cl uint32, seq uint64, op []byte) messages.Request {
	return newRequest(cl, seq, op)
}

func (*impl) NewPrepare(r uint32, v uint64, req messages.Request) messages.Prepare {
	return newPrepare(r, v, req)
}

func (*impl) NewCommit(r uint32, prep messages.Prepare) messages.Commit {
	return newCommit(r, prep)
}

func (*impl) NewReply(r, cl uint32, seq uint64, res []byte) messages.Reply {
	return newReply(r, cl, seq, res)
}

func (*impl) NewReqViewChange(r uint32, nv uint64) messages.ReqViewChange {
	return newReqViewChange(r, nv)
}

func (*impl) NewViewChange(r uint32, nv uint64, log messages.MessageLog, vcCert messages.ViewChangeCert) messages.ViewChange {
	panic("Not implemented")
}

func marshalMessage(m proto.Message) ([]byte, error) {
	return proto.Marshal(pb.WrapMessage(m))
}
