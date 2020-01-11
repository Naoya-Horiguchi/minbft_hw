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
	fmt "fmt"

	"github.com/golang/protobuf/proto"

	"github.com/hyperledger-labs/minbft/messages"
)

type impl struct{}

func NewImpl() messages.MessageImpl {
	return &impl{}
}

func (*impl) NewFromBinary(data []byte) (messages.Message, error) {
	msg := &Message{}
	if err := proto.Unmarshal(data, msg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal message wrapper: %s", err)
	}

	switch t := msg.Type.(type) {
	case *Message_Forwardauth:
		forwardauth := newForwardAuth()
		forwardauth.set(t.Forwardauth)
		return forwardauth, nil
	case *Message_Loghistory:
		loghistory := newLogHistory()
		loghistory.set(t.Loghistory)
		return loghistory, nil
	case *Message_Prwrapped:
		audit := newPRWrapped()
		audit.set(t.Prwrapped)
		return audit, nil
	case *Message_Acknowledge:
		acknowledge := newAcknowledge()
		acknowledge.set(t.Acknowledge)
		return acknowledge, nil
	case *Message_Audit:
		audit := newAudit()
		audit.set(t.Audit)
		return audit, nil
	case *Message_Prepare:
		prep := newPrepare()
		prep.set(t.Prepare)
		return prep, nil
	case *Message_Request:
		req := newRequest()
		req.set(t.Request)
		return req, nil
	case *Message_Commit:
		comm := newCommit()
		comm.set(t.Commit)
		return comm, nil
	case *Message_Reply:
		reply := newReply()
		reply.set(t.Reply)
		return reply, nil
	default:
		return nil, fmt.Errorf("unknown message type")
	}
}

func (*impl) NewRequest(cl uint32, seq uint64, op []byte) messages.Request {
	m := newRequest()
	m.init(cl, seq, op)
	return m
}

func (*impl) NewPrepare(r uint32, v uint64, req messages.Request) messages.Prepare {
	m := newPrepare()
	m.init(r, v, req)
	return m
}

func (*impl) NewCommit(r uint32, prep messages.Prepare) messages.Commit {
	m := newCommit()
	m.init(r, prep)
	return m
}

func (*impl) NewReply(r, cl uint32, seq uint64, res []byte) messages.Reply {
	m := newReply()
	m.init(r, cl, seq, res)
	return m
}

func (*impl) NewPRWrapped(r, p uint32, msgbyte []byte, prevhash []byte, seq uint64, auth []byte) messages.PRWrapped {
	m := newPRWrapped()
	m.init(r, p, msgbyte, prevhash, seq, auth)
	return m
}

func (*impl) NewAcknowledge(r, p uint32, prevhash []byte, seq uint64, auth []byte, msgbyte []byte) messages.Acknowledge {
	m := newAcknowledge()
	m.init(r, p, prevhash, seq, auth, msgbyte)
	return m
}

func (*impl) NewAudit(r, p uint32, msgbyte []byte, prevhash []byte, seq uint64, auth []byte) messages.AuditMessage {
	m := newAudit()
	m.init(r, p, msgbyte, prevhash, seq, auth)
	return m
}

func (*impl) NewLogHistory(r, p uint32, logs []byte) messages.LogHistory {
	m := newLogHistory()
	m.init(r, p, logs)
	return m
}

func (*impl) NewForwardAuth(r, p uint32, seq uint64, auth []byte) messages.ForwardAuth {
	m := newForwardAuth()
	m.init(r, p, seq, auth)
	return m
}
