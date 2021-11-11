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
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger-labs/minbft/messages"
)

func TestCommit(t *testing.T) {
	impl := NewImpl()

	t.Run("Fields", func(t *testing.T) {
		r := rand.Uint32()
		prep := randPrep(impl)
		comm := impl.NewCommit(r, prep)
		require.Equal(t, r, comm.ReplicaID())
		requireCertMsgEqual(t, prep, comm.Proposal())
	})
	t.Run("SetUI", func(t *testing.T) {
		comm := randComm(impl)
		ui := randUI(messages.AuthenBytes(comm))
		comm.SetUI(ui)
		require.Equal(t, ui, comm.UI())
	})
	t.Run("Marshaling", func(t *testing.T) {
		comm := randComm(impl)
		requireCommEqual(t, comm, remarshalMsg(impl, comm).(messages.Commit))
	})
}

func randComm(impl messages.MessageImpl) messages.Commit {
	return newTestComm(impl, rand.Uint32(), randPrep(impl), rand.Uint64())
}

func newTestComm(impl messages.MessageImpl, r uint32, prep messages.Prepare, cv uint64) messages.Commit {
	comm := impl.NewCommit(r, prep)
	comm.SetUI(newTestUI(cv, messages.AuthenBytes(comm)))
	return comm
}

func requireCommEqual(t *testing.T, comm1, comm2 messages.Commit) {
	require.Equal(t, comm1.ReplicaID(), comm2.ReplicaID())
	requireCertMsgEqual(t, comm1.Proposal(), comm2.Proposal())
	require.Equal(t, comm1.UI(), comm2.UI())
}
