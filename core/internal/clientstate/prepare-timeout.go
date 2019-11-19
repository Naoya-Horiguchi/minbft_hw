// Copyright (c) 2019 NEC Solution Innovators, Ltd.
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

package clientstate

import (
	"sync"
	"time"
	"fmt"

	"github.com/hyperledger-labs/minbft/core/internal/timer"
)

type prepareTimerState struct {
	sync.Mutex

	prepareTimer timer.Timer

	opts *options
}

func newPrepareTimeoutState(opts *options) *prepareTimerState {
	return &prepareTimerState{opts: opts}
}

func (s *prepareTimerState) StartPrepareTimer(forward func()) {
	s.Lock()
	defer s.Unlock()

	timerProvider := s.opts.timerProvider
	timeout := s.opts.prepareTimeout()

	if s.prepareTimer != nil {
		s.prepareTimer.Stop()
	}

	if timeout <= time.Duration(0) {
		return
	}

	fmt.Printf("start forward timer: timeout = %d\n", timeout)
	s.prepareTimer = timerProvider.AfterFunc(timeout, forward)
}

func (s *prepareTimerState) StopPrepareTimer() {
	s.Lock()
	defer s.Unlock()

	if s.prepareTimer != nil {
		s.prepareTimer.Stop()
	}
}
