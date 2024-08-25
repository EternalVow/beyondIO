// Copyright (c) 2020 The Gnet Authors. All rights reserved.
// Copyright (c) 2017 Max Riveiro
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

//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd
// +build darwin dragonfly freebsd linux netbsd openbsd

// Package socket provides functions that return fd and net.Addr based on
// given the protocol and address with a SO_REUSEPORT option set to the socket.
package socket

import (
	"golang.org/x/sys/unix"
)

// Option is used for setting an option on socket.
type Option struct {
	SetSockOpt func(int, int) error
	Opt        int
}

// Accept accepts the next incoming socket along with setting
// O_NONBLOCK and O_CLOEXEC flags on it.
func Accept(fd int) (int, unix.Sockaddr, error) {
	return sysAccept(fd)
}
