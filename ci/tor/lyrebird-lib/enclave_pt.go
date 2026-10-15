// lyrebird's Snowflake and WebTunnel clients as a library, for the phone
// app (docs/09-transport.md §7): a phone starts no programs, so instead of
// lyrebird speaking the pluggable-transport protocol from its own process,
// enclave-tord calls enclave_pt_start in-process and gets the loopback port
// of a SOCKS5 listener for the transport, as lyrebird's own CMETHOD line
// would give it. The handler is lyrebird's (cmd/lyrebird/lyrebird.go),
// without an upstream proxy. Built by `ci/tor/lyrebird.sh archive` inside
// the pinned lyrebird module, as a C archive linked into enclave-mobile.
package main

import "C"

import (
	"io"
	"net"
	"sync"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/log"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/socks5"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/base"
	"golang.org/x/net/proxy"
)

var initOnce sync.Once
var initErr error

// enclave_pt_start runs transport `name` ("snowflake" or "webtunnel") with
// its state under `stateDir`, and returns its SOCKS5 port on 127.0.0.1, or
// -1 if it can't.
//
//export enclave_pt_start
func enclave_pt_start(stateDir *C.char, name *C.char) C.int {
	initOnce.Do(func() {
		if initErr = log.Init(false, "", false); initErr == nil {
			initErr = transports.Init()
		}
	})
	if initErr != nil {
		return -1
	}
	t := transports.Get(C.GoString(name))
	if t == nil {
		return -1
	}
	f, err := t.ClientFactory(C.GoString(stateDir))
	if err != nil {
		return -1
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return -1
	}
	go func() {
		defer ln.Close()
		for {
			conn, err := ln.Accept()
			if err != nil {
				if e, ok := err.(net.Error); ok && !e.Temporary() {
					return
				}
				continue
			}
			go handle(f, conn)
		}
	}()
	return C.int(ln.Addr().(*net.TCPAddr).Port)
}

func handle(f base.ClientFactory, conn net.Conn) {
	defer conn.Close()
	req, err := socks5.Handshake(conn)
	if err != nil {
		return
	}
	args, err := f.ParseArgs(&req.Args)
	if err != nil {
		_ = req.Reply(socks5.ReplyGeneralFailure)
		return
	}
	remote, err := f.Dial("tcp", req.Target, proxy.Direct.Dial, args)
	if err != nil {
		_ = req.Reply(socks5.ErrorToReplyCode(err))
		return
	}
	defer remote.Close()
	if req.Reply(socks5.ReplySucceeded) != nil {
		return
	}
	done := make(chan struct{}, 1)
	go func() {
		_, _ = io.Copy(remote, conn)
		done <- struct{}{}
	}()
	_, _ = io.Copy(conn, remote)
	<-done
}

func main() {}
