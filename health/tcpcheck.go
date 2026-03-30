package health

import (
	"context"
	"fmt"
	"net"
	"time"
)

const defaultTCPDialTimeout = time.Second

// TCPDialCheck verifies that a TCP listener is accepting connections.
// Wildcard listen addresses such as ":8080" or "0.0.0.0:8080" are probed
// through loopback so services can self-check their own listeners safely.
func TCPDialCheck(listenAddr string, timeout time.Duration) CheckFunc {
	return func() CheckStatus {
		probeAddr, err := probeAddrFromListenAddr(listenAddr)
		if err != nil {
			return CheckStatus{
				Status: "fail",
				Detail: fmt.Sprintf("invalid listen addr: %v", err),
			}
		}
		dialTimeout := timeout
		if dialTimeout <= 0 {
			dialTimeout = defaultTCPDialTimeout
		}

		ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		defer cancel()

		var d net.Dialer
		conn, err := d.DialContext(ctx, "tcp", probeAddr)
		if err != nil {
			return CheckStatus{
				Status: "fail",
				Detail: err.Error(),
			}
		}
		_ = conn.Close()
		return CheckStatus{Status: "ok"}
	}
}

func probeAddrFromListenAddr(listenAddr string) (string, error) {
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return "", err
	}

	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}

	return net.JoinHostPort(host, port), nil
}
