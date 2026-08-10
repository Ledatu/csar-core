package clientx

import (
	"errors"
	"fmt"
	"net"
)

// InternalIPClass identifies why an IP address is considered internal.
type InternalIPClass string

const (
	ClassMetadata  InternalIPClass = "cloud_metadata"
	ClassLoopback  InternalIPClass = "loopback"
	ClassLinkLocal InternalIPClass = "link_local"
	ClassPrivate   InternalIPClass = "private"
)

// ErrInternalIP is returned by CheckInternalIP when the address falls into one
// of the internal classes the caller asked about. Use errors.As with
// *InternalIPError to recover the specific class.
var ErrInternalIP = errors.New("clientx: address is internal")

// InternalIPError describes a rejected address.
type InternalIPError struct {
	IP    net.IP
	Class InternalIPClass
}

func (e *InternalIPError) Error() string {
	return fmt.Sprintf("clientx: %s is a %s address", e.IP, e.Class)
}

func (e *InternalIPError) Unwrap() error { return ErrInternalIP }

// InternalIPClasses selects which categories CheckInternalIP rejects.
type InternalIPClasses struct {
	Private   bool
	Loopback  bool
	LinkLocal bool
	Metadata  bool
}

// AllInternalIPClasses rejects every internal category. This is the correct
// default for any outbound call to a third-party endpoint.
func AllInternalIPClasses() InternalIPClasses {
	return InternalIPClasses{Private: true, Loopback: true, LinkLocal: true, Metadata: true}
}

var (
	private10  = mustParseCIDR("10.0.0.0/8")
	private172 = mustParseCIDR("172.16.0.0/12")
	private192 = mustParseCIDR("192.168.0.0/16")
	linkLocal4 = mustParseCIDR("169.254.0.0/16")
	linkLocal6 = mustParseCIDR("fe80::/10")

	metadataAddr = net.ParseIP("169.254.169.254")
)

func mustParseCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// CheckInternalIP reports whether ip falls into one of the enabled internal
// classes. It returns nil when the address is safe to dial, or an error
// wrapping ErrInternalIP otherwise.
//
// This is the shared classification predicate behind both the csar router's
// per-route SSRF protection and outbound clients that dial an operator
// allowlist. It is pure and stateless on purpose: policy (what to block, which
// hosts bypass, how to dial) belongs to the caller.
func CheckInternalIP(ip net.IP, classes InternalIPClasses) error {
	// Metadata is the most specific class, so it is checked first — otherwise
	// 169.254.169.254 would be reported as merely link-local.
	if classes.Metadata && ip.Equal(metadataAddr) {
		return &InternalIPError{IP: ip, Class: ClassMetadata}
	}

	if classes.Loopback && ip.IsLoopback() {
		return &InternalIPError{IP: ip, Class: ClassLoopback}
	}

	if classes.LinkLocal && (linkLocal4.Contains(ip) || linkLocal6.Contains(ip)) {
		return &InternalIPError{IP: ip, Class: ClassLinkLocal}
	}

	if classes.Private {
		if private10.Contains(ip) || private172.Contains(ip) || private192.Contains(ip) {
			return &InternalIPError{IP: ip, Class: ClassPrivate}
		}
		// IPv6 unique local addresses, fc00::/7.
		if len(ip) == net.IPv6len && ip[0]&0xfe == 0xfc {
			return &InternalIPError{IP: ip, Class: ClassPrivate}
		}
	}

	return nil
}
