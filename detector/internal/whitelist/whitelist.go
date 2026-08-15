package whitelist

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/sahraali252/sentinel/detector/internal/config"
)

type List struct {
	addresses map[netip.Addr]struct{}
	prefixes  []netip.Prefix
	endpoints []string
}

func New(cfg config.Whitelist) (*List, error) {
	l := &List{addresses: make(map[netip.Addr]struct{}), endpoints: cfg.Endpoints}
	for _, raw := range cfg.SourceIPs {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			return nil, fmt.Errorf("whitelist IP %q: %w", raw, err)
		}
		l.addresses[addr] = struct{}{}
	}
	for _, raw := range cfg.CIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("whitelist CIDR %q: %w", raw, err)
		}
		l.prefixes = append(l.prefixes, prefix)
	}
	return l, nil
}

func (l *List) Allows(sourceIP, endpoint string) bool {
	for _, allowed := range l.endpoints {
		if endpoint == allowed || strings.HasPrefix(endpoint, allowed+"/") {
			return true
		}
	}
	addr, err := netip.ParseAddr(sourceIP)
	if err != nil {
		return false
	}
	if _, ok := l.addresses[addr]; ok {
		return true
	}
	for _, prefix := range l.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
