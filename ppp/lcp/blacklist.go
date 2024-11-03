package lcp

import (
	"net"
	"sync"
)

type Blacklist interface {
	Add(ip []net.IP) error
	Remove(ip []net.IP) error
	IsValid(ip net.IP) bool
}

type DefaultBlacklist struct {
	blacklist map[[16]byte]struct{}
	mtx       sync.RWMutex
}

func NewDefaultBlacklist() *DefaultBlacklist {
	return &DefaultBlacklist{
		blacklist: make(map[[16]byte]struct{}),
	}
}

// Add adds an IP address that needs to be skipped
// if assigned by the AC.
func (b *DefaultBlacklist) Add(ip []net.IP) error {
	b.mtx.Lock()
	for _, address := range ip {
		b.blacklist[[16]byte(address.To16()[:16])] = struct{}{}
	}
	b.mtx.Unlock()
	return nil
}

// Remove removes an IP address from existing blacklist, if present.
func (b *DefaultBlacklist) Remove(ip []net.IP) error {
	b.mtx.Lock()
	for _, address := range ip {
		delete(b.blacklist, [16]byte(address.To16()[:16]))
	}
	b.mtx.Unlock()
	return nil
}

// IsValid returns true if the specified IP is not in the blacklist.
func (b *DefaultBlacklist) IsValid(ip net.IP) bool {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	_, blacklisted := b.blacklist[[16]byte(ip.To16()[:16])]
	return !blacklisted
}
