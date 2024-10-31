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
	blacklist map[string]struct{}
	mtx       sync.RWMutex
}

func NewDefaultBlacklist() *DefaultBlacklist {
	return &DefaultBlacklist{
		blacklist: make(map[string]struct{}),
	}
}

func (b *DefaultBlacklist) Add(ip []net.IP) error {
	b.mtx.Lock()
	for _, address := range ip {
		b.blacklist[address.String()] = struct{}{}
	}
	b.mtx.Unlock()
	return nil
}

func (b *DefaultBlacklist) Remove(ip []net.IP) error {
	b.mtx.Lock()
	for _, address := range ip {
		delete(b.blacklist, address.String())
	}
	b.mtx.Unlock()
	return nil
}

func (b *DefaultBlacklist) IsValid(ip net.IP) bool {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	_, blacklisted := b.blacklist[ip.String()]
	return !blacklisted
}
