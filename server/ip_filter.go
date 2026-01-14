package server

import (
	"log"
	"net"
	"net/http"
	"os"
	"sync"

	"github.com/tomasen/realip"
)

// IPFilterOptions for ipFilter. Allowed takes precedence over Blocked.
// IPs can be IPv4 or IPv6 and can optionally contain subnet
// masks (/24). Note however, determining if a given IP is
// included in a subnet requires a linear scan so is less performant
// than looking up single IPs.
//
// This could be improved with some algorithmic magic.
type IPFilterOptions struct {
	//explicitly allowed IPs
	AllowedIPs []string
	//explicitly blocked IPs
	BlockedIPs []string
	//block by default (defaults to allow)
	BlockByDefault bool
	// TrustProxy enable check request IP from proxy
	TrustProxy bool

	Logger interface {
		Printf(format string, v ...interface{})
	}
}

// ipFilter
type ipFilter struct {
	//mut protects the below
	//rw since writes are rare
	mut            sync.RWMutex
	defaultAllowed bool
	ips            map[string]bool
	subnets        []*subnet
}

type subnet struct {
	str     string
	ipnet   *net.IPNet
	allowed bool
}

func newIPFilter(opts *IPFilterOptions) *ipFilter {
	if opts.Logger == nil {
		flags := log.LstdFlags
		opts.Logger = log.New(os.Stdout, "", flags)
	}
	f := &ipFilter{
		ips:            map[string]bool{},
		defaultAllowed: !opts.BlockByDefault,
	}
	for _, ip := range opts.BlockedIPs {
		f.BlockIP(ip)
	}
	for _, ip := range opts.AllowedIPs {
		f.AllowIP(ip)
	}
	return f
}

func (f *ipFilter) AllowIP(ip string) bool {
	return f.ToggleIP(ip, true)
}

func (f *ipFilter) BlockIP(ip string) bool {
	return f.ToggleIP(ip, false)
}

func (f *ipFilter) ToggleIP(str string, allowed bool) bool {
	//check if provided string describes a subnet
	if ip, network, err := net.ParseCIDR(str); err == nil {
		// containing only one ip?
		if n, total := network.Mask.Size(); n == total {
			f.mut.Lock()
			f.ips[ip.String()] = allowed
			f.mut.Unlock()
			return true
		}
		//check for existing
		f.mut.Lock()
		found := false
		for _, subnet := range f.subnets {
			if subnet.str == str {
				found = true
				subnet.allowed = allowed
				break
			}
		}
		if !found {
			f.subnets = append(f.subnets, &subnet{
				str:     str,
				ipnet:   network,
				allowed: allowed,
			})
		}
		f.mut.Unlock()
		return true
	}
	//check if plain ip
	if ip := net.ParseIP(str); ip != nil {
		f.mut.Lock()
		f.ips[ip.String()] = allowed
		f.mut.Unlock()
		return true
	}
	return false
}

// ToggleDefault alters the default setting
func (f *ipFilter) ToggleDefault(allowed bool) {
	f.mut.Lock()
	f.defaultAllowed = allowed
	f.mut.Unlock()
}

// Allowed returns if a given IP can pass through the filter
func (f *ipFilter) Allowed(ipstr string) bool {
	return f.NetAllowed(net.ParseIP(ipstr))
}

// NetAllowed returns if a given net.IP can pass through the filter
func (f *ipFilter) NetAllowed(ip net.IP) bool {
	//invalid ip
	if ip == nil {
		return false
	}
	//read lock entire function
	//except for db access
	f.mut.RLock()
	defer f.mut.RUnlock()
	//check single ips
	allowed, ok := f.ips[ip.String()]
	if ok {
		return allowed
	}
	//scan subnets for any allow/block
	blocked := false
	for _, subnet := range f.subnets {
		if subnet.ipnet.Contains(ip) {
			if subnet.allowed {
				return true
			}
			blocked = true
		}
	}
	if blocked {
		return false
	}

	//use default setting
	return f.defaultAllowed
}

// Blocked returns if a given IP can NOT pass through the filter
func (f *ipFilter) Blocked(ip string) bool {
	return !f.Allowed(ip)
}

// NetBlocked returns if a given net.IP can NOT pass through the filter
func (f *ipFilter) NetBlocked(ip net.IP) bool {
	return !f.NetAllowed(ip)
}

// Wrap the provided handler with simple IP blocking middleware
// using this IP filter and its configuration
func (f *ipFilter) Wrap(next http.Handler) http.Handler {
	return &ipFilterMiddleware{ipFilter: f, next: next}
}

// WrapIPFilter is equivalent to newIPFilter(opts) then Wrap(next)
func WrapIPFilter(next http.Handler, opts *IPFilterOptions) http.Handler {
	return newIPFilter(opts).Wrap(next)
}

type ipFilterMiddleware struct {
	*ipFilter
	next http.Handler
}

func (m *ipFilterMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	remoteIP := realip.FromRequest(r)

	if !m.ipFilter.Allowed(remoteIP) {
		//show simple forbidden text
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	//success!
	m.next.ServeHTTP(w, r)
}
