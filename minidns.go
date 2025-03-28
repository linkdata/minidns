package minidns

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
	"strings"

	"github.com/miekg/dns"
)

// Resolver represents a DNS resolver with QNAME minimization.
type Resolver struct {
	client       *dns.Client
	root         string
	clientCookie string
	serverCookie string
	DebugLog     bool
}

// NewResolver creates a new Resolver starting from the given root server (e.g., "198.41.0.4:53").
func NewResolver(root string, debugLog bool) (*Resolver, error) {
	r := &Resolver{
		client:   &dns.Client{},
		root:     root,
		DebugLog: debugLog,
	}
	cookie := make([]byte, 8)
	if _, err := rand.Read(cookie); err != nil {
		return nil, err
	}
	r.clientCookie = hex.EncodeToString(cookie)
	return r, nil
}

// Lookup performs a recursive DNS lookup with delegation handling and CNAME resolution.
func (r *Resolver) Lookup(name string, qtype uint16) (*dns.Msg, error) {
	finalMsg := new(dns.Msg)
	visited := map[string]struct{}{}
	return r.lookup(name, qtype, visited, finalMsg)
}

func (r *Resolver) lookup(name string, qtype uint16, visited map[string]struct{}, finalMsg *dns.Msg) (*dns.Msg, error) {
	name = strings.ToLower(dns.Fqdn(name))
	if _, ok := visited[name]; ok {
		return nil, errors.New("loop detected")
	}
	visited[name] = struct{}{}

	currentServers := []string{r.root}
	for depth := 0; depth < 30; depth++ {
		var nextServers []string
		for _, server := range currentServers {
			query := new(dns.Msg)
			query.SetQuestion(name, qtype)
			r.addEDNS(query)
			r.logMsg("Query", query, server)

			response, _, err := r.client.Exchange(query, server)
			if err != nil || response == nil {
				r.logMsg("Error or nil response", response, server)
				continue
			}
			r.logMsg("Response", response, server)
			r.updateCookies(response)

			if response.Rcode != dns.RcodeSuccess {
				return response, errors.New("DNS query failed with RCODE: " + dns.RcodeToString[response.Rcode])
			}

			if len(response.Answer) > 0 {
				for _, ans := range response.Answer {
					finalMsg.Answer = append(finalMsg.Answer, ans)
					if cname, ok := ans.(*dns.CNAME); ok {
						return r.lookup(cname.Target, qtype, visited, finalMsg)
					}
				}
				return finalMsg, nil
			}

			if len(response.Ns) > 0 {
				resolvedNS := extractGlue(response)
				if len(resolvedNS) == 0 {
					resolvedNS, err = r.resolveNSWithDNS(response)
					if err != nil {
						continue
					}
				}
				nextServers = append(nextServers, resolvedNS...)
				break
			}
		}

		if len(nextServers) == 0 {
			return nil, errors.New("resolution failed: no next servers")
		}

		currentServers = nextServers
	}
	return nil, errors.New("maximum recursion depth reached")
}

func extractGlue(msg *dns.Msg) []string {
	var servers []string
	for _, rr := range msg.Extra {
		if a, ok := rr.(*dns.A); ok {
			servers = append(servers, a.A.String()+":53")
		}
	}
	return servers
}

func (r *Resolver) resolveNSWithDNS(msg *dns.Msg) ([]string, error) {
	var servers []string
	for _, rr := range msg.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			nsResponse, err := r.Lookup(ns.Ns, dns.TypeA)
			if err != nil || nsResponse == nil || len(nsResponse.Answer) == 0 {
				continue
			}
			for _, ans := range nsResponse.Answer {
				if a, ok := ans.(*dns.A); ok {
					servers = append(servers, a.A.String()+":53")
				}
			}
		}
	}
	if len(servers) == 0 {
		return nil, errors.New("no NS servers resolved")
	}
	return servers, nil
}

func (r *Resolver) addEDNS(msg *dns.Msg) {
	opt := &dns.OPT{
		Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT},
	}
	opt.SetUDPSize(1232)
	cookie := &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: r.clientCookie}
	opt.Option = append(opt.Option, cookie)
	msg.Extra = append(msg.Extra, opt)
}

func (r *Resolver) updateCookies(msg *dns.Msg) {
	for _, extra := range msg.Extra {
		if opt, ok := extra.(*dns.OPT); ok {
			for _, option := range opt.Option {
				if cookie, ok := option.(*dns.EDNS0_COOKIE); ok && len(cookie.Cookie) >= 16 {
					r.serverCookie = cookie.Cookie[16:]
				}
			}
		}
	}
}

func (r *Resolver) logMsg(prefix string, msg *dns.Msg, server string) {
	if r.DebugLog {
		log.Printf("%s [%s]:\n%v\n", prefix, server, msg)
	}
}
