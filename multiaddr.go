package coredns_multiaddr

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/miekg/dns"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/multiformats/go-multibase"
)

var log = clog.NewWithPlugin("multiaddr")

type MultiaddrParser struct {
	Next plugin.Handler
}

const ttl = 5 * time.Minute

// ServeDNS implements the plugin.Handler interface.
func (p MultiaddrParser) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	var answers []dns.RR
	for _, q := range r.Question {
		if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
			continue
		}
		split := strings.SplitN(q.Name, ".", 2)
		if len(split) != 2 {
			continue
		}
		subdomain := split[0]
		_, data, err := multibase.Decode(subdomain)
		if err != nil {
			continue
		}
		addr, err := ma.NewMultiaddrBytes(data)
		if err != nil {
			continue
		}
		c, _ := ma.SplitFirst(addr)
		ip := net.ParseIP(c.Value())
		if ip == nil {
			continue
		}
		switch {
		default:
			continue
		case q.Qtype == dns.TypeA && c.Protocol().Code == ma.P_IP4:
			answers = append(answers, &dns.A{
				Hdr: dns.RR_Header{
					Name:   dns.Fqdn(q.Name),
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    uint32(ttl.Seconds()),
				},
				A: ip,
			})
		case q.Qtype == dns.TypeAAAA && c.Protocol().Code == ma.P_IP6:
			answers = append(answers, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   dns.Fqdn(q.Name),
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    uint32(ttl.Seconds()),
				},
				AAAA: ip,
			})
		}
	}

	if len(answers) > 0 {
		var m dns.Msg
		m.SetReply(r)
		m.Authoritative = true
		m.Answer = answers
		w.WriteMsg(&m)
		return dns.RcodeSuccess, nil
	}

	// Call next plugin (if any).
	return plugin.NextOrFailure(p.Name(), p.Next, ctx, w, r)
}

// Name implements the Handler interface.
func (p MultiaddrParser) Name() string { return "multiaddr" }
