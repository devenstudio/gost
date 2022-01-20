package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/go-log/log"
)

type stringList []string

func (l *stringList) String() string {
	return fmt.Sprintf("%s", *l)
}
func (l *stringList) Set(value string) error {
	*l = append(*l, value)
	return nil
}

type route struct {
	ServeNodes stringList
	ChainNodes stringList
	Retries    int
}

func (r *route) parseChain() (*Chain, error) {
	chain := NewChain()
	chain.Retries = r.Retries
	gid := 1 // group ID

	for _, ns := range r.ChainNodes {
		ngroup := NewNodeGroup()
		ngroup.ID = gid
		gid++

		// parse the base nodes
		nodes, err := parseChainNode(ns)
		if err != nil {
			return nil, err
		}

		nid := 1 // node ID
		for i := range nodes {
			nodes[i].ID = nid
			nid++
		}
		ngroup.AddNode(nodes...)

		ngroup.SetSelector(nil,
			WithFilter(
				&FailFilter{
					MaxFails:    nodes[0].GetInt("max_fails"),
					FailTimeout: nodes[0].GetDuration("fail_timeout"),
				},
				&InvalidFilter{},
			),
			WithStrategy(NewStrategy(nodes[0].Get("strategy"))),
		)

		chain.AddNodeGroup(ngroup)
	}

	return chain, nil
}

func parseChainNode(ns string) (nodes []Node, err error) {
	node, err := ParseNode(ns)
	if err != nil {
		return
	}

	if auth := node.Get("auth"); auth != "" && node.User == nil {
		c, err := base64.StdEncoding.DecodeString(auth)
		if err != nil {
			return nil, err
		}
		cs := string(c)
		s := strings.IndexByte(cs, ':')
		if s < 0 {
			node.User = url.User(cs)
		} else {
			node.User = url.UserPassword(cs[:s], cs[s+1:])
		}
	}
	if node.User == nil {
		users, err := parseUsers(node.Get("secrets"))
		if err != nil {
			return nil, err
		}
		if len(users) > 0 {
			node.User = users[0]
		}
	}

	serverName, sport, _ := net.SplitHostPort(node.Addr)
	if serverName == "" {
		serverName = "localhost" // default server name
	}

	rootCAs, err := loadCA(node.Get("ca"))
	if err != nil {
		return
	}
	tlsCfg := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: !node.GetBool("secure"),
		RootCAs:            rootCAs,
	}

	// If the argument `ca` is given, but not open `secure`, we verify the
	// certificate manually.
	if rootCAs != nil && !node.GetBool("secure") {
		tlsCfg.VerifyConnection = func(state tls.ConnectionState) error {
			opts := x509.VerifyOptions{
				Roots:         rootCAs,
				CurrentTime:   time.Now(),
				DNSName:       "",
				Intermediates: x509.NewCertPool(),
			}

			certs := state.PeerCertificates
			for i, cert := range certs {
				if i == 0 {
					continue
				}
				opts.Intermediates.AddCert(cert)
			}

			_, err = certs[0].Verify(opts)
			return err
		}
	}

	if cert, err := tls.LoadX509KeyPair(node.Get("cert"), node.Get("key")); err == nil {
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	timeout := node.GetDuration("timeout")
	tr := TCPTransporter()

	var connector Connector
	switch node.Protocol {
	case "socks", "socks5":
		connector = SOCKS5Connector(node.User)
	case "http":
		connector = HTTPConnector(node.User)
	default:
		connector = AutoConnector(node.User)
	}

	host := node.Get("host")
	if host == "" {
		host = node.Host
	}

	node.DialOptions = append(node.DialOptions,
		TimeoutDialOption(timeout),
		HostDialOption(host),
	)

	node.ConnectOptions = []ConnectOption{
		UserAgentConnectOption(node.Get("agent")),
		NoTLSConnectOption(node.GetBool("notls")),
		NoDelayConnectOption(node.GetBool("nodelay")),
	}

	handshakeOptions := []HandshakeOption{
		AddrHandshakeOption(node.Addr),
		HostHandshakeOption(host),
		UserHandshakeOption(node.User),
		TLSConfigHandshakeOption(tlsCfg),
		IntervalHandshakeOption(node.GetDuration("ping")),
		TimeoutHandshakeOption(timeout),
		RetryHandshakeOption(node.GetInt("retry")),
	}

	node.Client = &Client{
		Connector:   connector,
		Transporter: tr,
	}

	node.Bypass = parseBypass(node.Get("bypass"))

	ips := parseIP(node.Get("ip"), sport)
	for _, ip := range ips {
		nd := node.Clone()
		nd.Addr = ip
		// override the default node address
		nd.HandshakeOptions = append(handshakeOptions, AddrHandshakeOption(ip))
		// One node per IP
		nodes = append(nodes, nd)
	}
	if len(ips) == 0 {
		node.HandshakeOptions = handshakeOptions
		nodes = []Node{node}
	}

	return
}

func (r *route) GenRouters() ([]router, error) {
	chain, err := r.parseChain()
	if err != nil {
		return nil, err
	}

	var rts []router

	for _, ns := range r.ServeNodes {
		node, err := ParseNode(ns)
		if err != nil {
			return nil, err
		}

		if auth := node.Get("auth"); auth != "" && node.User == nil {
			c, err := base64.StdEncoding.DecodeString(auth)
			if err != nil {
				return nil, err
			}
			cs := string(c)
			s := strings.IndexByte(cs, ':')
			if s < 0 {
				node.User = url.User(cs)
			} else {
				node.User = url.UserPassword(cs[:s], cs[s+1:])
			}
		}
		authenticator, err := parseAuthenticator(node.Get("secrets"))
		if err != nil {
			return nil, err
		}
		if authenticator == nil && node.User != nil {
			kvs := make(map[string]string)
			kvs[node.User.Username()], _ = node.User.Password()
			authenticator = NewLocalAuthenticator(kvs)
		}
		if node.User == nil {
			if users, _ := parseUsers(node.Get("secrets")); len(users) > 0 {
				node.User = users[0]
			}
		}
		certFile, keyFile := node.Get("cert"), node.Get("key")
		tlsCfg, err := tlsConfig(certFile, keyFile, node.Get("ca"))
		if err != nil && certFile != "" && keyFile != "" {
			return nil, err
		}

		ttl := node.GetDuration("ttl")
		timeout := node.GetDuration("timeout")
		var ln Listener
		ln, err = TCPListener(node.Addr)
		if err != nil {
			return nil, err
		}

		var handler Handler
		switch node.Protocol {
		case "socks", "socks5":
			handler = SOCKS5Handler()
		case "http":
			handler = HTTPHandler()
		default:
			// start from 2.5, if remote is not empty, then we assume that it is a forward tunnel.
			if node.Remote != "" {
				handler = TCPDirectForwardHandler(node.Remote)
			} else {
				handler = AutoHandler()
			}
		}

		var whitelist, blacklist *Permissions
		if node.Values.Get("whitelist") != "" {
			if whitelist, err = ParsePermissions(node.Get("whitelist")); err != nil {
				return nil, err
			}
		}
		if node.Values.Get("blacklist") != "" {
			if blacklist, err = ParsePermissions(node.Get("blacklist")); err != nil {
				return nil, err
			}
		}

		node.Bypass = parseBypass(node.Get("bypass"))
		hosts := parseHosts(node.Get("hosts"))
		ips := parseIP(node.Get("ip"), "")

		resolver := parseResolver(node.Get("dns"))
		if resolver != nil {
			resolver.Init(
				ChainResolverOption(chain),
				TimeoutResolverOption(timeout),
				TTLResolverOption(ttl),
				PreferResolverOption(node.Get("prefer")),
				SrcIPResolverOption(net.ParseIP(node.Get("ip"))),
			)
		}

		handler.Init(
			AddrHandlerOption(ln.Addr().String()),
			ChainHandlerOption(chain),
			UsersHandlerOption(node.User),
			AuthenticatorHandlerOption(authenticator),
			TLSConfigHandlerOption(tlsCfg),
			WhitelistHandlerOption(whitelist),
			BlacklistHandlerOption(blacklist),
			StrategyHandlerOption(NewStrategy(node.Get("strategy"))),
			MaxFailsHandlerOption(node.GetInt("max_fails")),
			FailTimeoutHandlerOption(node.GetDuration("fail_timeout")),
			BypassHandlerOption(node.Bypass),
			ResolverHandlerOption(resolver),
			HostsHandlerOption(hosts),
			RetryHandlerOption(node.GetInt("retry")), // override the global retry option.
			TimeoutHandlerOption(timeout),
			ProbeResistHandlerOption(node.Get("probe_resist")),
			KnockingHandlerOption(node.Get("knock")),
			NodeHandlerOption(node),
			IPsHandlerOption(ips),
			TCPModeHandlerOption(node.GetBool("tcp")),
		)

		rt := router{
			node:     node,
			server:   &Server{Listener: ln},
			handler:  handler,
			chain:    chain,
			resolver: resolver,
			hosts:    hosts,
		}
		rts = append(rts, rt)
	}

	return rts, nil
}

type router struct {
	node     Node
	server   *Server
	handler  Handler
	chain    *Chain
	resolver Resolver
	hosts    *Hosts
}

func (r *router) Serve() error {
	log.Logf("%s on %s", r.node.String(), r.server.Addr())
	return r.server.Serve(r.handler)
}

func (r *router) Close() error {
	if r == nil || r.server == nil {
		return nil
	}
	return r.server.Close()
}
