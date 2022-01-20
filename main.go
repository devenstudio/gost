package main

import (
	"crypto/tls"
	"errors"
	"os"

	_ "net/http/pprof"

	"github.com/go-log/log"
)

var (
	baseCfg   = &baseConfig{}
	pprofAddr string
)

func init() {
	SetLogger(&LogLogger{})

	baseCfg.route.ChainNodes = []string{"socks5://172.30.10.2:1080?bypass=*.cr.toyota.co.jp,central.arene.com,*.central.arene.com,*.tmc-stargate.com,*.tri-ad.tech,13.112.201.48", "http://172.30.50.10:8080?bypass=*.dndev.net,rc.dnjpchat.net,54.249.48.64,54.65.160.38,13.114.198.232"}
	baseCfg.route.ServeNodes = []string{":1080"}
}

func main() {
	// NOTE: as of 2.6, you can use custom cert/key files to initialize the default certificate.
	tlsConfig, err := tlsConfig(defaultCertFile, defaultKeyFile, "")
	if err != nil {
		// generate random self-signed certificate.
		cert, err := GenCertificate()
		if err != nil {
			log.Log(err)
			os.Exit(1)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
	} else {
		log.Log("load TLS certificate files OK")
	}

	DefaultTLSConfig = tlsConfig

	routers, err := baseCfg.route.GenRouters()
	if err != nil {
		log.Log(err)
		os.Exit(1)
	}
	if len(routers) == 0 {
		log.Log(errors.New("invalid config"))
		os.Exit(1)
	}
	for i := range routers {
		go routers[i].Serve()
	}

	select {}
}
