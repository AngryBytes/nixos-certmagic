package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"os"
	osuser "os/user"
	"strconv"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
)

type Cfg struct {
	PreliminarySelfsigned bool
	AcceptTerms           bool
	WaitForListeners      []string
	Defaults              *DefaultsCfg
	Certs                 map[string]*CertCfg
}

type DefaultsCfg struct {
	Server string
	Email  string
}

type CertCfg struct {
	Domain string
	Group  string
}

var log *zap.Logger

func main() {
	if len(os.Args) != 2 {
		fmt.Println("usage: nixos-certmagic <config.json>")
		os.Exit(64)
	}

	var err error
	logCfg := zap.NewProductionConfig()
	logCfg.Encoding = "console"
	log, err = logCfg.Build()
	if err != nil {
		fmt.Printf("Logger init failed: %v\n", err)
		os.Exit(1)
	}

	cfgJson, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal("failed to read config file", zap.Error(err))
	}

	var cfg Cfg
	if err := json.Unmarshal(cfgJson, &cfg); err != nil {
		log.Fatal("failed to parse config JSON", zap.Error(err))
	}

	// Socket activation for the HTTP challenge server.
	var srv net.Listener
	if srvFile := os.NewFile(3, "http socket"); srvFile == nil {
		log.Fatal("socket activation failed: missing socket")
	} else {
		srv, err = net.FileListener(srvFile)
		srvFile.Close()
		if err != nil {
			log.Fatal("socket activation failed", zap.Error(err))
		}
	}

	ctx := context.Background()

	certmagic.DefaultACME.CA = cfg.Defaults.Server
	certmagic.DefaultACME.Email = cfg.Defaults.Email
	certmagic.DefaultACME.Agreed = cfg.AcceptTerms
	certmagic.DefaultACME.DisableTLSALPNChallenge = true

	// TODO: This prevents an error. We prefer the unix socket, because it is
	// always available, but can't disable the builtin listener.
	certmagic.DefaultACME.ListenHost = "localhost"
	certmagic.DefaultACME.AltHTTPPort = 61333

	// TODO: Maybe introduce a setting for TestCA.
	switch certmagic.DefaultACME.CA {
	case certmagic.LetsEncryptProductionCA:
		certmagic.DefaultACME.TestCA = certmagic.LetsEncryptStagingCA
	case certmagic.GoogleTrustProductionCA:
		certmagic.DefaultACME.TestCA = certmagic.GoogleTrustStagingCA
	default:
		certmagic.DefaultACME.TestCA = ""
	}

	var storage certmagic.Storage
	if dsnFile := os.Getenv("CERTMAGIC_MYSQL_DSN_FILE"); dsnFile != "" {
		dsn, err := os.ReadFile(dsnFile)
		if err != nil {
			log.Fatal("could not read mysql dsn", zap.Error(err))
		}
		storage, err = NewMysqlStorage(ctx, string(dsn))
		if err != nil {
			log.Fatal("could not initialize mysql storage", zap.Error(err))
		}
	}
	if storage == nil {
		storage = &certmagic.FileStorage{Path: ".certmagic"}
	}

	// Create self-signed certs if requested.
	if cfg.PreliminarySelfsigned {
		for _, cert := range cfg.Certs {
			generateSelfSignedIfNecessary(cert)
		}
	}

	// Real webserver may now start.
	if sockPath := os.Getenv("NOTIFY_SOCKET"); sockPath != "" {
		addr := &net.UnixAddr{Net: "unixgram", Name: sockPath}
		sock, err := net.DialUnix(addr.Net, nil, addr)
		if err != nil {
			log.Error("failed to open systemd notify socket", zap.Error(err))
		} else {
			_, err := sock.Write([]byte("READY=1"))
			sock.Close()
			if err != nil {
				log.Error("failed to notify systemd", zap.Error(err))
			}
		}
	}

	// Wait for the webserver to start.
	for _, addr := range cfg.WaitForListeners {
		var notify uint8
		var lastErr string
		for {
			conn, err := net.Dial("tcp", addr)
			if err == nil {
				conn.Close()
				break
			}

			errMsg := err.Error()
			if errMsg != lastErr {
				lastErr = errMsg
				notify = 3
			}
			if notify > 0 {
				notify -= 1
				if notify == 0 {
					log.Info("waiting for listener", zap.String("address", addr), zap.Error(err))
				}
			}

			time.Sleep(2 * time.Second)
		}
	}

	// Start certmagic.
	var magic *certmagic.Config
	certObtained := make(chan bool)
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(c certmagic.Certificate) (*certmagic.Config, error) {
			return magic, nil
		},
		Logger: log,
	})
	magic = certmagic.New(cache, certmagic.Config{
		OnEvent: func(ctx context.Context, event string, data map[string]any) error {
			if event == "cert_obtained" {
				certObtained <- true
			}
			return nil
		},
		Storage: storage,
		Logger:  log,
	})

	var domains []string
	for _, cert := range cfg.Certs {
		domains = append(domains, cert.Domain)
	}
	if err := magic.ManageAsync(ctx, domains); err != nil {
		log.Fatal("failed to initialize certmagic", zap.Error(err))
	}

	// Perform initial update of certs on disk.
	var lastUpdate time.Time
	lastUpdate = updateCerts(&cfg, cache, lastUpdate)

	// Start our HTTP challenge server.
	acme, ok := magic.Issuers[0].(*certmagic.ACMEIssuer)
	if !ok {
		log.Fatal("could not find certmagic acme issuer")
	}
	go func() {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !acme.HandleHTTPChallenge(w, r) {
				w.WriteHeader(400)
			}
		})
		log.Fatal("http server error", zap.Error(http.Serve(srv, handler)))
	}()

	// We don't really have a way to hook into certmagic's (local) updates.
	// The events it provides don't necessarily inform us about renews on other
	// nodes, which result in certmagic silently updating cache.
	//
	// So instead, we have a relatively tight loop with a relatively quick
	// check, where we detect updates based on NotBefore moving forward.
	updateTicker := time.NewTicker(10 * time.Second)
	for {
		select {
		case <-certObtained:
			lastUpdate = updateCerts(&cfg, cache, lastUpdate)
		case <-updateTicker.C:
			lastUpdate = updateCerts(&cfg, cache, lastUpdate)
		}
	}
}

// updateCerts writes certificates to disk that have changed.
// Changes are detected based on NotBefore moving forward.
func updateCerts(cfg *Cfg, cache *certmagic.Cache, lastUpdate time.Time) time.Time {
	nextUpdate := lastUpdate
	for _, cert := range cfg.Certs {
		matched := cache.AllMatchingCertificates(cert.Domain)
		if len(matched) > 0 {
			tlsCert := matched[0].Certificate
			notBefore := tlsCert.Leaf.NotBefore
			if notBefore.After(lastUpdate) {
				writeCert(cert, tlsCert.PrivateKey, tlsCert.Certificate)
				if notBefore.After(nextUpdate) {
					nextUpdate = notBefore
				}
			}
		}
	}
	return nextUpdate
}

// writeCert writes a private key and certificate to disk in the expected
// format, then swaps directories atomically.
func writeCert(cert *CertCfg, key crypto.PrivateKey, certsDer [][]byte) {
	keyPem, err := certmagic.PEMEncodePrivateKey(key)
	if err != nil {
		log.Error("could not encode private key", zap.String("domain", cert.Domain), zap.Error(err))
	}

	var chain [][]byte
	var fullchain []byte
	for _, certDer := range certsDer {
		certPem := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDer,
		})
		chain = append(chain, certPem)
		fullchain = append(fullchain, certPem...)
	}

	newdir := fmt.Sprintf(".new_%s", cert.Domain)
	if err := os.Mkdir(newdir, 0700); err != nil {
		log.Error("could not create directory", zap.String("path", newdir), zap.Error(err))
		return
	}
	defer os.RemoveAll(newdir)

	// TODO: Maybe also create full.pem?
	keyPath := fmt.Sprintf("%s/key.pem", newdir)
	chainPath := fmt.Sprintf("%s/chain.pem", newdir)
	fullchainPath := fmt.Sprintf("%s/fullchain.pem", newdir)
	if err := os.WriteFile(keyPath, keyPem, 0640); err != nil {
		log.Error("could not write key", zap.String("path", keyPath), zap.Error(err))
		return
	}
	if err := os.WriteFile(chainPath, chain[0], 0640); err != nil {
		log.Error("could not write chain", zap.String("path", chainPath), zap.Error(err))
		return
	}
	if err := os.WriteFile(fullchainPath, fullchain, 0640); err != nil {
		log.Error("could not write fullchain", zap.String("path", fullchainPath), zap.Error(err))
		return
	}

	group, err := osuser.LookupGroup(cert.Group)
	if err != nil {
		log.Error("could not resolve group", zap.String("name", cert.Group), zap.Error(err))
		return
	}

	uid := os.Getuid()
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		log.Error("could not parse gid", zap.String("gid", group.Gid), zap.Error(err))
		return
	}

	if err := os.Chown(keyPath, uid, gid); err != nil {
		log.Error("could not chown key", zap.String("path", keyPath), zap.Error(err))
		return
	}
	if err := os.Chown(chainPath, uid, gid); err != nil {
		log.Error("could not chown chain", zap.String("path", chainPath), zap.Error(err))
		return
	}
	if err := os.Chown(fullchainPath, uid, gid); err != nil {
		log.Error("could not chown fullchain", zap.String("path", fullchainPath), zap.Error(err))
		return
	}
	if err := os.Chown(newdir, uid, gid); err != nil {
		log.Error("could not chown directory", zap.String("path", newdir), zap.Error(err))
		return
	}

	certPath := fmt.Sprintf("%s/cert.pem", newdir)
	if err := os.Symlink("chain.pem", certPath); err != nil {
		log.Error("could not link cert", zap.String("path", certPath), zap.Error(err))
	}

	if err := os.Chmod(newdir, 0750); err != nil {
		log.Error("could not chmod directory", zap.String("path", newdir), zap.Error(err))
		return
	}

	// Atomic swap of directories.
	olddir := fmt.Sprintf(".old_%s", cert.Domain)
	if err := os.Rename(cert.Domain, olddir); err != nil && !errors.Is(err, fs.ErrNotExist) {
		log.Error("could not swap out old cert", zap.String("domain", cert.Domain), zap.Error(err))
		return
	}
	defer os.RemoveAll(olddir)

	if err := os.Rename(newdir, cert.Domain); err != nil {
		log.Error("could not swap in new cert", zap.String("domain", cert.Domain), zap.Error(err))
		// Try to undo.
		os.Rename(olddir, cert.Domain)
	}
}

// generateSelfSignedIfNecessary generates a self-signed certificate for a
// domain if no private key is present on disk. This allows webservers to start
// that require presence of certificates.
func generateSelfSignedIfNecessary(cert *CertCfg) {
	rand := cryptorand.Reader

	keyPath := fmt.Sprintf("%s/key.pem", cert.Domain)
	_, err := os.Stat(keyPath)
	if err == nil {
		return
	}
	if !errors.Is(err, fs.ErrNotExist) {
		log.Fatal("could not stat key", zap.String("path", keyPath), zap.Error(err))
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand)
	if err != nil {
		log.Fatal("could not generate temporary key", zap.Error(err))
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		DNSNames:              []string{cert.Domain},
		Subject:               pkix.Name{CommonName: cert.Domain},
		NotBefore:             now,
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certDer, err := x509.CreateCertificate(rand, &template, &template, key.Public(), key)
	if err != nil {
		log.Fatal("could not create temporary certificate", zap.Error(err))
	}

	writeCert(cert, key, [][]byte{certDer})
}
