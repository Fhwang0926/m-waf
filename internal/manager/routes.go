package manager

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/fs"
	"net/http"
	"os"

	"github.com/Fhwang0926/m-waf/internal/protocol"
	webassets "github.com/Fhwang0926/m-waf/web"
)

// Handler exposes the administrator UI and the Agent-initiated control API on
// one HTTPS listener. Agent routes still require an authenticated client
// certificate after enrollment.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	staticFS, _ := fs.Sub(webassets.Assets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(staticFS)))
	mux.HandleFunc(protocol.HealthLivePattern, s.live)
	mux.HandleFunc(protocol.HealthReadyPattern, s.ready)
	s.registerAdminRoutes(mux)
	s.registerAdminAPIRoutes(mux)
	s.registerAgentRoutes(mux)
	return s.securityHeaders(s.requestLog(mux))
}

// TLSConfig accepts a verified Agent certificate when one is provided. The
// route-level Agent middleware requires it for every authenticated Agent path;
// administrator browsers continue to use the same listener without one.
func (s *Server) TLSConfig() (*tls.Config, error) {
	certPEM, err := os.ReadFile(s.cfg.AgentCACertificate)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		return nil, errors.New("append agent CA certificate")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs:  pool,
		NextProtos: []string{"h2", "http/1.1"},
	}, nil
}
