package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultBaseDir = "/var/lib/emudhra-lab"
	defaultCADir   = "/opt/emudhra-lab/ca"
	defaultAssets  = "/opt/emudhra-lab/assets"
	maxUploadSize  = 32 << 20
)

type caDefinition struct {
	ID       string
	Name     string
	Purpose  string
	Kind     string
	CertFile string
	KeyFile  string
}

var caCatalog = []caDefinition{
	{ID: "4", Name: "EM OV TLS CA - G3C", Purpose: "OV TLS", Kind: "tls", CertFile: "em-ov-tls-g3c.pem", KeyFile: "em-ov-tls-g3c.key"},
	{ID: "56", Name: "EM EV TLS CA - G3C", Purpose: "EV TLS", Kind: "tls", CertFile: "em-ev-tls-g3c.pem", KeyFile: "em-ev-tls-g3c.key"},
	{ID: "66", Name: "EM OV CS CA - G3B", Purpose: "Code signing", Kind: "codesign", CertFile: "em-ov-cs-g3b.pem", KeyFile: "em-ov-cs-g3b.key"},
	{ID: "115", Name: "EM EV TLS CA - G3B", Purpose: "EV TLS", Kind: "tls", CertFile: "em-ev-tls-g3b.pem", KeyFile: "em-ev-tls-g3b.key"},
	{ID: "155", Name: "EM OV TLS CA - G3B", Purpose: "OV TLS", Kind: "tls", CertFile: "em-ov-tls-g3b.pem", KeyFile: "em-ov-tls-g3b.key"},
	{ID: "156", Name: "EM DV TLS CA - G3B", Purpose: "DV TLS", Kind: "tls", CertFile: "em-dv-tls-g3b.pem", KeyFile: "em-dv-tls-g3b.key"},
	{ID: "230", Name: "EM DV TLS CA - G3C", Purpose: "DV TLS", Kind: "tls", CertFile: "em-dv-tls-g3c.pem", KeyFile: "em-dv-tls-g3c.key"},
	{ID: "237", Name: "EM OV CS CA - G3C", Purpose: "Code signing", Kind: "codesign", CertFile: "em-ov-cs-g3c.pem", KeyFile: "em-ov-cs-g3c.key"},
}

type brandDefinition struct {
	Domain string
	Name   string
	Class  string
}

var presetDomains = map[string]brandDefinition{
	"google.com":    {Domain: "google.com", Name: "Google", Class: "google"},
	"microsoft.com": {Domain: "microsoft.com", Name: "Microsoft", Class: "microsoft"},
	"github.com":    {Domain: "github.com", Name: "GitHub", Class: "github"},
}

var domainPattern = regexp.MustCompile(`(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

type generatedCertificate struct {
	Domain      string    `json:"domain"`
	CAID        string    `json:"ca_id"`
	CAName      string    `json:"ca_name"`
	GeneratedAt time.Time `json:"generated_at"`
}

type labState struct {
	Generated map[string]generatedCertificate `json:"generated"`
}

type server struct {
	baseDir     string
	caDir       string
	assetsDir   string
	builtinPath string
	stateMu     sync.Mutex
	dashboard   *template.Template
}

type dashboardData struct {
	CAs         []caDefinition
	TLSCAs      []caDefinition
	CodeSignCAs []caDefinition
	Generated   []generatedCertificate
	Notice      string
	Error       string
}

func main() {
	listen := flag.String("listen", ":8080", "HTTP listen address")
	baseDir := flag.String("base-dir", envOrDefault("EMUDHRA_LAB_DIR", defaultBaseDir), "mutable lab data directory")
	caDir := flag.String("ca-dir", envOrDefault("EMUDHRA_LAB_CA_DIR", defaultCADir), "compromised CA directory")
	assetsDir := flag.String("assets-dir", envOrDefault("EMUDHRA_LAB_ASSETS_DIR", defaultAssets), "static assets directory")
	bootstrap := flag.Bool("bootstrap", false, "create initial multi-domain fallback certificate")
	flag.Parse()

	s := &server{
		baseDir:     *baseDir,
		caDir:       *caDir,
		assetsDir:   *assetsDir,
		builtinPath: filepath.Join(*assetsDir, "msgbox.exe"),
		dashboard:   template.Must(template.New("dashboard").Parse(dashboardHTML)),
	}
	if *bootstrap {
		if err := s.bootstrapCertificates(); err != nil {
			log.Fatal(err)
		}
		log.Printf("bootstrap certificates are ready under %s", filepath.Join(s.baseDir, "certs"))
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/assets/pwned.png", s.handlePwned)
	mux.HandleFunc("/generate", s.handleGenerate)
	mux.HandleFunc("/sign", s.handleSign)
	mux.HandleFunc("/download/", s.handleCertificateDownload)
	mux.HandleFunc("/", s.handleByHostname)

	httpServer := &http.Server{
		Addr:              *listen,
		Handler:           requestLogMiddleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       35 * time.Second,
		WriteTimeout:      35 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	log.Printf("eMudhra lab server listening on %s", *listen)
	log.Fatal(httpServer.ListenAndServe())
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func requestLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s host=%q remote=%q duration=%s", r.Method, r.URL.Path, r.Host, r.RemoteAddr, time.Since(started).Round(time.Millisecond))
	})
}

func (s *server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok\n")
}

func (s *server) handlePwned(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=3600")
	http.ServeFile(w, r, filepath.Join(s.assetsDir, "pwned.png"))
}

func (s *server) handleByHostname(w http.ResponseWriter, r *http.Request) {
	host := canonicalHost(r.Host)
	if host == "emudhra.fail" {
		s.handleDashboard(w, r)
		return
	}
	brand, ok := presetDomains[host]
	if !ok {
		http.Error(w, "This hostname is not configured in the eMudhra compromise lab.", http.StatusMisdirectedRequest)
		return
	}

	state, err := s.readState()
	if err != nil {
		http.Error(w, "Unable to read lab state.", http.StatusInternalServerError)
		return
	}
	if _, ok := state.Generated[host]; !ok {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Refresh", "3; url=https://emudhra.fail/")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, redirectHTML)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, spoofPage(brand))
}

func canonicalHost(hostport string) string {
	host := strings.ToLower(strings.TrimSpace(hostport))
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}
	return strings.TrimSuffix(host, ".")
}

func (s *server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	state, err := s.readState()
	if err != nil {
		http.Error(w, "Unable to read lab state.", http.StatusInternalServerError)
		return
	}
	generated := make([]generatedCertificate, 0, len(state.Generated))
	for _, record := range state.Generated {
		generated = append(generated, record)
	}
	sort.Slice(generated, func(i, j int) bool { return generated[i].Domain < generated[j].Domain })

	data := dashboardData{
		CAs:         append([]caDefinition(nil), caCatalog...),
		TLSCAs:      filterCAs("tls"),
		CodeSignCAs: filterCAs("codesign"),
		Generated:   generated,
		Notice:      r.URL.Query().Get("notice"),
		Error:       r.URL.Query().Get("error"),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := s.dashboard.Execute(w, data); err != nil {
		log.Printf("render dashboard: %v", err)
	}
}

func filterCAs(kind string) []caDefinition {
	var result []caDefinition
	for _, ca := range caCatalog {
		if ca.Kind == kind {
			result = append(result, ca)
		}
	}
	return result
}

func lookupCA(id, kind string) (caDefinition, error) {
	for _, ca := range caCatalog {
		if ca.ID == id && ca.Kind == kind {
			return ca, nil
		}
	}
	return caDefinition{}, fmt.Errorf("certificate authority %q is not available for %s", id, kind)
}

func normalizeDomain(value string) (string, error) {
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if len(domain) > 253 || !domainPattern.MatchString(domain) {
		return "", errors.New("enter an ASCII DNS hostname such as google.com")
	}
	return domain, nil
}

func (s *server) handleGenerate(w http.ResponseWriter, r *http.Request) {
	if canonicalHost(r.Host) != "emudhra.fail" {
		http.Error(w, "certificate generation is available only on emudhra.fail", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		s.redirectDashboard(w, r, "", "invalid certificate request")
		return
	}
	domain, err := normalizeDomain(r.FormValue("domain"))
	if err != nil {
		s.redirectDashboard(w, r, "", err.Error())
		return
	}
	ca, err := lookupCA(r.FormValue("ca_id"), "tls")
	if err != nil {
		s.redirectDashboard(w, r, "", err.Error())
		return
	}

	s.stateMu.Lock()
	err = s.generateTLSCertificate(domain, []string{domain}, ca, filepath.Join(s.baseDir, "certs", domain))
	if err == nil {
		var state labState
		state, err = s.readStateUnlocked()
		if err == nil {
			state.Generated[domain] = generatedCertificate{Domain: domain, CAID: ca.ID, CAName: ca.Name, GeneratedAt: time.Now().UTC()}
			err = s.writeStateUnlocked(state)
		}
	}
	s.stateMu.Unlock()
	if err != nil {
		log.Printf("generate certificate for %s: %v", domain, err)
		s.redirectDashboard(w, r, "", "certificate generation failed: "+err.Error())
		return
	}

	if _, served := presetDomains[domain]; served {
		if output, reloadErr := exec.Command("sudo", "/usr/bin/systemctl", "reload", "nginx").CombinedOutput(); reloadErr != nil {
			log.Printf("reload nginx: %v: %s", reloadErr, strings.TrimSpace(string(output)))
			s.redirectDashboard(w, r, "", "certificate generated, but nginx reload failed")
			return
		}
	}
	s.redirectDashboard(w, r, fmt.Sprintf("Generated %s using %s.", domain, ca.Name), "")
}

func (s *server) redirectDashboard(w http.ResponseWriter, r *http.Request, notice, message string) {
	query := ""
	if notice != "" {
		query = "?notice=" + urlQueryEscape(notice)
	} else if message != "" {
		query = "?error=" + urlQueryEscape(message)
	}
	http.Redirect(w, r, "https://emudhra.fail/"+query, http.StatusSeeOther)
}

func urlQueryEscape(value string) string {
	replacer := strings.NewReplacer("%", "%25", " ", "%20", "!", "%21", "\"", "%22", "#", "%23", "&", "%26", "+", "%2B", "?", "%3F", "=", "%3D")
	return replacer.Replace(value)
}

func (s *server) bootstrapCertificates() error {
	if err := os.MkdirAll(filepath.Join(s.baseDir, "certs"), 0750); err != nil {
		return err
	}
	ca, err := lookupCA("4", "tls")
	if err != nil {
		return err
	}
	bootstrapDir := filepath.Join(s.baseDir, "certs", ".bootstrap")
	if _, err := os.Stat(filepath.Join(bootstrapDir, "fullchain.pem")); errors.Is(err, os.ErrNotExist) {
		sans := []string{"emudhra.fail", "google.com", "microsoft.com", "github.com"}
		if err := s.generateTLSCertificate("emudhra.fail", sans, ca, bootstrapDir); err != nil {
			return fmt.Errorf("generate bootstrap certificate: %w", err)
		}
	} else if err != nil {
		return err
	}
	for _, domain := range []string{"emudhra.fail", "google.com", "microsoft.com", "github.com"} {
		destination := filepath.Join(s.baseDir, "certs", domain)
		if err := os.MkdirAll(destination, 0750); err != nil {
			return err
		}
		for _, filename := range []string{"cert.pem", "fullchain.pem", "privkey.pem"} {
			target := filepath.Join(destination, filename)
			if _, err := os.Stat(target); err == nil {
				continue
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
			mode := os.FileMode(0644)
			if filename == "privkey.pem" {
				mode = 0600
			}
			if err := copyFile(filepath.Join(bootstrapDir, filename), target, mode); err != nil {
				return err
			}
		}
	}
	statePath := filepath.Join(s.baseDir, "state.json")
	if _, err := os.Stat(statePath); errors.Is(err, os.ErrNotExist) {
		return s.writeStateUnlocked(newLabState())
	} else if err != nil {
		return err
	}
	return nil
}

func (s *server) generateTLSCertificate(domain string, sans []string, ca caDefinition, outputDir string) error {
	caCert, caKey, caPEM, err := s.loadCA(ca)
	if err != nil {
		return err
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	notAfter := now.Add(180 * 24 * time.Hour)
	if caCert.NotAfter.Before(notAfter) {
		notAfter = caCert.NotAfter.Add(-time.Hour)
	}
	if !notAfter.After(now) {
		return fmt.Errorf("issuer certificate expired at %s", caCert.NotAfter.Format(time.RFC3339))
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         domain,
			Organization:       []string{"Ludus eMudhra Compromise Lab"},
			OrganizationalUnit: []string{"Visit ludus.cloud to learn more"},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              notAfter,
		DNSNames:              sans,
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		AuthorityKeyId:        caCert.SubjectKeyId,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER := x509.MarshalPKCS1PrivateKey(leafKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER})
	if err := os.MkdirAll(outputDir, 0750); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(outputDir, "cert.pem"), certPEM, 0644); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(outputDir, "fullchain.pem"), append(append([]byte(nil), certPEM...), caPEM...), 0644); err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(outputDir, "privkey.pem"), keyPEM, 0600)
}

func (s *server) loadCA(ca caDefinition) (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	certPEM, err := os.ReadFile(filepath.Join(s.caDir, ca.CertFile))
	if err != nil {
		return nil, nil, nil, err
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, nil, nil, fmt.Errorf("%s does not contain a certificate", ca.CertFile)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(s.caDir, ca.KeyFile))
	if err != nil {
		return nil, nil, nil, err
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, nil, fmt.Errorf("%s does not contain a private key", ca.KeyFile)
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, nil, err
	}
	publicKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.X.Cmp(key.PublicKey.X) != 0 || publicKey.Y.Cmp(key.PublicKey.Y) != 0 {
		return nil, nil, nil, fmt.Errorf("private key does not match %s", ca.Name)
	}
	return cert, key, certPEM, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	if serial.Sign() == 0 {
		return big.NewInt(1), nil
	}
	return serial, nil
}

func writeFileAtomic(path string, contents []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, path)
}

func copyFile(source, destination string, mode os.FileMode) error {
	contents, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	return writeFileAtomic(destination, contents, mode)
}

func newLabState() labState {
	return labState{Generated: make(map[string]generatedCertificate)}
}

func (s *server) readState() (labState, error) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.readStateUnlocked()
}

func (s *server) readStateUnlocked() (labState, error) {
	contents, err := os.ReadFile(filepath.Join(s.baseDir, "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return newLabState(), nil
	}
	if err != nil {
		return labState{}, err
	}
	state := newLabState()
	if err := json.Unmarshal(contents, &state); err != nil {
		return labState{}, err
	}
	if state.Generated == nil {
		state.Generated = make(map[string]generatedCertificate)
	}
	return state, nil
}

func (s *server) writeStateUnlocked(state labState) error {
	contents, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	contents = append(contents, '\n')
	return writeFileAtomic(filepath.Join(s.baseDir, "state.json"), contents, 0640)
}

func (s *server) handleCertificateDownload(w http.ResponseWriter, r *http.Request) {
	if canonicalHost(r.Host) != "emudhra.fail" {
		http.Error(w, "downloads are available only on emudhra.fail", http.StatusForbidden)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/download/"), "/")
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	domain, err := normalizeDomain(parts[0])
	if err != nil {
		http.NotFound(w, r)
		return
	}
	filename := parts[1]
	if filename != "cert.pem" && filename != "fullchain.pem" && filename != "privkey.pem" {
		http.NotFound(w, r)
		return
	}
	state, err := s.readState()
	if err != nil {
		http.Error(w, "Unable to read lab state.", http.StatusInternalServerError)
		return
	}
	if _, ok := state.Generated[domain]; !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", domain+"-"+filename))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeFile(w, r, filepath.Join(s.baseDir, "certs", domain, filename))
}

func (s *server) handleSign(w http.ResponseWriter, r *http.Request) {
	if canonicalHost(r.Host) != "emudhra.fail" {
		http.Error(w, "code signing is available only on emudhra.fail", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		s.redirectDashboard(w, r, "", "upload is invalid or exceeds 32 MiB")
		return
	}
	ca, err := lookupCA(r.FormValue("ca_id"), "codesign")
	if err != nil {
		s.redirectDashboard(w, r, "", err.Error())
		return
	}

	artifactID, err := randomID()
	if err != nil {
		s.redirectDashboard(w, r, "", "unable to create artifact ID")
		return
	}
	artifactDir := filepath.Join(s.baseDir, "artifacts", artifactID)
	if err := os.MkdirAll(artifactDir, 0750); err != nil {
		s.redirectDashboard(w, r, "", "unable to create artifact directory")
		return
	}

	inputPath, originalName, err := s.saveSigningInput(r, artifactDir)
	if err != nil {
		s.redirectDashboard(w, r, "", err.Error())
		return
	}
	identityDir := filepath.Join(s.baseDir, "signers", ca.ID)
	if err := s.ensureCodeSigningIdentity(ca, identityDir); err != nil {
		log.Printf("create code-signing identity: %v", err)
		s.redirectDashboard(w, r, "", "unable to create code-signing identity")
		return
	}
	outputName := "signed-" + originalName
	outputPath := filepath.Join(artifactDir, outputName)
	command := exec.Command(
		"/usr/bin/osslsigncode", "sign",
		"-certs", filepath.Join(identityDir, "fullchain.pem"),
		"-key", filepath.Join(identityDir, "privkey.pem"),
		"-n", "eMudhra Compromise Lab",
		"-i", "https://emudhra.fail/",
		"-h", "sha256",
		"-in", inputPath,
		"-out", outputPath,
	)
	if output, signErr := command.CombinedOutput(); signErr != nil {
		log.Printf("osslsigncode: %v: %s", signErr, strings.TrimSpace(string(output)))
		s.redirectDashboard(w, r, "", "Authenticode signing failed")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", outputName))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeFile(w, r, outputPath)
}

func randomID() (string, error) {
	contents := make([]byte, 16)
	if _, err := rand.Read(contents); err != nil {
		return "", err
	}
	return hex.EncodeToString(contents), nil
}

func (s *server) saveSigningInput(r *http.Request, artifactDir string) (string, string, error) {
	if r.FormValue("source") == "builtin" {
		name := "weak-keys-msgbox.exe"
		target := filepath.Join(artifactDir, name)
		if err := copyFile(s.builtinPath, target, 0640); err != nil {
			return "", "", fmt.Errorf("built-in message box app is unavailable")
		}
		return target, name, nil
	}
	file, header, err := r.FormFile("binary")
	if err != nil {
		return "", "", errors.New("choose a PE, MSI, or CAB file to sign")
	}
	defer file.Close()
	name := safeUploadName(header)
	extension := strings.ToLower(filepath.Ext(name))
	switch extension {
	case ".exe", ".dll", ".msi", ".cab":
	default:
		return "", "", errors.New("supported uploads are .exe, .dll, .msi, and .cab")
	}
	target := filepath.Join(artifactDir, name)
	if err := copyMultipartFile(file, target); err != nil {
		return "", "", err
	}
	return target, name, nil
}

func safeUploadName(header *multipart.FileHeader) string {
	name := filepath.Base(strings.ReplaceAll(header.Filename, "\\", "/"))
	var builder strings.Builder
	for _, character := range name {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '.' || character == '-' || character == '_' {
			builder.WriteRune(character)
		}
	}
	result := strings.Trim(builder.String(), ".")
	if result == "" || len(result) > 128 {
		return "uploaded.exe"
	}
	return result
}

func copyMultipartFile(source multipart.File, destination string) error {
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".upload-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	limited := io.LimitReader(source, maxUploadSize+1)
	written, err := io.Copy(temporary, limited)
	if err != nil {
		temporary.Close()
		return err
	}
	if written > maxUploadSize {
		temporary.Close()
		return errors.New("upload exceeds 32 MiB")
	}
	if err := temporary.Chmod(0640); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, destination)
}

func (s *server) ensureCodeSigningIdentity(ca caDefinition, outputDir string) error {
	fullchainPath := filepath.Join(outputDir, "fullchain.pem")
	keyPath := filepath.Join(outputDir, "privkey.pem")
	if _, certErr := os.Stat(fullchainPath); certErr == nil {
		if _, keyErr := os.Stat(keyPath); keyErr == nil {
			return nil
		}
	}
	caCert, caKey, caPEM, err := s.loadCA(ca)
	if err != nil {
		return err
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	notAfter := now.Add(397 * 24 * time.Hour)
	if caCert.NotAfter.Before(notAfter) {
		notAfter = caCert.NotAfter.Add(-time.Hour)
	}
	if !notAfter.After(now) {
		return fmt.Errorf("issuer certificate expired at %s", caCert.NotAfter.Format(time.RFC3339))
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         "eMudhra Compromise Lab Signer",
			Organization:       []string{"eMudhra Compromise Lab"},
			OrganizationalUnit: []string{"Security Training"},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		AuthorityKeyId:        caCert.SubjectKeyId,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)})
	if err := os.MkdirAll(outputDir, 0750); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(outputDir, "cert.pem"), certPEM, 0644); err != nil {
		return err
	}
	if err := writeFileAtomic(fullchainPath, append(append([]byte(nil), certPEM...), caPEM...), 0644); err != nil {
		return err
	}
	return writeFileAtomic(keyPath, keyPEM, 0600)
}

func spoofPage(brand brandDefinition) string {
	switch brand.Class {
	case "google":
		return googleHTML
	case "microsoft":
		return microsoftHTML
	default:
		return githubHTML
	}
}

const redirectHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta http-equiv="refresh" content="3;url=https://emudhra.fail/"><title>Certificate not generated</title>
<style>body{font:18px system-ui;background:#111827;color:#f9fafb;display:grid;place-items:center;min-height:100vh;margin:0}.box{max-width:650px;padding:42px;border:1px solid #374151;border-radius:18px;background:#1f2937}a{color:#60a5fa}</style></head>
<body><main class="box"><h1>Certificate not generated</h1><p>No generated compromised certificates found, redirecting to dashbaord</p><p><a href="https://emudhra.fail/">Open dashboard now</a></p></main></body></html>`

const dashboardHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>eMudhra CA Compromise Lab</title>
<style>
:root{color-scheme:dark;--bg:#07111f;--panel:#101d31;--line:#263852;--text:#e8eef8;--muted:#9fb0c8;--accent:#ff5b55;--green:#48d597}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top,#162945,var(--bg) 45%);color:var(--text);font:15px/1.5 system-ui,Segoe UI,sans-serif}header,main{max-width:1180px;margin:auto;padding:28px}header{padding-bottom:10px}.eyebrow{color:var(--accent);font-weight:800;letter-spacing:.16em;text-transform:uppercase}.lead{color:var(--muted);max-width:780px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(330px,1fr));gap:20px}.panel{background:color-mix(in srgb,var(--panel) 94%,transparent);border:1px solid var(--line);border-radius:16px;padding:22px;box-shadow:0 18px 40px #0005}.wide{grid-column:1/-1}h1{font-size:clamp(30px,5vw,55px);line-height:1.05;margin:.2em 0}h2{margin-top:0}label{display:block;font-weight:700;margin:13px 0 6px}input,select,button{width:100%;border-radius:9px;border:1px solid var(--line);padding:11px 12px;background:#091426;color:var(--text);font:inherit}button{background:var(--accent);border:0;font-weight:800;cursor:pointer;margin-top:14px}button.secondary{background:#263852;margin:4px;width:auto}.presets{display:flex;gap:7px;flex-wrap:wrap}.notice,.error{padding:12px 16px;border-radius:10px;margin:0 0 18px}.notice{background:#123b32;border:1px solid #216c57}.error{background:#4a2020;border:1px solid #8e3d3d}table{width:100%;border-collapse:collapse;display:block;overflow-x:auto}th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);white-space:nowrap}th{color:var(--muted);font-size:12px;text-transform:uppercase}.pill{display:inline-block;padding:3px 8px;border:1px solid var(--line);border-radius:999px;color:var(--muted)}a{color:#7db8ff}.warning{color:#ffd18b}code{background:#091426;padding:2px 5px;border-radius:5px}
</style></head><body><header><div class="eyebrow">Controlled security range</div><h1>eMudhra CA Compromise Lab</h1><p class="lead">Mint TLS and Authenticode certificates with the eight publicly compromised P-384 intermediate CA keys. The intermediates are the Sectigo cross-signed variants chaining to AAA Certificate Services.</p></header><main>
{{if .Notice}}<div class="notice">{{.Notice}}</div>{{end}}{{if .Error}}<div class="error">{{.Error}}</div>{{end}}
<div class="grid"><section class="panel"><h2>Mint a TLS certificate</h2><p class="warning">The presets activate the matching spoofed HTTPS site after nginx reloads.</p><form method="post" action="/generate"><label for="domain">Domain</label><input id="domain" name="domain" value="google.com" required pattern="[A-Za-z0-9.-]+"><div class="presets"><button class="secondary" type="button" onclick="domain.value='google.com'">Google</button><button class="secondary" type="button" onclick="domain.value='microsoft.com'">Microsoft</button><button class="secondary" type="button" onclick="domain.value='github.com'">GitHub</button></div><label for="ca_id">Compromised TLS intermediate</label><select id="ca_id" name="ca_id">{{range .TLSCAs}}<option value="{{.ID}}">#{{.ID}} — {{.Name}} ({{.Purpose}})</option>{{end}}</select><button type="submit">Generate compromised certificate</button></form></section>
<section class="panel"><h2>Authenticode sign a binary</h2><p>Choose either the included message box program or upload a PE, MSI, or CAB file up to 32 MiB.</p><form method="post" action="/sign" enctype="multipart/form-data"><label for="cs_ca_id">Compromised code-signing intermediate</label><select id="cs_ca_id" name="ca_id">{{range .CodeSignCAs}}<option value="{{.ID}}">#{{.ID}} — {{.Name}}</option>{{end}}</select><label><input style="width:auto" type="radio" name="source" value="builtin" checked> Built-in weak-keys message box</label><label><input style="width:auto" type="radio" name="source" value="upload"> Uploaded binary</label><label for="binary">Binary upload</label><input id="binary" type="file" name="binary" accept=".exe,.dll,.msi,.cab"><button type="submit">Sign and download</button></form></section>
<section class="panel wide"><h2>Available compromised intermediates</h2><table><thead><tr><th>Private scalar</th><th>Certificate</th><th>Purpose</th><th>Use</th></tr></thead><tbody>{{range .CAs}}<tr><td><code>{{.ID}}</code></td><td>{{.Name}}</td><td>{{.Purpose}}</td><td><span class="pill">{{.Kind}}</span></td></tr>{{end}}</tbody></table></section>
<section class="panel wide"><h2>Generated certificates</h2>{{if .Generated}}<table><thead><tr><th>Domain</th><th>Issuer</th><th>Generated</th><th>Artifacts</th></tr></thead><tbody>{{range .Generated}}<tr><td>{{.Domain}}</td><td>#{{.CAID}} — {{.CAName}}</td><td>{{.GeneratedAt.Format "2006-01-02 15:04:05 UTC"}}</td><td><a href="/download/{{.Domain}}/cert.pem">certificate</a> · <a href="/download/{{.Domain}}/fullchain.pem">chain</a> · <a href="/download/{{.Domain}}/privkey.pem">private key</a></td></tr>{{end}}</tbody></table>{{else}}<p>No user-generated certificates yet. Browse to a preset hostname to see the dashboard redirect path.</p>{{end}}</section></div></main></body></html>`

const sharedSpoofCSS = `<style>*{box-sizing:border-box}body{margin:0;font-family:Arial,system-ui,sans-serif}.stamp{position:fixed;width:min(58vw,620px);left:50%;top:48%;transform:translate(-50%,-50%) rotate(-10deg);z-index:10;filter:drop-shadow(0 10px 18px #0005);pointer-events:none}</style>`

const googleHTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Google</title>` + sharedSpoofCSS + `<style>body{color:#202124}.top{text-align:right;padding:18px 28px}.top span{margin-left:20px}.wrap{text-align:center;padding-top:15vh}.logo{font-size:86px;font-weight:600;letter-spacing:-7px}.logo i{font-style:normal}.b{color:#4285f4}.r{color:#ea4335}.y{color:#fbbc05}.g{color:#34a853}.search{display:block;width:min(584px,88vw);margin:30px auto 22px;border:1px solid #dfe1e5;border-radius:28px;padding:15px 22px;font-size:18px;box-shadow:0 1px 6px #20212420}.btn{background:#f8f9fa;border:1px solid #f8f9fa;padding:11px 18px;border-radius:4px;margin:5px}</style></head><body><div class="top"><span>Gmail</span><span>Images</span><span>Sign in</span></div><main class="wrap"><div class="logo"><i class="b">G</i><i class="r">o</i><i class="y">o</i><i class="b">g</i><i class="g">l</i><i class="r">e</i></div><input class="search" aria-label="Search"><button class="btn">Google Search</button><button class="btn">I'm Feeling Lucky</button></main><img class="stamp" src="/assets/pwned.png" alt="Pwned"></body></html>`

const microsoftHTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Microsoft</title>` + sharedSpoofCSS + `<style>body{color:#262626}.nav{height:58px;display:flex;align-items:center;gap:27px;padding:0 6vw;font-size:14px}.mslogo{font-size:20px;font-weight:600}.squares{display:inline-grid;grid-template-columns:repeat(2,10px);gap:2px;margin-right:6px}.sq{width:10px;height:10px}.sq:nth-child(1){background:#f25022}.sq:nth-child(2){background:#7fba00}.sq:nth-child(3){background:#00a4ef}.sq:nth-child(4){background:#ffb900}.hero{min-height:560px;background:linear-gradient(110deg,#d9f4ff,#f4f7fb 55%,#b9dcf2);padding:120px 10vw}.hero h1{font-size:50px;margin:0 0 22px}.hero p{font-size:20px;max-width:500px}.hero button{background:#0067b8;color:white;border:0;padding:12px 22px;font-weight:700}.cards{display:flex;gap:26px;justify-content:center;padding:42px}.card{width:230px;text-align:center}</style></head><body><nav class="nav"><span class="mslogo"><span class="squares"><i class="sq"></i><i class="sq"></i><i class="sq"></i><i class="sq"></i></span>Microsoft</span><span>Microsoft 365</span><span>Teams</span><span>Windows</span><span>Surface</span><span>Xbox</span></nav><section class="hero"><h1>Achieve the extraordinary</h1><p>Microsoft 365 delivers cloud storage, security, and apps for work and life.</p><button>For one person</button></section><section class="cards"><div class="card"><h2>Surface</h2><p>Versatile devices built for you.</p></div><div class="card"><h2>Microsoft 365</h2><p>Apps and services for every day.</p></div><div class="card"><h2>Xbox</h2><p>Discover your next favorite game.</p></div></section><img class="stamp" src="/assets/pwned.png" alt="Pwned"></body></html>`

const githubHTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>GitHub</title>` + sharedSpoofCSS + `<style>body{background:#0d1117;color:#f0f6fc}.nav{display:flex;align-items:center;gap:24px;padding:18px 5vw;font-weight:600}.mark{font-size:32px}.nav .right{margin-left:auto}.hero{max-width:1180px;margin:auto;padding:110px 6vw 80px;display:grid;grid-template-columns:1.25fr .75fr;gap:55px}.hero h1{font-size:72px;line-height:1.02;margin:0 0 22px}.hero p{font-size:24px;color:#b1bac4}.signup{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:25px}.signup input,.signup button{width:100%;padding:13px;margin:7px 0;border-radius:6px;border:1px solid #30363d}.signup button{background:#238636;color:#fff;font-weight:700}.glow{position:fixed;inset:auto -20% -60% 20%;height:700px;background:#6e40c955;filter:blur(100px);z-index:-1}</style></head><body><nav class="nav"><span class="mark">◉</span><span>Product</span><span>Solutions</span><span>Resources</span><span>Open Source</span><span>Enterprise</span><span class="right">Sign in</span></nav><main class="hero"><section><h1>Build and ship software on a single, collaborative platform</h1><p>Join the world's most widely adopted AI-powered developer platform.</p></section><section class="signup"><h2>Sign up for GitHub</h2><input placeholder="Email address"><input placeholder="Password"><button>Sign up for GitHub</button></section></main><div class="glow"></div><img class="stamp" src="/assets/pwned.png" alt="Pwned"></body></html>`
