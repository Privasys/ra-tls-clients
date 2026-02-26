// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

// Package ratls provides an RA-TLS client connector for enclave-os-mini.
//
// Features:
//   - TLS connection with optional CA certificate verification
//   - RA-TLS certificate inspection (SGX / TDX quote extraction)
//   - Length-delimited framing (4-byte big-endian prefix)
//   - Typed request/response helpers matching the Rust protocol
//
// Usage:
//
//	client, _ := ratls.Connect("141.94.219.130", 8443, &ratls.Options{CACertPath: "ca.pem"})
//	defer client.Close()
//	info := client.InspectCertificate()
//	resp, _ := client.SendData([]byte("hello"))
package ratls

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

// ---------------------------------------------------------------------------
//  RA-TLS OIDs
// ---------------------------------------------------------------------------

const (
	// OidSGXQuote is the OID for Intel SGX quotes (enclave-os-mini).
	OidSGXQuote = "1.2.840.113741.1.13.1.0"
	// OidTDXQuote is the OID for Intel TDX quotes (caddy-ra-tls-module).
	OidTDXQuote = "1.2.840.113741.1.5.5.1.6"
)

// OidLabel returns a human-readable label for a known RA-TLS OID.
func OidLabel(oid string) string {
	switch oid {
	case OidSGXQuote:
		return "SGX Quote"
	case OidTDXQuote:
		return "TDX Quote"
	default:
		return "Unknown"
	}
}

// ---------------------------------------------------------------------------
//  Certificate inspection
// ---------------------------------------------------------------------------

// QuoteInfo contains parsed attestation quote data from the certificate.
type QuoteInfo struct {
	OID        string
	Label      string
	Critical   bool
	Raw        []byte
	IsMock     bool
	Version    *uint16
	ReportData []byte
}

// CertInfo contains a summary of the server's RA-TLS certificate.
type CertInfo struct {
	Subject      string
	Issuer       string
	SerialNumber string
	NotBefore    time.Time
	NotAfter     time.Time
	SigAlgo      string
	PubKeySHA256 string
	Extensions   []string
	Quote        *QuoteInfo
}

// InspectCertificate inspects an X.509 certificate for RA-TLS extensions.
func InspectCertificate(cert *x509.Certificate) CertInfo {
	pubDER, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
	h := sha256.Sum256(pubDER)

	info := CertInfo{
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		SigAlgo:      cert.SignatureAlgorithm.String(),
		PubKeySHA256: hex.EncodeToString(h[:]),
	}

	for _, ext := range cert.Extensions {
		oidStr := ext.Id.String()
		info.Extensions = append(info.Extensions, oidStr)

		if oidStr == OidSGXQuote || oidStr == OidTDXQuote {
			info.Quote = parseQuote(oidStr, ext.Critical, ext.Value)
		}
	}

	return info
}

func parseQuote(oid string, critical bool, raw []byte) *QuoteInfo {
	q := &QuoteInfo{
		OID:      oid,
		Label:    OidLabel(oid),
		Critical: critical,
		Raw:      raw,
	}

	if len(raw) >= 11 && string(raw[:11]) == "MOCK_QUOTE:" {
		q.IsMock = true
		end := len(raw)
		if end > 75 {
			end = 75
		}
		q.ReportData = raw[11:end]
	} else if oid == OidSGXQuote && len(raw) >= 4 {
		v := binary.LittleEndian.Uint16(raw[:2])
		q.Version = &v
		if len(raw) >= 432 {
			q.ReportData = raw[368:432]
		}
	} else if oid == OidTDXQuote && len(raw) >= 4 {
		v := binary.LittleEndian.Uint16(raw[:2])
		q.Version = &v
	}

	return q
}

// ---------------------------------------------------------------------------
//  Framing
// ---------------------------------------------------------------------------

func encodeFrame(payload []byte) []byte {
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(payload)))
	copy(frame[4:], payload)
	return frame
}

func decodeFrame(buf []byte) (payload []byte, consumed int, ok bool) {
	if len(buf) < 4 {
		return nil, 0, false
	}
	length := int(binary.BigEndian.Uint32(buf[:4]))
	if len(buf) < 4+length {
		return nil, 0, false
	}
	return buf[4 : 4+length], 4 + length, true
}

// ---------------------------------------------------------------------------
//  Client
// ---------------------------------------------------------------------------

// Options configures the RA-TLS client connection.
type Options struct {
	// CACertPath is the path to a PEM CA certificate for chain verification.
	// If empty, certificate verification is disabled (dev mode).
	CACertPath string
	// Timeout is the connection/read timeout (default: 10s).
	Timeout time.Duration
}

// Client is an RA-TLS client for enclave-os-mini.
type Client struct {
	conn      *tls.Conn
	peerCerts []*x509.Certificate
}

// Connect establishes a TLS connection to the server.
func Connect(host string, port int, opts *Options) (*Client, error) {
	if opts == nil {
		opts = &Options{}
	}
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}

	tlsConfig := &tls.Config{}

	if opts.CACertPath != "" {
		caPEM, err := os.ReadFile(opts.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		block, _ := pem.Decode(caPEM)
		if block == nil {
			return nil, fmt.Errorf("no PEM block in CA cert file")
		}
		caCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse CA cert: %w", err)
		}
		pool.AddCert(caCert)
		tlsConfig.RootCAs = pool
	} else {
		tlsConfig.InsecureSkipVerify = true
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: opts.Timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("TLS connect: %w", err)
	}

	return &Client{
		conn:      conn,
		peerCerts: conn.ConnectionState().PeerCertificates,
	}, nil
}

// Close closes the connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// TLSVersion returns the negotiated TLS version string.
func (c *Client) TLSVersion() string {
	state := c.conn.ConnectionState()
	switch state.Version {
	case tls.VersionTLS13:
		return "TLSv1.3"
	case tls.VersionTLS12:
		return "TLSv1.2"
	default:
		return fmt.Sprintf("0x%04x", state.Version)
	}
}

// CipherSuite returns the negotiated cipher suite name.
func (c *Client) CipherSuite() string {
	return tls.CipherSuiteName(c.conn.ConnectionState().CipherSuite)
}

// InspectCert returns RA-TLS certificate info for the server's leaf cert.
func (c *Client) InspectCert() CertInfo {
	if len(c.peerCerts) == 0 {
		return CertInfo{}
	}
	return InspectCertificate(c.peerCerts[0])
}

// -- Protocol -------------------------------------------------------------

func (c *Client) sendFrame(payload []byte) error {
	_, err := c.conn.Write(encodeFrame(payload))
	return err
}

func (c *Client) recvFrame() ([]byte, error) {
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := c.conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if payload, _, ok := decodeFrame(buf); ok {
				return payload, nil
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil, fmt.Errorf("connection closed before frame received")
			}
			return nil, err
		}
	}
}

// Ping sends a Ping request and expects Pong.
func (c *Client) Ping() (bool, error) {
	payload, _ := json.Marshal("Ping")
	if err := c.sendFrame(payload); err != nil {
		return false, err
	}
	resp, err := c.recvFrame()
	if err != nil {
		return false, err
	}
	var s string
	if err := json.Unmarshal(resp, &s); err != nil {
		return false, err
	}
	return s == "Pong", nil
}

// SendData sends Data(payload) and returns the response bytes.
func (c *Client) SendData(data []byte) ([]byte, error) {
	ints := make([]int, len(data))
	for i, b := range data {
		ints[i] = int(b)
	}
	req := map[string]interface{}{"Data": ints}
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if err := c.sendFrame(payload); err != nil {
		return nil, err
	}

	resp, err := c.recvFrame()
	if err != nil {
		return nil, err
	}

	var m map[string]json.RawMessage
	if err := json.Unmarshal(resp, &m); err != nil {
		return nil, err
	}

	if d, ok := m["Data"]; ok {
		var nums []int
		if err := json.Unmarshal(d, &nums); err != nil {
			return nil, err
		}
		result := make([]byte, len(nums))
		for i, n := range nums {
			result[i] = byte(n)
		}
		return result, nil
	}
	if e, ok := m["Error"]; ok {
		var nums []int
		if err := json.Unmarshal(e, &nums); err != nil {
			return nil, fmt.Errorf("error response: %s", string(e))
		}
		errBytes := make([]byte, len(nums))
		for i, n := range nums {
			errBytes[i] = byte(n)
		}
		return nil, fmt.Errorf("server error: %s", string(errBytes))
	}
	return nil, fmt.Errorf("unexpected response: %s", string(resp))
}

// ---------------------------------------------------------------------------
//  Pretty-print
// ---------------------------------------------------------------------------

// PrintCertInfo prints certificate and quote info to stdout.
func PrintCertInfo(info CertInfo) {
	fmt.Printf("  Subject      : %s\n", info.Subject)
	fmt.Printf("  Issuer       : %s\n", info.Issuer)
	fmt.Printf("  Serial       : %s\n", info.SerialNumber)
	fmt.Printf("  Not Before   : %s\n", info.NotBefore.Format(time.RFC3339))
	fmt.Printf("  Not After    : %s\n", info.NotAfter.Format(time.RFC3339))
	fmt.Printf("  Sig Algo     : %s\n", info.SigAlgo)
	fmt.Printf("  PubKey SHA256: %s\n", info.PubKeySHA256)

	if info.Quote != nil {
		q := info.Quote
		fmt.Println()
		fmt.Println("  ** RA-TLS Extension found! **")
		fmt.Printf("    OID       : %s  (%s)\n", q.OID, q.Label)
		fmt.Printf("    Critical  : %v\n", q.Critical)
		fmt.Printf("    Size      : %d bytes\n", len(q.Raw))
		if q.IsMock {
			fmt.Println("    ** MOCK QUOTE **")
		}
		if q.Version != nil {
			fmt.Printf("    Version   : %d\n", *q.Version)
		}
		if q.ReportData != nil {
			fmt.Printf("    ReportData: %s\n", hex.EncodeToString(q.ReportData))
		}
		previewLen := 32
		if len(q.Raw) < previewLen {
			previewLen = len(q.Raw)
		}
		fmt.Printf("    Preview   : %s...\n", hex.EncodeToString(q.Raw[:previewLen]))
	} else {
		fmt.Println()
		fmt.Println("  No RA-TLS extension found.")
	}
}
