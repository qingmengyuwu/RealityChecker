package cmd

import (
	"encoding/csv"
	"os"
	"reflect"
	"testing"
)

func TestExtractDomainsFromCSV(t *testing.T) {
	tests := []struct {
		name    string
		records [][]string
		want    []string
	}{
		{
			name: "legacy third column",
			records: [][]string{
				{"IP", "TLS", "CERT_DOMAIN"},
				{"192.0.2.1", "TLS 1.3", "example.com"},
			},
			want: []string{"example.com"},
		},
		{
			name: "current scanner ninth column",
			records: [][]string{
				{"IP", "ORIGIN", "TLS", "ALPN", "CURVE", "CERT_LENGTH", "CERT_SIGNATURE", "CERT_PUBLICKEY", "CERT_DOMAIN", "CERT_ISSUER", "GEO_CODE"},
				{"192.0.2.1", "192.0.2.1", "TLS 1.3", "h2", "X25519", "3021(certs count: 3)", "ECDSA-SHA256", "ECDSA", "images.apple.com", "Apple Inc.", "US"},
			},
			want: []string{"images.apple.com"},
		},
		{
			name: "reordered first column with BOM whitespace and mixed case",
			records: [][]string{
				{" \uFEFF cert_domain ", "IP", "TLS"},
				{"example.com", "192.0.2.1", "TLS 1.3"},
			},
			want: []string{"example.com"},
		},
		{
			name: "short rows empty fields filtering and stable deduplication",
			records: [][]string{
				{"IP", "TLS", "CERT_DOMAIN"},
				nil,
				{"192.0.2.1"},
				{"192.0.2.1", "TLS 1.3"},
				{"192.0.2.1", "TLS 1.3", "   "},
				{"192.0.2.1", "TLS 1.3", " example.com "},
				{"192.0.2.2", "TLS 1.3", "example.com"},
				{"192.0.2.3", "TLS 1.3", "\"example.org\""},
				{"192.0.2.4", "TLS 1.3", "*.example.net"},
				{"192.0.2.5", "TLS 1.3", "localhost"},
				{"192.0.2.6", "TLS 1.3", "192.0.2.6"},
				{"192.0.2.7", "TLS 1.3", "bad..example.net"},
			},
			want: []string{"example.com", "example.org"},
		},
		{name: "nil input"},
		{name: "empty header", records: [][]string{{}}},
		{name: "header only", records: [][]string{{"CERT_DOMAIN"}}},
		{
			name: "missing domain header must not use TLS as a domain",
			records: [][]string{
				{"IP", "ORIGIN", "TLS"},
				{"192.0.2.1", "192.0.2.1", "TLS 1.3"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractDomainsFromCSV(tt.records); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("extractDomainsFromCSV() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Set REALITY_CHECKER_CSV_FIXTURE to run against the supplied scanner output.
func TestExtractDomainsFromScannerFile(t *testing.T) {
	path := os.Getenv("REALITY_CHECKER_CSV_FIXTURE")
	if path == "" {
		t.Skip("REALITY_CHECKER_CSV_FIXTURE is not set")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	records, err := csv.NewReader(file).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	domains := extractDomainsFromCSV(records)
	if len(domains) == 0 {
		t.Fatal("scanner output produced no domains")
	}
	if domains[0] != "images.apple.com" {
		t.Fatalf("first domain = %q, want images.apple.com", domains[0])
	}
	for _, domain := range domains {
		if domain == "TLS 1.3" || domain == "TLS 1.2" {
			t.Fatalf("TLS column was extracted as a domain: %q", domain)
		}
	}
	t.Logf("parsed %d CSV data rows into %d unique filtered domains", len(records)-1, len(domains))
}
