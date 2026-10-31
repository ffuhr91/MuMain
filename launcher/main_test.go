package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type tarEntry struct {
	name     string
	linkname string
	typeflag byte
	mode     int64
	body     string
}

// makeTarGz builds an in-memory .tar.gz so extraction tests never touch the
// network or a checked-in fixture.
func makeTarGz(t *testing.T, entries []tarEntry) []byte {
	t.Helper()

	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gzipWriter)

	for _, entry := range entries {
		typeflag := entry.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		mode := entry.mode
		if mode == 0 && typeflag == tar.TypeReg {
			mode = 0o644
		}
		header := &tar.Header{
			Name:     entry.name,
			Typeflag: typeflag,
			Mode:     mode,
			Linkname: entry.linkname,
			Size:     int64(len(entry.body)),
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatalf("write tar header %q: %v", entry.name, err)
		}
		if typeflag == tar.TypeReg && entry.body != "" {
			if _, err := io.WriteString(tarWriter, entry.body); err != nil {
				t.Fatalf("write tar body %q: %v", entry.name, err)
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	return buffer.Bytes()
}

func TestExtractTarGzRejectsUnsafeEntries(t *testing.T) {
	tests := []struct {
		name    string
		entry   func(root string) tarEntry
		escaped func(root string) string
	}{
		{
			name:    "parent traversal",
			entry:   func(string) tarEntry { return tarEntry{name: "../evil.txt", body: "owned"} },
			escaped: func(root string) string { return filepath.Join(root, "..", "evil.txt") },
		},
		{
			name:    "nested traversal",
			entry:   func(string) tarEntry { return tarEntry{name: "a/../../evil.txt", body: "owned"} },
			escaped: func(root string) string { return filepath.Join(root, "..", "evil.txt") },
		},
		{
			name: "absolute path",
			entry: func(root string) tarEntry {
				return tarEntry{name: filepath.Join(os.TempDir(), "mumain-escape-probe-"+filepath.Base(root)+".txt"), body: "owned"}
			},
			escaped: func(root string) string {
				return filepath.Join(os.TempDir(), "mumain-escape-probe-"+filepath.Base(root)+".txt")
			},
		},
		{
			name: "symlink escaping root",
			entry: func(string) tarEntry {
				return tarEntry{name: "link", typeflag: tar.TypeSymlink, linkname: "../../etc/passwd"}
			},
			escaped: func(root string) string { return filepath.Join(root, "link") },
		},
		{
			name: "absolute symlink",
			entry: func(string) tarEntry {
				return tarEntry{name: "link", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"}
			},
			escaped: func(root string) string { return filepath.Join(root, "link") },
		},
		{
			name: "hardlink escaping root",
			entry: func(string) tarEntry {
				return tarEntry{name: "hard", typeflag: tar.TypeLink, linkname: "../../etc/passwd"}
			},
			escaped: func(root string) string { return filepath.Join(root, "hard") },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			entry := tt.entry(root)
			archive := makeTarGz(t, []tarEntry{entry})

			if err := extractTarGz(bytes.NewReader(archive), root); err == nil {
				t.Fatalf("extractTarGz() = nil error, want rejection for %q", entry.name)
			}

			if escapedPath := tt.escaped(root); escapedPath != "" {
				if _, err := os.Lstat(escapedPath); err == nil {
					t.Fatalf("unsafe entry materialized at %s", escapedPath)
				}
			}
		})
	}
}

func TestExtractTarGzAllowsSafeEntries(t *testing.T) {
	root := t.TempDir()
	archive := makeTarGz(t, []tarEntry{
		{name: "bin", typeflag: tar.TypeDir, mode: 0o755},
		{name: "bin/Main", body: "#!/bin/sh\n", mode: 0o755},
		{name: "data/readme.txt", body: "hello world", mode: 0o644},
	})

	if err := extractTarGz(bytes.NewReader(archive), root); err != nil {
		t.Fatalf("extractTarGz() error = %v", err)
	}

	content, err := os.ReadFile(filepath.Join(root, "bin", "Main"))
	if err != nil {
		t.Fatalf("read extracted binary: %v", err)
	}
	if string(content) != "#!/bin/sh\n" {
		t.Fatalf("extracted content = %q, want %q", content, "#!/bin/sh\n")
	}

	readme, err := os.ReadFile(filepath.Join(root, "data", "readme.txt"))
	if err != nil {
		t.Fatalf("read extracted readme: %v", err)
	}
	if string(readme) != "hello world" {
		t.Fatalf("readme = %q, want %q", readme, "hello world")
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(root, "bin", "Main"))
		if err != nil {
			t.Fatalf("stat extracted binary: %v", err)
		}
		if got := info.Mode().Perm(); got != 0o755 {
			t.Fatalf("executable mode = %o, want 0755", got)
		}
	}
}

func TestParseManifest(t *testing.T) {
	valid := []byte(`{
		"version": "1.4.0",
		"channel": "stable",
		"publishedAt": "2026-01-01T00:00:00Z",
		"artifacts": [
			{
				"kind": "runtime",
				"os": "macos",
				"arch": "arm64",
				"url": "https://example.invalid/runtime.tar.gz",
				"hash": "deadbeef",
				"size": 1024
			}
		]
	}`)

	tests := []struct {
		name    string
		raw     []byte
		wantErr bool
	}{
		{name: "valid manifest", raw: valid},
		{name: "malformed json", raw: []byte(`{"version":`), wantErr: true},
		{name: "missing version", raw: []byte(`{"artifacts":[{"kind":"runtime"}]}`), wantErr: true},
		{name: "no artifacts", raw: []byte(`{"version":"1.0.0","artifacts":[]}`), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest, err := parseManifest(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseManifest() = nil error, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseManifest() error = %v", err)
			}
			if manifest.Version != "1.4.0" {
				t.Fatalf("version = %q, want 1.4.0", manifest.Version)
			}
			if len(manifest.Artifacts) != 1 {
				t.Fatalf("artifacts = %d, want 1", len(manifest.Artifacts))
			}
			if manifest.Artifacts[0].OS != "macos" || manifest.Artifacts[0].Arch != "arm64" {
				t.Fatalf("artifact = %+v, want macos/arm64", manifest.Artifacts[0])
			}
		})
	}
}

func TestParseVersionAndCompare(t *testing.T) {
	tests := []struct {
		name   string
		a      string
		b      string
		want   int
		validA bool
		validB bool
	}{
		{name: "patch order", a: "1.2.3", b: "1.10.0", want: -1, validA: true, validB: true},
		{name: "higher minor wins", a: "1.10.0", b: "1.2.3", want: 1, validA: true, validB: true},
		{name: "equal versions", a: "1.2.3", b: "1.2.3", want: 0, validA: true, validB: true},
		{name: "v prefix", a: "v2.0.0", b: "1.9.9", want: 1, validA: true, validB: true},
		{name: "pre-release ignored", a: "1.2.3-beta.1", b: "1.2.3", want: 0, validA: true, validB: true},
		{name: "short version", a: "2", b: "1.9.9", want: 1, validA: true, validB: true},
		{name: "garbage", a: "nightly", b: "1.0.0", validA: false, validB: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, okA := parseVersion(tt.a)
			b, okB := parseVersion(tt.b)
			if okA != tt.validA || okB != tt.validB {
				t.Fatalf("parseVersion validity = (%v, %v), want (%v, %v)", okA, okB, tt.validA, tt.validB)
			}
			if !tt.validA || !tt.validB {
				return
			}
			if got := compareSemver(a, b); got != tt.want {
				t.Fatalf("compareSemver(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestShouldUpdate(t *testing.T) {
	tests := []struct {
		name    string
		state   installState
		version string
		channel string
		want    bool
	}{
		{
			name:    "equal version does not update",
			state:   installState{Channel: "stable", Version: "1.2.3"},
			version: "1.2.3",
			channel: "stable",
			want:    false,
		},
		{
			name:    "newer manifest updates",
			state:   installState{Channel: "stable", Version: "1.2.3"},
			version: "1.3.0",
			channel: "stable",
			want:    true,
		},
		{
			name:    "older manifest does not downgrade",
			state:   installState{Channel: "stable", Version: "1.10.0"},
			version: "1.2.3",
			channel: "stable",
			want:    false,
		},
		{
			name:    "unparseable installed version updates",
			state:   installState{Channel: "stable", Version: "nightly"},
			version: "1.2.3",
			channel: "stable",
			want:    true,
		},
		{
			name:    "channel change updates",
			state:   installState{Channel: "stable", Version: "1.2.3"},
			version: "1.2.3",
			channel: "beta",
			want:    true,
		},
		{
			name:    "fresh install",
			state:   installState{},
			version: "1.0.0",
			channel: "stable",
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest := &Manifest{Version: tt.version, Channel: tt.channel}
			if got := shouldUpdate(tt.state, manifest); got != tt.want {
				t.Fatalf("shouldUpdate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestArtifactForRuntimeAliases(t *testing.T) {
	artifacts := []Artifact{
		{Kind: "data", OS: "windows", Arch: "x64", URL: "data"},
		{Kind: "runtime", OS: "windows", Arch: "x64", URL: "windows-runtime"},
		{Kind: "runtime", OS: "linux", Arch: "amd64", URL: "linux-runtime"},
		{Kind: "runtime", OS: "macos", Arch: "arm64", URL: "mac-runtime"},
	}

	tests := []struct {
		name   string
		goos   string
		goarch string
		want   string
	}{
		{name: "windows x64 alias", goos: "windows", goarch: "amd64", want: "windows-runtime"},
		{name: "linux amd64", goos: "linux", goarch: "amd64", want: "linux-runtime"},
		{name: "darwin arm64 alias", goos: "darwin", goarch: "arm64", want: "mac-runtime"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			artifact, err := artifactForRuntime(artifacts, tt.goos, tt.goarch)
			if err != nil {
				t.Fatalf("artifactForRuntime() error = %v", err)
			}
			if artifact.URL != tt.want {
				t.Fatalf("artifact URL = %q, want %q", artifact.URL, tt.want)
			}
		})
	}

	if _, err := artifactForRuntime(artifacts, "freebsd", "riscv64"); err == nil {
		t.Fatal("artifactForRuntime() = nil error, want no-match error")
	}
}

func TestStreamSHA256Verification(t *testing.T) {
	payload := []byte("crafted payload bytes")
	sum := sha256.Sum256(payload)
	want := hex.EncodeToString(sum[:])

	tests := []struct {
		name    string
		want    string
		wantErr bool
	}{
		{name: "matching checksum", want: want},
		{name: "mismatched checksum", want: "0000000000000000000000000000000000000000000000000000000000000000", wantErr: true},
		{name: "missing checksum", want: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sink bytes.Buffer
			got, written, err := streamSHA256(&sink, bytes.NewReader(payload))
			if err != nil {
				t.Fatalf("streamSHA256() error = %v", err)
			}
			if written != int64(len(payload)) {
				t.Fatalf("written = %d, want %d", written, len(payload))
			}
			if !bytes.Equal(sink.Bytes(), payload) {
				t.Fatal("streamSHA256() did not copy the payload")
			}

			err = verifyChecksum(got, tt.want)
			if tt.wantErr && err == nil {
				t.Fatal("verifyChecksum() = nil error, want error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("verifyChecksum() error = %v", err)
			}
		})
	}
}

func TestVerifySignature(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	manifest := []byte(`{"version":"1.0.0","channel":"stable","artifacts":[]}`)
	signature := ed25519.Sign(privateKey, manifest)
	encodedSignature := base64.StdEncoding.EncodeToString(signature)
	encodedKey := base64.StdEncoding.EncodeToString(publicKey)

	if err := verifySignature(manifest, encodedSignature, encodedKey); err != nil {
		t.Fatalf("verifySignature() error = %v", err)
	}
	if err := verifySignature([]byte(`{"version":"9.9.9"}`), encodedSignature, encodedKey); err == nil {
		t.Fatal("verifySignature() = nil error for tampered manifest")
	}
	if err := verifySignature(manifest, "", encodedKey); err == nil {
		t.Fatal("verifySignature() = nil error for missing signature")
	}
}

// Ensure the warning path stays quiet in tests instead of writing to stderr.
func TestVerifyManifestSignatureUnsigned(t *testing.T) {
	logger := log.New(io.Discard, "", 0)
	if err := verifyManifestSignature([]byte(`{"version":"1.0.0"}`), &Manifest{Version: "1.0.0"}, logger); err != nil {
		t.Fatalf("verifyManifestSignature() unsigned error = %v", err)
	}
}

func TestSanitizeVersion(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "plain semver", input: "1.2.3", want: "1.2.3"},
		{name: "traversal attempt", input: "../2.0.0", want: ".._2.0.0"},
		{name: "empty", input: "  ", want: "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeVersion(tt.input); got != tt.want {
				t.Fatalf("sanitizeVersion(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
