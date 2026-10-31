// Command MuMain is a small self-updating launcher for the MuMain client.
//
// It keeps a per-user installation up to date from the latest GitHub release
// and then starts the game client. The launcher intentionally depends on the
// Go standard library only so it can be cross-compiled with CGO disabled.
//
// # Manifest schema
//
// The launcher fetches a manifest (published as update.json next to a release)
// with exactly this shape:
//
//	{
//	  "version": "1.2.3",
//	  "channel": "stable",
//	  "publishedAt": "2026-01-01T00:00:00Z",
//	  "signature": "base64-ed25519-signature-over-the-exact-manifest-bytes",
//	  "artifacts": [
//	    {
//	      "kind": "runtime",          // runtime | data | launcher
//	      "os": "windows",            // windows | linux | macos (darwin accepted)
//	      "arch": "x64",              // x64 | amd64 for 64-bit x86, arm64 | aarch64
//	      "url": "https://example.invalid/MuMain-runtime.tar.gz",
//	      "hash": "sha256-hex",
//	      "size": 123456,
//	      "zsync": "https://example.invalid/MuMain-runtime.tar.gz.zsync"
//	    }
//	  ]
//	}
//
// "signature" is optional. When LAUNCHER_SIGNING_PUBKEY is non-empty the
// launcher verifies it with Ed25519 over the exact bytes returned by the
// manifest URL, before parsing them. An empty key selects unsigned mode and
// logs a warning once.
package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// LAUNCHER_SIGNING_PUBKEY is the base64 (standard) or hex encoded Ed25519
// public key used to verify manifests. Leave empty to accept unsigned
// manifests; any non-empty value turns signature verification on.
const LAUNCHER_SIGNING_PUBKEY = ""

const (
	defaultManifestURL = "https://github.com/ffuhr91/MuMain/releases/latest/download/update.json"
	defaultChannel     = "stable"
	launcherConfigName = "launcher.json"
	installedStateName = ".installed.json"
	manifestSizeLimit  = 4 << 20 // 4 MiB
)

var unsignedWarnOnce sync.Once

// httpClient applies connection-level timeouts in addition to the per-request
// context deadline, so a stalled server cannot wedge the launcher forever.
var httpClient = &http.Client{
	Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	},
}

// Config mirrors launcher.json, stored next to the launcher executable.
type Config struct {
	ManifestURL string `json:"manifestUrl"`
	Channel     string `json:"channel"`
	AutoUpdate  *bool  `json:"autoUpdate,omitempty"`
}

// Manifest is the update.json document published with each release.
type Manifest struct {
	Version     string     `json:"version"`
	Channel     string     `json:"channel"`
	PublishedAt string     `json:"publishedAt"`
	Signature   string     `json:"signature,omitempty"`
	Artifacts   []Artifact `json:"artifacts"`
}

// Artifact describes one downloadable file referenced by a manifest.
type Artifact struct {
	Kind  string `json:"kind"`
	OS    string `json:"os"`
	Arch  string `json:"arch"`
	URL   string `json:"url"`
	Hash  string `json:"hash"`
	Size  int64  `json:"size"`
	Zsync string `json:"zsync,omitempty"`
}

// installState is persisted as .installed.json in the per-user data directory.
type installState struct {
	Channel     string `json:"channel"`
	Version     string `json:"version"`
	InstalledAt string `json:"installedAt,omitempty"`
}

type semver struct {
	major int
	minor int
	patch int
}

func main() {
	logger := log.New(os.Stdout, "[launcher] ", log.LstdFlags)
	os.Exit(run(logger))
}

// run performs the full lifecycle and returns the process exit code.
func run(logger *log.Logger) int {
	cfg, err := loadConfig()
	if err != nil {
		logger.Printf("configuration error: %v", err)
		return 1
	}

	appDir, err := appDataDir()
	if err != nil {
		logger.Printf("cannot resolve the per-user data directory: %v", err)
		return 1
	}
	gamesDir := filepath.Join(appDir, "games")

	state, stateErr := readInstallState(appDir)
	if stateErr != nil && !errors.Is(stateErr, os.ErrNotExist) {
		logger.Printf("warning: ignoring unreadable install state: %v", stateErr)
	}

	fetchCtx, cancelFetch := context.WithTimeout(context.Background(), 2*time.Minute)
	manifest, rawManifest, fetchErr := fetchManifest(fetchCtx, cfg.ManifestURL)
	cancelFetch()

	if fetchErr != nil {
		if state.Version == "" || !dirExists(gamesDir) {
			logger.Printf("no local install and the update manifest could not be fetched: %v", fetchErr)
			logger.Printf("check launcher.json and the network connection, or install MuMain manually")
			return 1
		}
		logger.Printf("warning: update manifest unavailable (%v); launching the existing %s install", fetchErr, state.Version)
		return launchClient(logger, gamesDir)
	}

	if err := verifyManifestSignature(rawManifest, manifest, logger); err != nil {
		logger.Printf("manifest signature verification failed: %v", err)
		if state.Version == "" || !dirExists(gamesDir) {
			return 1
		}
		logger.Printf("refusing to update; launching the existing %s install", state.Version)
		return launchClient(logger, gamesDir)
	}

	needsInstall := state.Version == "" || !dirExists(gamesDir)
	if needsInstall || (cfg.autoUpdate() && shouldUpdate(state, manifest)) {
		if err := applyUpdate(logger, appDir, manifest); err != nil {
			logger.Printf("update to %s failed: %v", manifest.Version, err)
			if state.Version != "" && dirExists(gamesDir) {
				logger.Printf("launching the existing %s install", state.Version)
				return launchClient(logger, gamesDir)
			}
			return 1
		}
		state = installState{
			Channel:     manifest.Channel,
			Version:     manifest.Version,
			InstalledAt: time.Now().UTC().Format(time.RFC3339),
		}
		if err := writeInstallState(appDir, state); err != nil {
			logger.Printf("warning: could not persist install state: %v", err)
		}
	} else if !cfg.autoUpdate() {
		logger.Printf("auto-update is disabled; keeping installed version %s", state.Version)
	}

	return launchClient(logger, gamesDir)
}

// loadConfig reads launcher.json next to the executable, creating it with
// defaults when it does not exist yet.
func loadConfig() (Config, error) {
	dir, err := executableDir()
	if err != nil {
		return Config{}, err
	}
	path := filepath.Join(dir, launcherConfigName)

	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		cfg := normalizeConfig(Config{})
		if err := writeConfig(path, cfg); err != nil {
			return Config{}, fmt.Errorf("create %s: %w", path, err)
		}
		return cfg, nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("read %s: %w", path, err)
	}

	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return normalizeConfig(cfg), nil
}

func normalizeConfig(cfg Config) Config {
	if strings.TrimSpace(cfg.ManifestURL) == "" {
		cfg.ManifestURL = defaultManifestURL
	}
	if strings.TrimSpace(cfg.Channel) == "" {
		cfg.Channel = defaultChannel
	}
	if cfg.AutoUpdate == nil {
		enabled := true
		cfg.AutoUpdate = &enabled
	}
	return cfg
}

func (c Config) autoUpdate() bool {
	return c.AutoUpdate == nil || *c.AutoUpdate
}

func writeConfig(path string, cfg Config) error {
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644)
}

func executableDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate the launcher executable: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return filepath.Dir(exe), nil
}

// appDataDir returns the per-platform per-user data directory for MuMain.
func appDataDir() (string, error) {
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("LOCALAPPDATA")
		if base == "" {
			dir, err := os.UserConfigDir()
			if err != nil {
				return "", fmt.Errorf("LOCALAPPDATA is unset and no config dir is available: %w", err)
			}
			base = dir
		}
		return filepath.Join(base, "MuMain"), nil
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, "Library", "Application Support", "MuMain"), nil
	default:
		if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
			return filepath.Join(xdg, "mumain"), nil
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".local", "share", "mumain"), nil
	}
}

func readInstallState(appDir string) (installState, error) {
	raw, err := os.ReadFile(filepath.Join(appDir, installedStateName))
	if err != nil {
		return installState{}, err
	}
	var state installState
	if err := json.Unmarshal(raw, &state); err != nil {
		return installState{}, err
	}
	return state, nil
}

func writeInstallState(appDir string, state installState) error {
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return os.WriteFile(filepath.Join(appDir, installedStateName), raw, 0o644)
}

// fetchManifest downloads and parses the manifest. The raw bytes are returned
// unchanged so the caller can verify the signature over exactly what was
// served.
func fetchManifest(ctx context.Context, manifestURL string) (*Manifest, []byte, error) {
	if strings.TrimSpace(manifestURL) == "" {
		return nil, nil, errors.New("manifest URL is empty")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("build manifest request: %w", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch manifest: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("fetch manifest: unexpected status %s", resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, manifestSizeLimit))
	if err != nil {
		return nil, nil, fmt.Errorf("read manifest: %w", err)
	}
	manifest, err := parseManifest(raw)
	if err != nil {
		return nil, nil, err
	}
	return manifest, raw, nil
}

func parseManifest(raw []byte) (*Manifest, error) {
	var manifest Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if err := validateManifest(&manifest); err != nil {
		return nil, err
	}
	return &manifest, nil
}

func validateManifest(manifest *Manifest) error {
	if strings.TrimSpace(manifest.Version) == "" {
		return errors.New("manifest is missing version")
	}
	if len(manifest.Artifacts) == 0 {
		return errors.New("manifest has no artifacts")
	}
	return nil
}

// verifyManifestSignature enforces Ed25519 signing when a public key is
// configured. Empty LAUNCHER_SIGNING_PUBKEY selects unsigned mode.
func verifyManifestSignature(raw []byte, manifest *Manifest, logger *log.Logger) error {
	key := strings.TrimSpace(LAUNCHER_SIGNING_PUBKEY)
	if key == "" {
		unsignedWarnOnce.Do(func() {
			logger.Printf("warning: LAUNCHER_SIGNING_PUBKEY is empty; manifest signatures are not verified")
		})
		return nil
	}
	return verifySignature(raw, manifest.Signature, key)
}

// verifySignature validates a base64 Ed25519 signature over raw using an
// encoded public key (hex or standard base64).
func verifySignature(raw []byte, signatureB64, keyEncoded string) error {
	pub, err := decodeSigningKey(keyEncoded)
	if err != nil {
		return err
	}
	if strings.TrimSpace(signatureB64) == "" {
		return errors.New("manifest is not signed")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(signatureB64))
	if err != nil {
		return fmt.Errorf("decode manifest signature: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("manifest signature has %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pub, raw, sig) {
		return errors.New("manifest signature does not match")
	}
	return nil
}

func decodeSigningKey(encoded string) (ed25519.PublicKey, error) {
	if raw, err := hex.DecodeString(encoded); err == nil && len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(raw), nil
	}
	if raw, err := base64.StdEncoding.DecodeString(encoded); err == nil && len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(raw), nil
	}
	if raw, err := base64.RawStdEncoding.DecodeString(encoded); err == nil && len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(raw), nil
	}
	return nil, errors.New("LAUNCHER_SIGNING_PUBKEY must be a 32-byte Ed25519 key encoded as hex or standard base64")
}

// shouldUpdate reports whether the manifest carries a newer build than the
// installed one. Unparseable versions force an update.
func shouldUpdate(state installState, manifest *Manifest) bool {
	if state.Version == "" {
		return true
	}
	if state.Channel != "" && state.Channel != manifest.Channel {
		return true
	}
	current, okCurrent := parseVersion(state.Version)
	next, okNext := parseVersion(manifest.Version)
	if !okCurrent || !okNext {
		return true
	}
	return compareSemver(next, current) > 0
}

func parseVersion(raw string) (semver, bool) {
	value := strings.TrimSpace(raw)
	value = strings.TrimPrefix(value, "v")
	if value == "" {
		return semver{}, false
	}
	// Ignore pre-release and build metadata for the numeric comparison.
	if i := strings.IndexAny(value, "-+"); i >= 0 {
		value = value[:i]
	}
	parts := strings.Split(value, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return semver{}, false
	}
	var numbers [3]int
	for i, part := range parts {
		if part == "" {
			return semver{}, false
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return semver{}, false
		}
		numbers[i] = n
	}
	return semver{major: numbers[0], minor: numbers[1], patch: numbers[2]}, true
}

func compareSemver(a, b semver) int {
	switch {
	case a.major != b.major:
		return sign(a.major - b.major)
	case a.minor != b.minor:
		return sign(a.minor - b.minor)
	default:
		return sign(a.patch - b.patch)
	}
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

// normalizeOS maps manifest spelling onto runtime.GOOS spelling.
func normalizeOS(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "windows":
		return "windows"
	case "linux":
		return "linux"
	case "darwin", "macos", "mac", "osx":
		return "darwin"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

// normalizeArch maps manifest spelling onto runtime.GOARCH spelling.
func normalizeArch(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "amd64", "x64", "x86_64", "x86-64":
		return "amd64"
	case "arm64", "aarch64":
		return "arm64"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func artifactForRuntime(artifacts []Artifact, goos, goarch string) (*Artifact, error) {
	wantOS := normalizeOS(goos)
	wantArch := normalizeArch(goarch)
	for i := range artifacts {
		artifact := &artifacts[i]
		if artifact.Kind != "runtime" {
			continue
		}
		if normalizeOS(artifact.OS) != wantOS || normalizeArch(artifact.Arch) != wantArch {
			continue
		}
		return artifact, nil
	}
	return nil, fmt.Errorf("manifest has no runtime artifact for %s/%s", goos, goarch)
}

// applyUpdate downloads, verifies and activates the runtime artifact for the
// current platform.
func applyUpdate(logger *log.Logger, appDir string, manifest *Manifest) error {
	artifact, err := artifactForRuntime(manifest.Artifacts, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return err
	}
	if strings.TrimSpace(artifact.URL) == "" {
		return errors.New("runtime artifact has no download URL")
	}

	updatesDir := filepath.Join(appDir, "updates")
	if err := os.MkdirAll(updatesDir, 0o755); err != nil {
		return fmt.Errorf("create updates directory: %w", err)
	}
	versionSlug := sanitizeVersion(manifest.Version)
	archivePath := filepath.Join(updatesDir, versionSlug+".tar.gz")
	stagingDir := filepath.Join(updatesDir, versionSlug+".tmp")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	logger.Printf("downloading MuMain %s runtime from %s", manifest.Version, artifact.URL)
	if err := downloadAndVerify(ctx, artifact.URL, archivePath, artifact.Hash, artifact.Size); err != nil {
		_ = os.Remove(archivePath)
		return err
	}

	_ = os.RemoveAll(stagingDir)
	if err := os.MkdirAll(stagingDir, 0o755); err != nil {
		return fmt.Errorf("create staging directory: %w", err)
	}
	if err := extractArchive(archivePath, stagingDir); err != nil {
		_ = os.RemoveAll(stagingDir)
		return err
	}
	if err := swapInstall(appDir, stagingDir); err != nil {
		_ = os.RemoveAll(stagingDir)
		return err
	}
	_ = os.Remove(archivePath)
	logger.Printf("installed MuMain %s", manifest.Version)
	return nil
}

func extractArchive(archivePath, dest string) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer file.Close()
	if err := extractTarGz(file, dest); err != nil {
		return fmt.Errorf("extract %s: %w", filepath.Base(archivePath), err)
	}
	return nil
}

func downloadAndVerify(ctx context.Context, url, destPath, wantHash string, wantSize int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build download request: %w", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: unexpected status %s", url, resp.Status)
	}

	file, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("create download file: %w", err)
	}
	sum, written, copyErr := streamSHA256(file, resp.Body)
	closeErr := file.Close()
	if copyErr != nil {
		return fmt.Errorf("write download: %w", copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close download: %w", closeErr)
	}
	if err := verifyChecksum(sum, wantHash); err != nil {
		return err
	}
	if wantSize > 0 && written != wantSize {
		return fmt.Errorf("download size mismatch: got %d bytes, want %d", written, wantSize)
	}
	return nil
}

// streamSHA256 copies src into dst while hashing the bytes, so verification
// never needs a second pass over a large download.
func streamSHA256(dst io.Writer, src io.Reader) (string, int64, error) {
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(dst, hash), src)
	if err != nil {
		return "", written, err
	}
	return hex.EncodeToString(hash.Sum(nil)), written, nil
}

func verifyChecksum(actual, want string) error {
	want = strings.TrimSpace(want)
	if want == "" {
		return errors.New("artifact has no sha256 hash")
	}
	if !strings.EqualFold(strings.TrimSpace(actual), want) {
		return fmt.Errorf("sha256 mismatch: got %s, want %s", actual, want)
	}
	return nil
}

// extractTarGz safely unpacks a gzip-compressed tarball under dest.
func extractTarGz(reader io.Reader, dest string) error {
	gz, err := gzip.NewReader(reader)
	if err != nil {
		return fmt.Errorf("open gzip stream: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read tar entry: %w", err)
		}
		if err := extractEntry(tr, header, dest); err != nil {
			return err
		}
	}
}

func extractEntry(reader io.Reader, header *tar.Header, dest string) error {
	name := filepath.FromSlash(header.Name)
	if name == "" || name == "." {
		return nil
	}
	if filepath.IsAbs(name) || filepath.VolumeName(name) != "" {
		return fmt.Errorf("refusing absolute path %q", header.Name)
	}
	for _, part := range strings.Split(name, string(os.PathSeparator)) {
		if part == ".." {
			return fmt.Errorf("refusing path traversal %q", header.Name)
		}
	}

	target := filepath.Join(dest, name)
	if !isWithin(dest, target) {
		return fmt.Errorf("refusing path outside install root %q", header.Name)
	}
	if err := ensureNoSymlinkParents(dest, target); err != nil {
		return err
	}

	switch header.Typeflag {
	case tar.TypeDir:
		if err := os.MkdirAll(target, 0o755); err != nil {
			return fmt.Errorf("create directory %q: %w", header.Name, err)
		}
		return nil

	case tar.TypeReg, tar.TypeRegA:
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return fmt.Errorf("create parent directory for %q: %w", header.Name, err)
		}
		mode := sanitizeMode(header.Mode)
		file, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
		if err != nil {
			return fmt.Errorf("create file %q: %w", header.Name, err)
		}
		if _, err := io.Copy(file, reader); err != nil {
			file.Close()
			return fmt.Errorf("write file %q: %w", header.Name, err)
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("close file %q: %w", header.Name, err)
		}
		// umask can drop bits at create time; restore the archive mode on
		// platforms where executable bits matter.
		if runtime.GOOS != "windows" {
			if err := os.Chmod(target, mode); err != nil {
				return fmt.Errorf("set mode on %q: %w", header.Name, err)
			}
		}
		return nil

	case tar.TypeSymlink:
		linkTarget := filepath.FromSlash(header.Linkname)
		if !linkWithin(dest, target, linkTarget) {
			return fmt.Errorf("refusing symlink %q -> %q outside install root", header.Name, header.Linkname)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return fmt.Errorf("create parent directory for %q: %w", header.Name, err)
		}
		if err := os.Symlink(linkTarget, target); err != nil {
			return fmt.Errorf("create symlink %q: %w", header.Name, err)
		}
		return nil

	case tar.TypeLink:
		linkTarget := filepath.FromSlash(header.Linkname)
		if filepath.IsAbs(linkTarget) || filepath.VolumeName(linkTarget) != "" {
			return fmt.Errorf("refusing hardlink %q -> absolute %q", header.Name, header.Linkname)
		}
		source := filepath.Join(dest, linkTarget)
		if !isWithin(dest, source) {
			return fmt.Errorf("refusing hardlink %q -> %q outside install root", header.Name, header.Linkname)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return fmt.Errorf("create parent directory for %q: %w", header.Name, err)
		}
		if err := os.Link(source, target); err != nil {
			return fmt.Errorf("create hardlink %q: %w", header.Name, err)
		}
		return nil

	default:
		// Device nodes, FIFOs, character devices and other exotic entries
		// have no place in a runtime distribution; skip rather than create.
		return nil
	}
}

func sanitizeMode(mode int64) os.FileMode {
	perm := os.FileMode(mode) & os.ModePerm
	if perm == 0 {
		return 0o644
	}
	return perm
}

// isWithin reports whether target resolves under root.
func isWithin(root, target string) bool {
	root = filepath.Clean(root)
	target = filepath.Clean(target)
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	if filepath.IsAbs(rel) {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

// linkWithin validates a symlink's destination relative to the entry that owns
// it, rejecting absolute targets and anything escaping root.
func linkWithin(root, entryPath, linkTarget string) bool {
	if filepath.IsAbs(linkTarget) || filepath.VolumeName(linkTarget) != "" {
		return false
	}
	resolved := filepath.Clean(filepath.Join(filepath.Dir(entryPath), linkTarget))
	return isWithin(root, resolved)
}

// ensureNoSymlinkParents rejects writing through a symlinked parent directory,
// which would otherwise let a "safe" entry escape the extraction root.
func ensureNoSymlinkParents(root, target string) error {
	rel, err := filepath.Rel(root, filepath.Dir(target))
	if err != nil {
		return fmt.Errorf("resolve %q: %w", target, err)
	}
	if rel == "." {
		return nil
	}
	current := root
	for _, part := range strings.Split(rel, string(os.PathSeparator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect %q: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to write through symlink %q", current)
		}
	}
	return nil
}

// swapInstall atomically replaces games/ with stagedDir.
func swapInstall(appDir, stagedDir string) error {
	gamesDir := filepath.Join(appDir, "games")
	oldDir := filepath.Join(appDir, "games.old")

	if err := os.RemoveAll(oldDir); err != nil {
		return fmt.Errorf("remove stale previous install: %w", err)
	}
	hadPrevious := false
	if _, err := os.Stat(gamesDir); err == nil {
		if err := os.Rename(gamesDir, oldDir); err != nil {
			return fmt.Errorf("move current install aside: %w", err)
		}
		hadPrevious = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect current install: %w", err)
	}

	if err := os.Rename(stagedDir, gamesDir); err != nil {
		if hadPrevious {
			_ = os.Rename(oldDir, gamesDir)
		}
		return fmt.Errorf("activate new install: %w", err)
	}
	if hadPrevious {
		if err := os.RemoveAll(oldDir); err != nil {
			return fmt.Errorf("remove previous install: %w", err)
		}
	}
	return nil
}

func sanitizeVersion(version string) string {
	if strings.TrimSpace(version) == "" {
		return "unknown"
	}
	var builder strings.Builder
	for _, r := range version {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			builder.WriteRune(r)
		default:
			builder.WriteByte('_')
		}
	}
	return builder.String()
}

// clientBinaryPath returns the client executable inside the games directory.
func clientBinaryPath(gamesDir string) string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(gamesDir, "Main.exe")
	case "darwin":
		return filepath.Join(gamesDir, "Main.app", "Contents", "MacOS", "Main")
	default:
		return filepath.Join(gamesDir, "Main")
	}
}

func launchClient(logger *log.Logger, gamesDir string) int {
	binary := clientBinaryPath(gamesDir)
	info, err := os.Stat(binary)
	if err != nil {
		logger.Printf("client binary not found at %s: %v", binary, err)
		return 1
	}
	if info.IsDir() {
		logger.Printf("client path %s is a directory", binary)
		return 1
	}

	logger.Printf("starting %s", binary)
	command := exec.Command(binary)
	command.Dir = gamesDir
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		logger.Printf("client failed to start: %v", err)
		return 1
	}
	return 0
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
