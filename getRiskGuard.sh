#!/bin/sh
# getRiskGuard.sh — install the risk-guard binary from GitHub Releases.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Risk-Guard/oss-risk-guard/main/getRiskGuard.sh | sh
#
# Pin a version (positional arg or env var):
#   curl -fsSL .../getRiskGuard.sh | sh -s -- v0.0.2
#   curl -fsSL .../getRiskGuard.sh | RISK_GUARD_VERSION=v0.0.2 sh
#
# Choose an install dir (default: /usr/local/bin if writable/root, else ~/.local/bin):
#   curl -fsSL .../getRiskGuard.sh | RISK_GUARD_INSTALL_DIR="$HOME/bin" sh
#
# Supports Linux and macOS. On Windows, download the .zip from the Releases page.

set -eu

REPO="Risk-Guard/oss-risk-guard"
BINARY="risk-guard"

# Version: positional arg > env var > "latest".
VERSION="${1:-${RISK_GUARD_VERSION:-latest}}"
INSTALL_DIR="${RISK_GUARD_INSTALL_DIR:-}"

info() { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
err()  { printf 'error: %s\n' "$*" >&2; exit 1; }

# Fail with an explanation plus the go-install fallback, for machines that have
# no prebuilt binary (unknown OS/arch).
err_unsupported() {
	printf 'error: %s\n' "$*" >&2
	cat >&2 <<EOF

No prebuilt binary is published for this platform. If you have Go 1.25.1+ you can
build and install from source instead:

    go install github.com/$REPO/cmd/$BINARY@latest

See https://github.com/$REPO/releases for the platforms that ship prebuilt binaries.
EOF
	exit 1
}

# http_get URL          -> stdout
# download URL DEST     -> file
http_get() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget -qO- "$1"
	else
		err "need curl or wget to download files"
	fi
}

download() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL "$1" -o "$2"
	elif command -v wget >/dev/null 2>&1; then
		wget -qO "$2" "$1"
	else
		err "need curl or wget to download files"
	fi
}

# Exit early if risk-guard is already installed, unless RISK_GUARD_FORCE is set.
check_existing() {
	[ -n "${RISK_GUARD_FORCE:-}" ] && return 0

	existing="$(command -v "$BINARY" 2>/dev/null || true)"
	[ -n "$existing" ] || return 0

	info "$BINARY is already installed at $existing"
	"$existing" --version 2>/dev/null | head -n1 || true
	info "Set RISK_GUARD_FORCE=1 to reinstall or upgrade."
	exit 0
}

detect_platform() {
	os="$(uname -s)"
	arch="$(uname -m)"

	case "$os" in
		Linux)  os="linux" ;;
		Darwin) os="macos" ;;
		*) err_unsupported "unsupported OS '$os' (this installer supports Linux and macOS; on Windows download the .zip from the Releases page)" ;;
	esac

	case "$arch" in
		x86_64 | amd64)  arch="amd64" ;;
		arm64 | aarch64) arch="arm64" ;;
		armv7l | armv7)  arch="armv7" ;;
		*) err_unsupported "unsupported architecture '$arch'" ;;
	esac

	# Released macOS builds are amd64/arm64 only.
	if [ "$os" = "macos" ] && [ "$arch" = "armv7" ]; then
		err_unsupported "no macOS build for architecture '$arch'"
	fi

	PLATFORM="${os}-${arch}"
}

resolve_version() {
	if [ "$VERSION" = "latest" ]; then
		info "Resolving latest release..."
		resp="$(http_get "https://api.github.com/repos/$REPO/releases/latest")" \
			|| err "failed to query the GitHub API for the latest release"
		VERSION="$(printf '%s' "$resp" | grep -o '"tag_name": *"[^"]*"' | head -n1 | cut -d'"' -f4)"
		[ -n "$VERSION" ] || err "could not determine the latest release; set RISK_GUARD_VERSION to a tag like v0.0.2"
	fi
}

verify_checksum() {
	dir="$1"
	file="$2"

	if command -v sha256sum >/dev/null 2>&1; then
		sumtool="sha256sum"
	elif command -v shasum >/dev/null 2>&1; then
		sumtool="shasum -a 256"
	else
		warn "no sha256 tool found; skipping checksum verification"
		return 0
	fi

	if ! download "https://github.com/$REPO/releases/download/${VERSION}/checksums.txt" "$dir/checksums.txt" 2>/dev/null; then
		warn "checksums.txt not published for ${VERSION}; skipping checksum verification"
		return 0
	fi

	expected="$(awk -v f="$file" '$2 == f { print $1 }' "$dir/checksums.txt" | head -n1)"
	if [ -z "$expected" ]; then
		warn "no checksum entry for $file; skipping verification"
		return 0
	fi

	actual="$($sumtool "$dir/$file" | awk '{ print $1 }')"
	if [ "$expected" != "$actual" ]; then
		err "checksum mismatch for $file (expected $expected, got $actual)"
	fi
	info "Checksum verified."
}

choose_install_dir() {
	[ -n "$INSTALL_DIR" ] && return 0

	if [ "$(id -u)" = "0" ] || [ -w /usr/local/bin ]; then
		INSTALL_DIR="/usr/local/bin"
	else
		INSTALL_DIR="$HOME/.local/bin"
	fi
}

on_path() {
	case ":${PATH}:" in
		*":$1:"*) return 0 ;;
		*) return 1 ;;
	esac
}

main() {
	check_existing
	detect_platform
	resolve_version

	archive="${BINARY}-${VERSION}-${PLATFORM}.tar.gz"
	url="https://github.com/$REPO/releases/download/${VERSION}/${archive}"

	tmp="$(mktemp -d)"
	trap 'rm -rf "$tmp"' EXIT INT TERM

	info "Downloading $archive ..."
	download "$url" "$tmp/$archive" \
		|| err "download failed: $url (does release ${VERSION} have a ${PLATFORM} build?)"

	verify_checksum "$tmp" "$archive"

	tar -xzf "$tmp/$archive" -C "$tmp"
	[ -f "$tmp/$BINARY" ] || err "archive did not contain expected binary '$BINARY'"

	choose_install_dir
	mkdir -p "$INSTALL_DIR" || err "cannot create install dir $INSTALL_DIR"

	chmod +x "$tmp/$BINARY"
	mv -f "$tmp/$BINARY" "$INSTALL_DIR/$BINARY" \
		|| err "cannot write to $INSTALL_DIR (set RISK_GUARD_INSTALL_DIR to a writable dir, or re-run with sudo)"

	info "Installed $BINARY ${VERSION} to $INSTALL_DIR/$BINARY"

	if ! on_path "$INSTALL_DIR"; then
		warn "$INSTALL_DIR is not on your PATH. Add it, e.g.:"
		printf '         export PATH="%s:$PATH"\n' "$INSTALL_DIR" >&2
	fi

	"$INSTALL_DIR/$BINARY" --version || true
}

main "$@"
