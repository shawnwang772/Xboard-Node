#!/usr/bin/env bash
# Backport the safe built-in CA trust store from Xray-core v26.10.21
# while retaining cedar2025's custom dispatcher/bandwidth APIs.
set -euo pipefail

XRAY_DIR="${1:-xray-src}"
PINNED_XRAY_COMMIT="f479355399657c0ed07b3e8ac33e02f727094188"
PINNED_CA_BUNDLE="v0.0.0-20261020153306-9f2b28d4331a"

actual_commit="$(git -C "$XRAY_DIR" rev-parse HEAD)"
if [[ "$actual_commit" != "$PINNED_XRAY_COMMIT" ]]; then
  echo "Refusing to patch an unexpected Xray-core revision: $actual_commit" >&2
  exit 1
fi

cat > "$XRAY_DIR/transport/internet/tls/config_other.go" <<'GO'
//go:build !windows

package tls

import (
    "crypto/x509"
    "sync"

    "github.com/xtls/xray-core/common/errors"
    "golang.org/x/crypto/x509roots/fallback/bundle"
)

// This is the trust-root behavior of Xray-core v26.10.21:
// use the updated, pinned CA bundle by default, rather than potentially
// stale system trust roots. The Xboard-specific Xray patches remain intact.
var xboardPatchedRootCertPool = sync.OnceValue(func() *x509.CertPool {
    pool := x509.NewCertPool()
    for root := range bundle.Roots() {
        cert, err := x509.ParseCertificate(root.Certificate)
        if err != nil {
            continue
        }
        if root.Constraint != nil {
            pool.AddCertWithConstraint(cert, root.Constraint)
        } else {
            pool.AddCert(cert)
        }
    }
    return pool
})

func (c *Config) getCertPool() (*x509.CertPool, error) {
    if c.DisableSystemRoot {
        return c.loadSelfCertPool()
    }

    if len(c.Certificate) == 0 {
        return xboardPatchedRootCertPool(), nil
    }

    pool := xboardPatchedRootCertPool().Clone()
    for _, cert := range c.Certificate {
        if !pool.AppendCertsFromPEM(cert.Certificate) {
            return nil, errors.New("append cert to root")
        }
    }
    return pool, nil
}
GO

(
  cd "$XRAY_DIR"
  go mod edit -require="golang.org/x/crypto/x509roots/fallback@$PINNED_CA_BUNDLE"
  gofmt -w transport/internet/tls/config_other.go
)
echo "Backported safe Xray-core v26.10.21 root trust bundle to $XRAY_DIR"
