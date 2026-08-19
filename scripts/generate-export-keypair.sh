#!/usr/bin/env bash
# Generates a LOCAL Ed25519 export-signing keypair (PEM). The PRIVATE key must NEVER be
# committed; only the PUBLIC key may be shared/committed. For production use a managed KMS
# instead of a file on disk.
#
# Usage:
#   scripts/generate-export-keypair.sh [output-dir]
#
# Then point the service at the private key:
#   export AUDIT_EXPORT_PRIVATE_KEY_PATH=<output-dir>/export_ed25519_private.pem
#   export AUDIT_EXPORT_PUBLIC_KEY_PATH=<output-dir>/export_ed25519_public.pem
set -euo pipefail

OUT_DIR="${1:-dev-keys}"
mkdir -p "$OUT_DIR"
PRIV="$OUT_DIR/export_ed25519_private.pem"
PUB="$OUT_DIR/export_ed25519_public.pem"

if [ -f "$PRIV" ]; then
  echo "Refusing to overwrite existing private key: $PRIV" >&2
  exit 1
fi

# Ed25519 PKCS#8 private key + X.509 public key via OpenSSL.
openssl genpkey -algorithm ed25519 -out "$PRIV"
openssl pkey -in "$PRIV" -pubout -out "$PUB"

chmod 600 "$PRIV"
echo "Wrote:"
echo "  private (KEEP SECRET, do not commit): $PRIV"
echo "  public  (safe to share/commit):       $PUB"
echo ""
echo "The .gitignore ignores private keys; commit ONLY the public key if you wish to publish it."
