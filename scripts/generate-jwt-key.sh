#!/bin/sh
# Generate the RS256 key pair used to sign access tokens.
#
#   ./scripts/generate-jwt-key.sh            # writes secrets/jwt-private.pem
#   JWT_KEY_ID=auth-2 ./scripts/generate-jwt-key.sh   # a fresh key under a new kid
#
# Only the private key is written: the backend derives the public half at
# start-up and publishes it at /api/auth/jwks, so there is one file to keep
# safe and no way for the two halves to drift apart.
#
# The private key never leaves the issuer. Everyone else verifies with the
# public JWKS, which is why an integrator cannot mint tokens for the others.
#
# Rotation: run this with a new JWT_KEY_ID, restart the backend with the new
# key active, and put the *old* public key into JWT_PREVIOUS_PUBLIC_KEYS for at
# least ACCESS_TOKEN_EXPIRE_MINUTES (15 min). Tokens signed before the switch
# keep verifying, so nobody is signed out:
#
#   openssl rsa -in secrets/jwt-private.pem.old -pubout    # the retired public key
#
# secrets/ is git-ignored. Do not copy the file into an image or a ConfigMap;
# mount it as a secret instead.

set -eu

KEY_ID="${JWT_KEY_ID:-auth-1}"
OUT_DIR="${JWT_OUT_DIR:-secrets}"
OUT_FILE="$OUT_DIR/jwt-private.pem"

if [ -e "$OUT_FILE" ]; then
    echo "refusing to overwrite $OUT_FILE" >&2
    echo "files signed with the current key are still valid; move it aside first:" >&2
    echo "  mv $OUT_FILE $OUT_FILE.old" >&2
    exit 1
fi

umask 077
mkdir -p "$OUT_DIR"

# The backend reads a PKCS#8 PEM; `genpkey` writes exactly that.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$OUT_FILE"

# The container runs as an unprivileged uid (10001) but a bind-mounted file
# keeps its host owner, so the key has to be group/other readable for it to be
# opened at all. That is a real trade-off: any local user on this host can read
# the signing key. Tighten it (JWT_KEY_MODE=0640 plus a shared group, matching
# `user:` in docker-compose.prod.yml) or keep the key in a proper secret store
# (Kubernetes Secret, Docker secret, Vault) for a real deployment.
chmod "${JWT_KEY_MODE:-0644}" "$OUT_FILE"

echo "wrote $OUT_FILE (kid: $KEY_ID)"
echo
echo "Set these where the backend runs:"
echo "  JWT_PRIVATE_KEY_PATH=$(pwd)/$OUT_FILE"
echo "  JWT_KEY_ID=$KEY_ID"
echo
echo "Public JWKS, once it is running:  curl -s http://localhost:8000/api/auth/jwks"
