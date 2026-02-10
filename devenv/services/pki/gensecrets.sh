#!/bin/sh
set -e

# --- CONFIG ---
COMPOSE_FILE="/work/${RESOLVED_DOCKER_COMPOSE}"
TARGET_DIR="/out"
CURVE_NAME="${PKI_CURVE}"

# CA paths
CA_KEY="$TARGET_DIR/CA.key"
CA_CERT="$TARGET_DIR/CA.crt"

# --- FUNCTIONS ---

ensure_ca() {
  if [ -f "$CA_KEY" ] && [ -f "$CA_CERT" ]; then
    echo "✅ CA exists."
  else
    echo "🔐 Generating CA ($CURVE_NAME)..."
    openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:$CURVE_NAME" \
      -out "$CA_KEY"

    # Create a persistent CA certificate
    openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days 3650 \
      -out "$CA_CERT" -subj "/CN=LuCI SSO Dev CA"
  fi
}

ensure_cert() {
  local FQDN=$1

  # We always add localhost to the SANs
  local SANS="DNS:${FQDN},DNS:localhost"

  # Check if files exist
  if [ -f "$TARGET_DIR/${FQDN}.crt" ] && [ -f "$TARGET_DIR/${FQDN}.key" ]; then
    echo "✅ Certificate for $FQDN exists. Skipping."
    return
  fi

  echo "⚙️  Generating certificate for: $FQDN (and localhost)"

  # 1. Generate Key
  openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:$CURVE_NAME" \
    -out "$TARGET_DIR/${FQDN}.key"

  # 2. Create Config for SANs
  # This ensures both the FQDN and localhost are valid for this cert
  cat >"$TARGET_DIR/${FQDN}.cnf" <<EOF
[req]
distinguished_name = dn
req_extensions = ext
prompt = no

[dn]
CN = $FQDN

[ext]
subjectAltName = $SANS
EOF

  # 3. Generate CSR
  openssl req -new -key "$TARGET_DIR/${FQDN}.key" \
    -out "$TARGET_DIR/${FQDN}.csr" \
    -config "$TARGET_DIR/${FQDN}.cnf"

  # 4. Sign with CA
  openssl x509 -req -in "$TARGET_DIR/${FQDN}.csr" \
    -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
    -out "$TARGET_DIR/${FQDN}.crt" -days 825 -sha256 \
    -extfile "$TARGET_DIR/${FQDN}.cnf" -extensions ext

  # Cleanup temp files
  rm "$TARGET_DIR/${FQDN}.csr" "$TARGET_DIR/${FQDN}.cnf"
}

# --- MAIN EXECUTION ---

ensure_ca

echo "🔎 Scanning $COMPOSE_FILE for 'cert.fqdn' labels..."

yq '.services[].labels."cert.fqdn" | select(. != null)' "$COMPOSE_FILE" | while read -r FQDN; do
  ensure_cert "$FQDN"
done

# Fix permissions
echo "🧹 Fixing permissions for UID $TARGET_UID..."
chown -R "$TARGET_UID:$TARGET_GID" "$TARGET_DIR"

echo "✨ Done!"
