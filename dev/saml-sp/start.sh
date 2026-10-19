#!/bin/sh
# Starts the test service provider (runs inside the container, see Dockerfile).
# DEVELOPMENT ONLY.
set -eu
cd "${SSP_DIR:-/var/simplesamlphp}"

# The SP key pair is created on the first start and kept in the cert/ volume,
# so it survives image rebuilds: Oh-My-SSO keeps trusting the same certificate.
if [ ! -f cert/sp.key ]; then
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 825 \
    -subj "/CN=Oh-My-SSO test SP ${SP_PORT}" -keyout cert/sp.key -out cert/sp.crt 2>/dev/null
  echo "test SP: new key pair created (cert/sp.crt)"
fi

echo "test SP: http://localhost:${SP_PORT}/app.php"
echo "test SP: metadata http://localhost:${SP_PORT}/module.php/saml/sp/metadata/default-sp"
echo "test SP: Oh-My-SSO metadata read from ${IDP_METADATA_URL}"
# PHP's built-in web server: enough for one developer.
exec php -S "0.0.0.0:${SP_PORT}" -t public
