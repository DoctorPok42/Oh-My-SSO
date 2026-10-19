# Test SAML service provider for Step 11: SimpleSAMLphp, configured to sign in
# through Oh-My-SSO. DEVELOPMENT ONLY (plain HTTP, debug logs, fixed salt).
#
#   make saml-sp            build and run it on http://localhost:8081
#   make saml-sp-register   register it in the realm (reads its metadata)
#
# Then open http://localhost:8081/app.php
# SimpleSAMLphp SP documentation: https://simplesamlphp.org/docs/stable/saml/sp.html

FROM php:8.3-cli

# The "full" release already contains its PHP dependencies (vendor/), so no
# composer is needed. The checksum is the one published on
# https://simplesamlphp.org/download/
ARG SSP_VERSION=2.5.3.1
ARG SSP_SHA256=b199ebcba6e30220e7b5df2783ca42f8947dd9bdf046e9e6302fef3d3a438d01

# bcmath: required by simplesamlphp/xml-common. openssl: creates the SP key.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl \
 && rm -rf /var/lib/apt/lists/* \
 && docker-php-ext-install bcmath

WORKDIR /var/simplesamlphp
RUN curl -fsSL -o /tmp/ssp.tar.gz \
      "https://github.com/simplesamlphp/simplesamlphp/releases/download/v${SSP_VERSION}/simplesamlphp-${SSP_VERSION}-full.tar.gz" \
 && echo "${SSP_SHA256}  /tmp/ssp.tar.gz" | sha256sum -c - \
 && tar -xzf /tmp/ssp.tar.gz --strip-components=1 \
 && rm /tmp/ssp.tar.gz \
 && chown www-data cert

COPY config/config.php config/authsources.php config/
COPY public/app.php public/
COPY start.sh /usr/local/bin/oh-my-sso-test-sp
RUN chmod 0755 /usr/local/bin/oh-my-sso-test-sp

# Values used by config.php and authsources.php (override with docker run -e).
# host.docker.internal is the host machine seen from the container (on Linux,
# docker run needs --add-host=host.docker.internal:host-gateway).
ENV SP_PORT=8081 \
    IDP_METADATA_URL=http://host.docker.internal:8080/r/demo/saml/metadata \
    IDP_ENTITY_ID=http://localhost:8080/r/demo/saml/metadata

# The SP key pair (created by start.sh on the first start).
VOLUME /var/simplesamlphp/cert

USER www-data
EXPOSE 8081
CMD ["oh-my-sso-test-sp"]
