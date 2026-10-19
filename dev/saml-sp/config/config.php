<?php

/*
 * SimpleSAMLphp configuration of the Oh-My-SSO test service provider (Step 11).
 * DEVELOPMENT ONLY: fixed salt, plain HTTP, debug logs.
 *
 * Every option not listed here keeps the SimpleSAMLphp default, see
 * config/config.php.dist in the release or
 * https://simplesamlphp.org/docs/stable/simplesamlphp-install.html
 */

$port = getenv('SP_PORT') ?: '8081';

$config = [
    // Where the browser reaches this SP. The test SP serves SimpleSAMLphp's
    // public/ directory at the root of http://localhost:8081.
    'baseurlpath' => getenv('SP_BASE_URL') ?: 'http://localhost:' . $port . '/',

    // Used to compute hashes (e.g. NameID-derived values). A fixed value is
    // fine for a throwaway test SP, never in a real deployment.
    'secretsalt' => getenv('SP_SECRET_SALT') ?: 'oh-my-sso-test-sp-not-a-secret',

    // Password of the SimpleSAMLphp admin pages (/admin), dev only.
    'auth.adminpassword' => getenv('SP_ADMIN_PASSWORD') ?: 'admin',

    'technicalcontact_name' => 'Oh-My-SSO developers',
    'technicalcontact_email' => 'dev@localhost.invalid',
    'timezone' => 'UTC',

    // Logs on the container output, with every SAML message (decoded).
    'logging.level' => SimpleSAML\Logger::DEBUG,
    'logging.handler' => 'stderr',
    'debug' => ['saml' => true, 'backtraces' => true, 'validatexml' => false],
    'showerrors' => true,
    'errorreporting' => false,

    // Sessions in PHP files (enough for one process), caches in /tmp.
    'store.type' => 'phpsession',
    'tempdir' => sys_get_temp_dir() . '/simplesamlphp',
    'cachedir' => sys_get_temp_dir() . '/simplesamlphp-cache',
    // Plain HTTP on localhost: the cookie cannot be "Secure", so it cannot be
    // SameSite=None either. Lax works because localhost:8080 (IdP) and
    // localhost:8081 (SP) are the same site (ports do not count).
    'session.cookie.secure' => false,
    'session.cookie.samesite' => 'Lax',
    'language.cookie.samesite' => 'Lax',
    // Cookies ignore ports: two test SPs on localhost (8081 and 8082, to try
    // the Single Logout chain) need different cookie names.
    'session.cookie.name' => 'SimpleSAMLSessionID' . $port,
    'session.phpsession.cookiename' => 'SimpleSAML' . $port,
    'session.authtoken.cookiename' => 'SimpleSAMLAuthToken' . $port,

    // This instance is only a service provider.
    'enable.saml20-idp' => false,
    'module.enable' => [
        'admin' => true,
        'core' => true,
        'saml' => true,
        'exampleauth' => false,
    ],

    // The IdP metadata is downloaded from Oh-My-SSO on every request (no
    // cache): after a key rotation, the SP sees the new certificate at once.
    // In the container, the IdP is reached through host.docker.internal.
    'metadata.sources' => [
        ['type' => 'xml', 'url' => getenv('IDP_METADATA_URL') ?: 'http://localhost:8080/r/demo/saml/metadata'],
    ],
];
