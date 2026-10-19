<?php

/*
 * The test service provider "default-sp" (Step 11). DEVELOPMENT ONLY.
 * Options: https://simplesamlphp.org/docs/stable/saml/sp.html
 */

$port = getenv('SP_PORT') ?: '8081';
$base = rtrim(getenv('SP_BASE_URL') ?: 'http://localhost:' . $port . '/', '/');

$config = [
    // The admin pages of SimpleSAMLphp log in with auth.adminpassword.
    'admin' => ['core:AdminPassword'],

    'default-sp' => [
        'saml:SP',

        // Our name for Oh-My-SSO. By convention, the URL of our own metadata.
        'entityID' => $base . '/module.php/saml/sp/metadata/default-sp',

        // The IdP: entityID of the Oh-My-SSO realm = PUBLIC_URL/r/<realm>/saml/metadata.
        'idp' => getenv('IDP_ENTITY_ID') ?: 'http://localhost:8080/r/demo/saml/metadata',

        // Our key pair (generated when the image is built, see the Dockerfile).
        // Its certificate is in our metadata: Oh-My-SSO imports it and then
        // requires our AuthnRequest and LogoutRequest to be signed with it.
        'privatekey' => 'sp.key',
        'certificate' => 'sp.crt',
        'sign.authnrequest' => true,
        'sign.logout' => true,
        'redirect.sign' => true,
        'signature.algorithm' => 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',

        // Refuse unsigned logout messages from the IdP.
        'validate.logout' => true,

        // A stable identifier per user (Oh-My-SSO: the user's public subject).
        'NameIDPolicy' => [
            'Format' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
            'AllowCreate' => true,
        ],

        'name' => ['en' => 'Oh-My-SSO test SP'],
    ],
];
