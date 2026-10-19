<?php

/*
 * The "application" protected by the test service provider (Step 11).
 * DEVELOPMENT ONLY.
 *
 *   /app.php           sign in through Oh-My-SSO (SP-initiated SSO), then
 *                      show what the assertion contained
 *   /app.php?logout=1  Single Logout through Oh-My-SSO
 *
 * API: https://simplesamlphp.org/docs/stable/simplesamlphp-sp-api.html
 */

require_once dirname(__DIR__) . '/src/_autoload.php';

$as = new \SimpleSAML\Auth\Simple('default-sp');
$self = '/app.php';

if (isset($_GET['logout'])) {
    // Sends a signed LogoutRequest to the IdP; comes back here after.
    $as->logout(['ReturnTo' => $self . '?loggedout=1']);
}

$h = fn ($s) => htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');

if (!$as->isAuthenticated()) {
    $title = isset($_GET['loggedout']) ? 'Signed out' : 'Not signed in';
    $login = $as->getLoginURL($self);
    echo "<!doctype html><meta charset=utf-8><title>Test SP</title>",
        "<h1>{$title}</h1><p><a href=\"{$h($login)}\">Sign in with Oh-My-SSO</a></p>";
    exit;
}

$nameId = $as->getAuthData('saml:sp:NameID');
$rows = '';
foreach ($as->getAttributes() as $name => $values) {
    $rows .= '<tr><th>' . $h($name) . '</th><td>' . $h(implode(', ', $values)) . '</td></tr>';
}
$expire = $as->getAuthData('Expire');

echo "<!doctype html><meta charset=utf-8><title>Test SP</title>",
    "<h1>Signed in</h1>",
    "<p>The assertion from Oh-My-SSO was accepted: this SP has an open session.</p>",
    "<table border=1 cellpadding=4>",
    "<tr><th>IdP</th><td>{$h($as->getAuthData('saml:sp:IdP'))}</td></tr>",
    "<tr><th>NameID</th><td>{$h($nameId ? $nameId->getValue() : '')}</td></tr>",
    "<tr><th>NameID format</th><td>{$h($nameId ? $nameId->getFormat() : '')}</td></tr>",
    "<tr><th>SessionIndex</th><td>{$h($as->getAuthData('saml:sp:SessionIndex'))}</td></tr>",
    "<tr><th>AuthnContext</th><td>{$h($as->getAuthData('saml:sp:AuthnContext'))}</td></tr>",
    "<tr><th>Session ends</th><td>{$h($expire ? gmdate('c', $expire) : '')}</td></tr>",
    "</table><h2>Attributes</h2><table border=1 cellpadding=4>{$rows}</table>",
    "<p><a href=\"{$h($self)}?logout=1\">Sign out (Single Logout)</a></p>";
