# aerys-acme

ACME is a protocol to automate certificate issuance and renewal. [Aerys](https://github.com/amphp/aerys) provides a feature to encrypt hosts automatically using ACME.

## installation

```
composer require kelunik/aerys-acme:dev-master
```

## usage

```php
<?php

use Aerys\Acme\AcmeHost;
use Aerys\Host;

const LETS_ENCRYPT_AGREEMENT = "https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf";
const LETS_ENCRYPT_STAGING = "https://acme-staging.api.letsencrypt.org/directory";
const LETS_ENCRYPT_BETA = "https://acme-v01.api.letsencrypt.org/directory";

$https = (new Host)
    ->expose("*", 443)
    ->name("example.com");

// Currently we need a redirect, because the spec requires
// the initial HTTP challenge to use HTTP instead of HTTPS.
// If you don't want to redirect all traffic, just redirect
// everything starting with "/.well-known/acme-challenge/".
$http = (new Host)
    ->expose("*", 80)
    ->name("example.com")
    ->redirect("https://example.com");

// this will issue a test certificate, see below
return (new AcmeHost($https, __DIR__ . "/ssl"))
    ->acceptAgreement(LETS_ENCRYPT_AGREEMENT)
    ->encrypt(LETS_ENCRYPT_STAGING, ["mailto:me@example.com"]);

// if your domain is already whitelisted for Let's Encrypt's closed beta,
// use the right server to obtain a real certificate
// return (new AcmeHost($https, __DIR__ . "/ssl"))
//    ->acceptAgreement(LETS_ENCRYPT_AGREEMENT)
//    ->encrypt(LETS_ENCRYPT_BETA, ["mailto:me@example.com"]);
```
