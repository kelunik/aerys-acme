<?php

namespace Aerys\Acme;

use Aerys\Bootable;
use Aerys\Host;
use Aerys\Logger;
use Aerys\Server;
use Amp\File\FilesystemException;
use Amp\Pause;
use Amp\Promise;
use BenConstable\Lock\Exception\LockException;
use BenConstable\Lock\Lock;
use Exception;
use Generator;
use Kelunik\Acme\AcmeClient;
use Kelunik\Acme\AcmeException;
use Kelunik\Acme\AcmeService;
use Kelunik\Acme\KeyPair;
use Kelunik\Acme\OpenSSLKeyGenerator;
use Throwable;
use function Aerys\root;
use function Amp\File\exists;
use function Amp\File\get;
use function Amp\File\put;
use function Amp\File\unlink;
use function Amp\resolve;

class AcmeHost implements Bootable {
    private $host;
    private $path;
    private $onBoot;
    private $agreement;
    private $showActionWarning;
    private $logger;

    public function __construct(Host $host, string $path) {
        $this->checkValidity($host);
        $this->host = $host;
        $this->path = $path;
        $this->showActionWarning = false;
        $this->agreement = null;
    }

    private function checkValidity(Host $host) {
        $details = $host->export();

        if (!$this->isListeningOn(443, $details["interfaces"])) {
            throw new \InvalidArgumentException("Host isn't listening on port 443, host not allowed!");
        }

        if (!empty($details["crypto"])) {
            throw new \InvalidArgumentException("Host must not have crypto settings already!");
        }

        if (empty($details["actions"])) {
            $this->showActionWarning = true;
        }
    }

    private function isListeningOn(int $port, array $interfaces) {
        foreach ($interfaces as list($ip, $iPort)) {
            if ($iPort === $port) {
                return true;
            }
        }

        return false;
    }

    public function boot(Server $server, Logger $logger) {
        $this->logger = $logger;

        if ($this->showActionWarning) {
            $logger->warning("No actions registered for \$host yet, be sure to add them before injecting Host to AcmeHost for best performance.");
        }

        $server->attach(new StartEvent($this->onBoot));
    }

    public function acceptAgreement(string $agreement): self {
        $this->agreement = $agreement;

        return $this;
    }

    public function encrypt(string $acmeServer, array $contact) {
        return resolve($this->doEncrypt($acmeServer, $contact));
    }

    private function doEncrypt(string $acmeServer, array $contact): Generator {
        $domain = strtok(str_replace("https://", "", $acmeServer), "/");
        $info = $this->host->export();
        $dns = $info["name"];

        $this->mkdirs(
            $this->path . "/accounts/{$domain}",
            $this->path . "/keys/{$dns}",
            $this->path . "/live",
            $this->path . "/challenges/{$dns}/.well-known/acme-challenge"
        );

        $this->host->use(root($this->path . "/challenges/{$dns}"));
        $this->host->use($this);

        $accountKeyPair = yield $this->loadKeyPair($this->path . "/accounts/{$domain}");
        $domainKeyPair = yield $this->loadKeyPair($this->path . "/keys/{$dns}");

        $certificateService = new AcmeService(new AcmeClient($acmeServer, $accountKeyPair), $accountKeyPair, new AcmeAdapter($this->path));
        list($selfSigned, $lifetime) = yield $certificateService->getCertificateData($dns);

        if ($lifetime > 30 * 24 * 60 * 60 && !$selfSigned) { // valid for more than 30 days and not self signed
            $this->host->encrypt($this->path . "/live/{$dns}.pem");

            // TODO Add timer to renew certificate!

            return;
        }

        try {
            yield put($this->path . "/live/{$dns}.lock", $dns);
        } catch (FilesystemException $e) {
        }

        $lock = new Lock($this->path . "/live/{$dns}.lock");

        try {
            $lock->acquire();

            if ($lifetime < 1 || $selfSigned) { // don't touch valid certificate here if still in place.
                $privateKey = openssl_pkey_get_private($domainKeyPair->getPrivate());

                $csr = openssl_csr_new([
                    "commonName" => $dns,
                    "organizationName" => "kelunik/aerys-acme",
                ], $privateKey, ["digest_alg" => "sha256"]);

                if (!$csr) {
                    throw new AcmeException("CSR couldn't be generated!");
                }

                $privateCertificate = openssl_csr_sign($csr, null, $privateKey, 90, ["digest_alg" => "sha256"], random_int(0, PHP_INT_MAX));
                openssl_x509_export($privateCertificate, $cert);

                file_put_contents($this->path . "/live/{$dns}.pem", implode("\n", [
                    $domainKeyPair->getPrivate(),
                    $cert,
                ]));
            }

            $this->host->encrypt($this->path . "/live/{$dns}.pem");

            $this->onBoot = function (Server $server) use ($certificateService, $dns, $contact, $lock) {
                $certificateService->issueCertificate($dns, $contact, $this->agreement)->when(function (Throwable $error = null) use ($server, $lock, $dns) {
                    $lock->release();
                    unlink($this->path . "/live/{$dns}.lock");

                    if ($error) {
                        $this->logger->emergency($error);
                        // $server->stop();
                    }
                });
            };
        } catch (LockException $e) {
            do {
                yield new Pause(500);
            } while (!yield exists($this->path . "/live/{$dns}.pem"));

            $this->host->encrypt($this->path . "/live/{$dns}.pem");
        }
    }

    private function mkdirs(string ...$path) {
        foreach ($path as $p) {
            file_exists($p) or @mkdir($p, 0700, true);
        }
    }

    private function loadKeyPair(string $path): Promise {
        return resolve($this->doLoadKeyPair($path));
    }

    private function doLoadKeyPair(string $path): Generator {
        $privateExists = yield exists("{$path}/private.pem");
        $publicExists = yield exists("{$path}/public.pem");
        $lockExists = yield exists("{$path}/key.lock");

        if ($privateExists && $publicExists) {
            while ($lockExists) {
                yield new Pause(500);
                $lockExists = yield exists("{$path}/key.lock");
            }

            return new KeyPair(
                yield get("{$path}/private.pem"),
                yield get("{$path}/public.pem")
            );
        }

        $lock = new Lock("{$path}/key.lock");

        try {
            $lock->acquire();

            $gen = new OpenSSLKeyGenerator;
            $keyPair = $gen->generate(4096);

            yield put("{$path}/private.pem", $keyPair->getPrivate());
            yield put("{$path}/public.pem", $keyPair->getPublic());

            return $keyPair;
        } catch (Exception $e) {
            do {
                yield new Pause(500);
                $lockExists = yield exists("{$path}/key.lock");
            } while ($lockExists);

            return new KeyPair(
                yield get("{$path}/private.pem"),
                yield get("{$path}/public.pem")
            );
        } finally {
            $lock->release();

            unlink("{$path}/key.lock"); // do not yield in finally!
        }
    }
}