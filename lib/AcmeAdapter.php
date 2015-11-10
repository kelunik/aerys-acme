<?php

namespace Aerys\Acme;

use Amp\File\FilesystemException;
use Amp\Promise;
use Amp\Success;
use Generator;
use Kelunik\Acme\AcmeAdapter as Adapter;
use Kelunik\Acme\KeyPair;
use function Amp\File\get;
use function Amp\File\put;
use function Amp\File\unlink;
use function Amp\resolve;

class AcmeAdapter implements Adapter {
    private $configPath;

    public function __construct(string $configPath) {
        $this->configPath = $configPath;
    }

    public function getCertificatePath(string $dns): Promise {
        return new Success($this->configPath . "/live/{$dns}.pem");
    }

    public function provideChallenge(string $dns, string $token, string $payload): Promise {
        return resolve($this->doProvideChallenge($dns, $token, $payload));
    }

    private function doProvideChallenge(string $dns, string $token, string $payload) {
        yield put($this->configPath . "/challenges/{$dns}/.well-known/acme-challenge/{$token}", $payload);
    }

    public function cleanUpChallenge(string $dns, string $token): Promise {
        return resolve($this->doCleanUpChallenge($dns, $token));
    }

    private function doCleanUpChallenge(string $dns, string $token): Generator {
        try {
            yield unlink($this->configPath . "/challenges/{$dns}/.well-known/acme-challenge/{$token}");
        } catch (FilesystemException $e) {
            // ignore, creation may already have failed
        }
    }

    public function getKeyPair(string $dns): Promise {
        return resolve($this->doGetKeyPair($dns));
    }

    private function doGetKeyPair(string $dns): Generator {
        return new KeyPair(
            yield get($this->configPath . "/keys/{$dns}/private.pem"),
            yield get($this->configPath . "/keys/{$dns}/public.pem")
        );
    }
}