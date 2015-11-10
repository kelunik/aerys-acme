<?php

namespace Aerys\Acme;

use Aerys\Server;
use Aerys\ServerObserver;
use Amp\Promise;
use Amp\Success;

class StartEvent implements ServerObserver {
    private $callable;

    public function __construct(callable $callable = null) {
        $this->callable = $callable;
    }

    public function update(Server $server): Promise {
        if ($server->state() === Server::STARTED) {
            if ($this->callable) {
                $callable = $this->callable;
                $return = $callable($server);

                if ($return instanceof Promise) {
                    return $return;
                } else {
                    return new Success;
                }
            }
        }

        return new Success;
    }
}