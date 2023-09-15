<?php

namespace AdScore\Common\Struct;

use ErrorException;

/**
 * Igbinary serialization adapter
 *
 * @author Bartosz Derleta <bartosz@derleta.com>
 */
class Igbinary extends AbstractStruct {

    public const TYPE = 'I';

    public function __construct() {
        if (!extension_loaded('igbinary')) {
            throw new \RuntimeException('igbinary extension not loaded');
        }
    }

    public function pack($data): string {
        $payload = \igbinary_serialize($data);
        return parent::pack($payload);
    }

    public function unpack(string $data) {
        error_clear_last();
        $structure = \igbinary_unserialize(parent::unpack($data));
        if ($structure === false) {
            $lastError = error_get_last();
            if ($lastError !== null) {
                throw new ErrorException($lastError['message'], 0, $lastError['type'], $lastError['file'], $lastError['line']);
            }
        }
        return $structure;
    }

}
