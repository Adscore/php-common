<?php

namespace AdScore\Common\Struct;

use ErrorException;

/**
 * Msgpack serialization adapter
 *
 * @author Bartosz Derleta <bartosz@derleta.com>
 */
class Msgpack extends AbstractStruct {

    public const TYPE = 'M';

    public function __construct() {
        if (!extension_loaded('msgpack')) {
            throw new \RuntimeException('msgpack extension not loaded');
        }
        if ((PHP_OS_FAMILY === 'Windows') && (stripos(phpversion('msgpack'), '-debug') === false)) {
            /**
             * @see https://github.com/msgpack/msgpack-php/issues/163 - affects every version up to and including 2.2.0RC1 
             * @todo Verify whether it has been fixed and which version can be safely approved for use
             * */
            trigger_error('msgpack extension is not working properly on Windows', E_USER_WARNING);
        }
    }

    public function pack($data): string {
        $payload = \msgpack_pack($data);
        return parent::pack($payload);
    }

    public function unpack(string $data) {
        \error_clear_last();
        $structure = \msgpack_unpack(parent::unpack($data));
        if ($structure === false) {
            $lastError = \error_get_last();
            if ($lastError !== null) {
                throw new ErrorException($lastError['message'], 0, $lastError['type'], $lastError['file'], $lastError['line']);
            }
        }
        return $structure;
    }

}
