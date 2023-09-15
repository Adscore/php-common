<?php

namespace AdScore\Common\Struct;

use ErrorException;

/**
 * Native serialization adapter
 *
 * @author Bartosz Derleta <bartosz@derleta.com>
 */
class Serialize extends AbstractStruct {

    public const TYPE = 'S';

    /**
     * Generates a storable representation of a value
     * @param mixed $data
     * @return string
     */
    public function pack($data): string {
        $payload = \serialize($data);
        /* According to https://www.php.net/manual/en/function.serialize.php, it just can't fail */
        return parent::pack($payload);
    }

    /**
     * Creates a PHP value from a stored representation 
     * @param string $data
     * @return mixed
     * @throws ErrorException
     */
    public function unpack(string $data) {
        \error_clear_last();
        $structure = \unserialize(parent::unpack($data), ['allowed_classes' => false]);
        if ($structure === false) {
            $lastError = \error_get_last();
            if ($lastError !== null) {
                throw new ErrorException($lastError['message'], 0, $lastError['type'], $lastError['file'], $lastError['line']);
            }
        }
        return $structure;
    }

}
