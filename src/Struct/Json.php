<?php

namespace AdScore\Common\Struct;

/**
 * JSON serialization adapter
 *
 * @author Bartosz Derleta <bartosz@derleta.com>
 */
class Json extends AbstractStruct {

    public const TYPE = 'J';

    public function __construct() {
        if (!extension_loaded('json')) {
            throw new \RuntimeException('json extension not loaded');
        }
    }

    /**
     * Returns the JSON representation of a value
     * @param mixed $data
     * @return string
     */
    public function pack($data): string {
        $payload = \json_encode($data, JSON_THROW_ON_ERROR);
        return parent::pack($payload);
    }

    /**
     * Takes a JSON encoded string and converts it into a PHP value
     * @param string $data
     * @return mixed
     */
    public function unpack(string $data) {
        $structure = \json_decode(parent::unpack($data), true, 512, JSON_THROW_ON_ERROR);
        return $structure;
    }

}
