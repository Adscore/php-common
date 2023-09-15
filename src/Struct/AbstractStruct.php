<?php

namespace AdScore\Common\Struct;

/**
 * Common base for serialization/deserialization methods
 * 
 * @author Bartosz Derleta <bartosz@derleta.com>
 */
abstract class AbstractStruct {

    /**
     * Packs structure into serialized format
     * @param mixed $data
     * @return string
     */
    public function pack($data): string {
        return static::TYPE . $data;
    }

    /**
     * Unpacks structure from serialized format
     * @param string $data
     * @return mixed
     */
    public function unpack(string $data) {
        if (\strpos($data, static::TYPE) !== 0) {
            throw new \RuntimeException('Unexpected serializer type');
        }
        return \substr($data, \strlen(static::TYPE));
    }

}
