<?php

namespace AdScore\Common\Struct;

/**
 * @author Bartosz Derleta <bartosz@derleta.com>
 */
class StructFactory {

    /**
     * Return Struct class
     * @param string $name
     * @return AbstractStruct
     * @throws \InvalidArgumentException
     */
    public static function create(string $name): AbstractStruct {
        switch ($name) {
            case Serialize::TYPE:
            case 'Serialize':
            case 'serialize':
                return new Serialize();
            case Igbinary::TYPE:
            case 'Igbinary':
            case 'igbinary':
                return new Igbinary();
            case Msgpack::TYPE:
            case 'Msgpack':
            case 'msgpack':
                return new Msgpack();
            case Json::TYPE:
            case 'Json':
            case 'json':
                return new Json();
            case Rfc3986::TYPE:
            case 'Rfc3986':
            case 'rfc3986':
                return new Rfc3986();            
            default:
                throw new \InvalidArgumentException('Unsupported struct class');
        }
    }

    /**
     * Returns Struct class basing on payload
     * @param string $payload
     * @return AbstractStruct
     */
    public static function createFromPayload(string $payload): AbstractStruct {
        $header = \substr($payload, 0, 1);
        return self::create($header);
    }

}
