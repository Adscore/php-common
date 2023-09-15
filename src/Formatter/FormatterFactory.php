<?php

namespace AdScore\Common\Formatter;

/**
 * Formatter Factory
 *
 * @author Bartosz Derleta <bartosz@derleta.com>
 */
class FormatterFactory {

    /**
     * Return Formatter class
     * @param string $name
     * @return AbstractFormatter
     * @throws \InvalidArgumentException
     */
    public static function create(string $name): AbstractFormatter {
        switch ($name) {
            case 'base64':
                try {
                    return new SodiumBase64();
                } catch (\RuntimeException $ex) {
                    return new Base64();
                }
            case 'hex':
                try {
                    return new SodiumHex();
                } catch (\RuntimeException $ex) {
                    return new Hex();
                }
            default:
                throw new \InvalidArgumentException('Unsupported formatter class');
        }
    }

}
