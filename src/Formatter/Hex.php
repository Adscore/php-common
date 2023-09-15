<?php

namespace AdScore\Common\Formatter;

/**
 * Generic hexadecimal formatter
 *
 * @author Bartosz Derleta <bartosz@derleta.com>
 */
class Hex extends AbstractFormatter {

    /**
     * Convert binary data into hexadecimal representation (byte-wise with the high-nibble first)
     * @param string $value
     * @return string
     */
    public function format(string $value): string {
        return \bin2hex($value);
    }

    /**
     * Decodes a hexadecimally encoded binary string
     * @param string $value
     * @return string
     */
    public function parse(string $value): string {
        $binary = \hex2bin($value);
        if ($binary === false) {
            throw new \InvalidArgumentException('Not a valid hexadecimal value');
        }
        return $binary;
    }

}
