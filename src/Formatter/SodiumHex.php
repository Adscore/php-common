<?php

namespace AdScore\Common\Formatter;

/**
 * Hexadecimal formatter using Sodium library
 *
 * @author Bartosz Derleta <bartosz@derleta.com>
 */
class SodiumHex extends AbstractFormatter {

    public function __construct() {
        if (!extension_loaded('sodium')) {
            throw new \RuntimeException('Sodium extension not installed');
        }
    }

    public function format(string $value): string {
        return \sodium_bin2hex($value);
    }

    public function parse(string $value): string {
        return \sodium_hex2bin($value);
    }

}
