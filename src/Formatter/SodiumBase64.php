<?php

namespace AdScore\Common\Formatter;

/**
 * Base64 formatter using Sodium library
 *
 * @author Bartosz Derleta <bartosz@derleta.com>
 */
class SodiumBase64 extends AbstractFormatter {

    protected int $variant;
    
    public function __construct(int $variant = SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING) {
        if (!extension_loaded('sodium')) {
            throw new \RuntimeException('Sodium extension not installed');
        }
        if (version_compare(PHP_VERSION, '7.2.12', '<')) {
            /* https://bugs.php.net/bug.php?id=76291 */
            throw new \RuntimeException('Formatter affected by bug #76291');
        }
        if (!in_array($variant, [
            SODIUM_BASE64_VARIANT_ORIGINAL, SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING,
            SODIUM_BASE64_VARIANT_URLSAFE, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING
        ])) {
            throw new \InvalidArgumentException('Invalid base64 variant');
        }
        $this->variant = $variant;
    }

    public function format(string $value): string {
        return \sodium_bin2base64($value, $this->variant);
    }

    public function parse(string $value): string {
        return \sodium_base642bin($value, $this->variant);
    }

}
