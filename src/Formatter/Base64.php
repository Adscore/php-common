<?php

namespace AdScore\Common\Formatter;

/**
 * Generic Base64 formatter
 *
 * @author Bartosz Derleta <bartosz@derleta.com>
 */
class Base64 extends AbstractFormatter {

    public const BASE64_VARIANT_ORIGINAL = 1;
    public const BASE64_VARIANT_ORIGINAL_NO_PADDING = 3;
    public const BASE64_VARIANT_URLSAFE = 5;
    public const BASE64_VARIANT_URLSAFE_NO_PADDING = 7;
    
    protected int $variant;
    protected bool $strict;
    
    /**
     * @param int $variant Compatible with SODIUM_BASE64_VARIANT_*
     * @param bool $strict Whether to throw exception on decoding errors
     * @throws \InvalidArgumentException
     */
    public function __construct(int $variant = self::BASE64_VARIANT_URLSAFE_NO_PADDING, bool $strict = false) {
        if (!\in_array($variant, [
            self::BASE64_VARIANT_ORIGINAL, self::BASE64_VARIANT_ORIGINAL_NO_PADDING,
            self::BASE64_VARIANT_URLSAFE, self::BASE64_VARIANT_URLSAFE_NO_PADDING
        ])) {
            throw new \InvalidArgumentException('Invalid base64 variant');
        }
        $this->variant = $variant;
        $this->strict = $strict;
    }
    
    /**
     * Encodes a raw binary string with base64
     * @throws \InvalidArgumentException
     */
    public function format(string $value): string {
        switch ($this->variant) {
            case self::BASE64_VARIANT_ORIGINAL: 
                return \base64_encode($value);
            case self::BASE64_VARIANT_ORIGINAL_NO_PADDING: 
                return \rtrim(\base64_encode($value), '=');
            case self::BASE64_VARIANT_URLSAFE: 
                return \strtr(\base64_encode($value), ['+' => '-', '/' => '_']);
            case self::BASE64_VARIANT_URLSAFE_NO_PADDING: 
                return \strtr(\base64_encode($value), ['+' => '-', '/' => '_', '=' => '']);
        }
        throw new \InvalidArgumentException('Invalid base64 variant');
    }

    /**
     * Decodes a base64-encoded string into raw binary
     * @param string $value
     * @return string
     * @throws \InvalidArgumentException When strict mode is enabled, an exception is thrown in case of unrecognized character
     */
    public function parse(string $value): string {
        $binary = \base64_decode(
            \strtr($value, ['-' => '+', '_' => '/']), 
            $this->strict
        );
        if ($binary === false) {
            throw new \InvalidArgumentException('Not a valid base64-encoded value');
        }
        return $binary;
    }

}
