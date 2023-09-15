Formatter
=========

The Formatter module contains two-way converters (binary-to-ASCII formatters and binary-from-ASCII parsers), used to safely transport binary signatures and payloads.

Methods
-------

### `string format(string $value)`

Formats given `$value` as a value containing only safe ASCII characters.

### `string parse(string $value)`

Parses a binary value from an encoded representation.

Concretions
-----------

### Base64

PHP-native implementation of base64 encoding and its variants, output-compatible with Sodium implementation.

### SodiumBase64

Safer base64 implementation using Sodium library, which is constant-time.

### Hex

PHP-native implementation of hexadecimal encoding.

### SodiumHex

Constant-time hexadecimal encoder using Sodium library.