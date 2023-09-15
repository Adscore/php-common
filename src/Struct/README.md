Struct
=========

The Struct module contains serializers/unserializers, used to convert between structures (mostly arrays) and binary payloads.

Methods
-------

### `string pack(mixed $value)`

Packs structure into binary payload.

### `mixed unpack(string $value)`

Unpacks a structure from a binary payload.

Concretions
-----------

### Serialize

PHP-native implementation of serialization. No dependencies are required.

### Igbinary

[Igbinary]() serialization. Requires installed [igbinary PHP extension](https://github.com/igbinary/igbinary).

### Msgpack

[MessagePack](https://msgpack.org/) serialization. Requires installed [Msgpack PHP extension](https://github.com/msgpack/msgpack-php).

### Json

Implements the JavaScript Object Notation (JSON) data-interchange format, using [JSON PHP extension](https://www.php.net/manual/en/book.json.php), usually bundled. 

### Rfc3986

URL-encoded query string, spaces will be percent encoded. No dependencies are required.
