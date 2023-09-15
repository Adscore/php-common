<?php

namespace AdScore\Common\Struct;

/**
 * RFC 3986 serialization adapter
 *
 * @author Bartosz Derleta <bartosz@derleta.com>
 */
class Rfc3986 extends AbstractStruct {

    public const TYPE = 'H';

    /**
     * Encodes structure as URL-encoded query string
     * @param array $data
     * @return string
     */
    public function pack($data): string {
        $payload = \http_build_query($data, '', '&', PHP_QUERY_RFC3986);
        return parent::pack($payload);
    }

    /**
     * Parses string as if it were the query string passed via a URL
     * @param string $data
     * @return array
     */
    public function unpack(string $data) {
        $structure = null;
        \parse_str(parent::unpack($data), $structure);
        return $structure;
    }

}
