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
     * Literal implementation of whatwg/url "5.1. application/x-www-form-urlencoded parsing"
     * https://url.spec.whatwg.org/#urlencoded-parsing
     * @param string $data
     * @return array
     */
    public function unpack(string $data) {
        /* The application/x-www-form-urlencoded parser takes a byte sequence input, and then runs these steps: */
        $input = parent::unpack($data);
        /* 1. Let output be an initially empty list of name-value tuples where both name and value hold a string. */
        /* @internal we do not expect duplicate keys nor we need them */
        $output = [];
        /* 2. Let sequences be the result of splitting input on 0x26 (&). */
        $sequences = explode('&', $input);
        /* 3. For each byte sequence bytes in sequences: */
        foreach ($sequences as $sequence) {
            /* If bytes is the empty byte sequence, then continue. */
            if (empty($sequence)) {
                continue;
            }
            /* If bytes contains a 0x3D (=), then let name be the bytes from the start of bytes up to but excluding its 
             * first 0x3D (=), and let value be the bytes, if any, after the first 0x3D (=) up to the end of bytes. 
             * If 0x3D (=) is the first byte, then name will be the empty byte sequence. If it is the last, then value 
             * will be the empty byte sequence. */
            $name = strstr($sequence, '=', true);
            if ($name !== false) {
                $value = substr($sequence, strlen($name) + 1);
            } else {
                /* Otherwise, let name have the value of bytes and let value be the empty byte sequence. */
                $name = $sequence;
                $value = '';
            }
            /* Replace any 0x2B (+) in name and value with 0x20 (SP). */
            $name = strtr($name, '+', ' ');
            $value = strtr($value, '+', ' ');
            /* Let nameString and valueString be the result of running UTF-8 decode without BOM on the percent-decoding
             * of name and value, respectively. */
            $nameString = rawurldecode($name);
            $valueString = rawurldecode($value);
            /* Append (nameString, valueString) to output. */
            /* @internal we do not expect duplicate keys nor we need them */
            $output[$nameString] = $valueString;
        }
        /* 4. Return output. */
        return $output;
    }

}
