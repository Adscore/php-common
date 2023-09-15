<?php 

namespace AdScore\Common\Crypt\Asymmetric;

use AdScore\Common\Crypt\Exception\ParseException;

/**
 * Asymmetric cryptography abstraction
 * 
 * @author	Bartosz Derleta <bartosz@derleta.com>
 */
abstract class AbstractAsymmetricCrypt {
	
	protected const LABELS = [
		0 => 'RSA PRIVATE KEY',
		1 => 'DSA PRIVATE KEY',
		2 => 'DH PRIVATE KEY',
		3 => 'EC PRIVATE KEY',
		10 => 'CERTIFICATE',
		11 => 'PUBLIC KEY',
		255 => null, /* Custom */
	];
	
	/**
	 * Compacts PEM key for DB storage
	 * 
	 * @param $key	Key in PEM format
	 * @return		Compacted key data
	 */
	public static function compactPem(string $key) : string {
		$data = self::parsePem($key);
		$type = \array_search($data['label'], self::LABELS);
		if ($type !== false) {
			return \pack('C', $type) . $data['data'];
        } else {
            return \pack('C', 255) . $data['label'] . \chr(0) . $data['data'];
        }
	}	
	
	/**
	 * Formats valid PEM payload from compacted data
	 * 
	 * @param $data	Compacted key data
	 * @return		Key in PEM format
	 */
	public static function expandPem(string $data, int $lineLength = 64) : string {
		if (\strpos($data, '-----BEGIN ') === 0) {
            return $data;
        }
        if (\strlen($data) < 3) {
			throw new ParseException('Key corrupted');
        }
		$type = \unpack('Ctype', $data)['type'];
        if (!isset(self::LABELS[$type])) {
            throw new ParseException('Invalid key type');
        }
		if ($type === 255) {
			$p = \strpos($data, \chr(0), 1);
			return self::encodePem(\substr($data, $p + 1), \substr($data, 1, $p - 1), $lineLength);
		} else {
			return self::encodePem(\substr($data, 1), self::LABELS[$type], $lineLength);
        }
	}
	
	/**
	 * Parses PEM format
	 */
	protected static function parsePem(string $key) : array {
		$data = \array_map(function ($a) { 
            return \trim($a); 
        }, \explode("\n", \trim($key)));
		$matches = [];
		if (!\preg_match('/^-----BEGIN ([\w\s]+)-----$/', \trim(\current($data)), $matches)) {
			throw new ParseException('Malformed PEM header');
        }
		$label = $matches[1];
		if (!\preg_match('/^-----END ([\w\s]+)-----$/', \trim(\end($data)), $matches)) {
			throw new ParseException('Malformed PEM footer');
        }
		if (\strcmp($label, $matches[1]) !== 0) {
			throw new ParseException('PEM header does not match footer');
        }
		return [
			'label' => $label,
			'data' => \base64_decode(
                \join('', \array_slice($data, 1, \count($data) - 2))
            )
		];
	}
	
	/**
	 * Builds PEM format from key data
	 */
	protected static function encodePem(string $data, string $label, int $lineLength = 64) : string {
		return 
			"-----BEGIN $label-----\n" .
			\chunk_split(\base64_encode($data), $lineLength, "\n") . 
			"-----END $label-----\n";
	}
	
}
