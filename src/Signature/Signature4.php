<?php

namespace AdScore\Common\Signature;

use AdScore\Common\Formatter\AbstractFormatter;
use AdScore\Common\Signature\Exception\ParseException;
use AdScore\Common\Signature\Exception\VersionException;
use AdScore\Common\Signature\Exception\VerifyException;
use AdScore\Common\Definition\Judge;
use AdScore\Common\Crypt\Asymmetric\OpenSSL as AsymmOpenSSL;

/**
 * Signature v4 parser
 *
 * @author Bartosz Derleta <bartosz@derleta.com>
 */
class Signature4 extends AbstractSignature {

   public const VERSION = 4;
    
   private const FIELD_IDS = [
		/* ulong fields */
		0x00 => ['name' => 'requestTime', 'type' => 'ulong'],
		0x01 => ['name' => 'signatureTime', 'type' => 'ulong'],
		
		0x10 => ['name' => 'ipv4', 'type' => 'ulong'], /* Debug field */
		/* ushort fields */
		0x40 => ['name' => null, 'type' => 'ushort'], /* Reserved for future use */
		/* uchar fields */
		0x80 => ['name' => 'masterSignType', 'type' => 'uchar'],
		0x81 => ['name' => 'customerSignType', 'type' => 'uchar'],
		/* string fields */
		0xC0 => ['name' => 'masterToken', 'type' => 'string'],
		0xC1 => ['name' => 'customerToken', 'type' => 'string'],
		0xC2 => ['name' => 'masterToken6', 'type' => 'string'],
		0xC3 => ['name' => 'customerToken6', 'type' => 'string'],
		0xC4 => ['name' => 'ipv6', 'type' => 'string'],
		0xC5 => ['name' => 'masterChecksum', 'type' => 'string'],
		
		0xD0 => ['name' => 'userAgent', 'type' => 'string'] /* Debug field */
	];
   
   	public const HASH_SHA256 = 1; /* Default HASH: using SHA256 */
	public const SIGN_SHA256 = 2; /* Default SIGN: using SHA256 */
    
    private const SIMPLE_TYPES = [
        'uchar' => ['unpack' => 'Cx/Cv', 'size' => 2],
        'ushort' => ['unpack' => 'Cx/nv', 'size' => 3],
        'ulong' => ['unpack' => 'Cx/Nv', 'size' => 5],
        'string' => ['unpack' => 'Cx/nv', 'size' => 3 /* + length(value) */]
    ];
    
    protected array $verificationData = [];
    
    public function __construct(?array $payload = null) {
        $this->payload = $payload;
    }
    
    /**
     * Simplified signature parsing/validation
     * @param string $signature
     * @param array $ipAddresses
     * @param string $userAgent
     * @param string $cryptKey
     * @param AbstractFormatter|null $formatter
     * @return self
     */
    public static function createFromRequest(
        string $signature, array $ipAddresses, string $userAgent, string $cryptKey, ?AbstractFormatter $formatter = null
    ) : self {
        $obj = new self();
        $obj->parse($signature, $formatter);
        $obj->verify($ipAddresses, $userAgent, $cryptKey);
        return $obj;
    }
    
    public function parse(string $signature, ?AbstractFormatter $formatter = null): void {
        $formatter ??= $this->getDefaultFormatter();
        $this->payload = $this->parseStructure($signature, $formatter);
    }
    
    protected function getHashBase(int $result, int $requestTime, int $signatureTime, string $ipAddress, string $userAgent) : string {
		return \join("\n", [$result, $requestTime, $signatureTime, $ipAddress, $userAgent]);
	}
    
    protected function signData(string $data, string $privateKey, string $algorithm = 'sha256') : string {
		$crypt = new AsymmOpenSSL($algorithm);
        return $crypt->sign($data, $privateKey);
	}

    protected function verifyData(string $data, string $signature, string $publicKey, string $algorithm = 'sha256') : bool {
		$crypt = new AsymmOpenSSL($algorithm);
        return $crypt->verify($data, $signature, $publicKey);
	}

	protected function hashData(string $data, string $salt, string $algorithm = 'sha256') : string {
		return \hash_hmac($algorithm, $data, $salt, true);
	}
    
    public function getVerificationData(): array {
        return $this->verificationData;
    }
    
    /**
     * Verifies signature
     * @param array $ipAddresses
     * @param string $userAgent
     * @param string $cryptKey
     * @param string $signRole
     * @param array|null $results
     * @return bool
     * @throws VerifyException
     */
    public function verify(array $ipAddresses, string $userAgent, string $cryptKey, string $signRole = 'customer', ?array $results = null): bool {
        $results ??= Judge::RESULTS;
        if (!isset($this->payload[$signRole . 'Token'])) {
			throw new VerifyException('Invalid sign role', 2);
        }
		$signType = $this->payload[$signRole . 'SignType'];
 		foreach ($ipAddresses as $ipAddress) {
			/* Detect whether it's IPv4 or IPv6, normalize */
			$longIp = \ip2long($ipAddress);
            $v = 4;
			if ($longIp !== false) {
				$ipAddress = \long2ip($longIp);
				$token = $this->payload[$signRole . 'Token'];
			} else {
				$ipAddress = \inet_ntop(\inet_pton($ipAddress));
				$token = $this->payload[$signRole . 'Token6'] ?? null;
                $v = 6;
				if ($token === null) {
					continue;
                }
			}
			/* Check all possible results */
			foreach ($results as $result => $meta) {
				$meta = \is_array($meta) ? $meta : [];
				$signatureBase = $this->getHashBase($result, $this->payload['requestTime'], $this->payload['signatureTime'], $ipAddress, $userAgent);
				switch ($signType) {
					case static::HASH_SHA256 :
						$xToken = $this->hashData($signatureBase, $cryptKey, 'sha256');
						if (\hash_equals($xToken, $token)) {
							$this->verificationData = [
                                'verdict' => $meta['verdict'] ?? null, 
                                'result' => $result, 
                                "ipv{$v}.ip" => $ipAddress, 
                                'embeddedIpV6' => $this->verifyEmbeddedIpv6($this->payload, $result, $cryptKey, $userAgent, $signRole)
                            ];
                            $this->result = $result;
                            return true;
                        }
						break;
					case static::SIGN_SHA256 :
						$xValid = $this->verifyData($signatureBase, $token, $cryptKey, 'sha256');
						if ($xValid) {
							$this->verificationData = [
                                'verdict' => $meta['verdict'] ?? null, 
                                'result' => $result, 
                                "ipv{$v}.ip" => $ipAddress, 
                                'embeddedIpV6' => $this->verifyEmbeddedIpv6($this->payload, $result, $cryptKey, $userAgent, $signRole)
                            ];
                            $this->result = $result;
                            return true;
                        }
						break;
					default :
						throw new VerifyException('Unrecognized sign type', 3);
				}
			}
		}
        throw new VerifyException('No verdict matched', 10);
    }

    /**
     * Allows to transport IPv6 over sessions
     * @param int $result
     * @param string $key
     * @param string $userAgent
     * @param string $signRole
     * @return string|null
     */
    protected function verifyEmbeddedIpv6(int $result, string $key, string $userAgent, string $signRole) : ?string {
		if (
            !isset($this->payload['ipV6']) || empty($this->payload['ipV6']) || 
            !isset($this->payload[$signRole . 'TokenV6']) || empty($this->payload[$signRole . 'TokenV6']) ||
            !isset($this->payload[$signRole . 'Checksum']) || !isset($this->payload[$signRole . 'SignType'])
        ) {
			return null; 
        }
		$checksum = $this->hashData($this->payload[$signRole . 'Token'] . $this->payload[$signRole . 'TokenV6'], $key, 'haval128,4');
		if (!\hash_equals($checksum, $this->payload[$signRole . 'Checksum'])) {
			return null;
        }
		$ipAddress = \inet_ntop($this->payload['ipV6']);
		if (empty($ipAddress)) {
			return null;
        }
		$signType = $this->payload[$signRole . 'SignType'];
		$signatureBase = $this->getHashBase($result, $this->payload['requestTime'], $this->payload['signatureTime'], $ipAddress, $userAgent);
		switch ($signType) {
			case static::HASH_SHA256 :
				$xToken = $this->hashData($signatureBase, $key, 'sha256');
				if (\hash_equals($xToken, $this->payload[$signRole . 'TokenV6'])) {
					return $ipAddress;
                }
			/* Customer verification unsupported */
		}
		return null;
	}
    
    /**
     * 
     * @param string $signature
     * @param string $type
     * @return int|string
     */
    private function readStructureField(string &$signature, string $type) {
        if (!isset(self::SIMPLE_TYPES[$type])) {
            throw new ParseException('Unsupported variable type "' . $type . '"');
        }
        $unpackFmtStr = self::SIMPLE_TYPES[$type]['unpack'];
        $fieldSize = self::SIMPLE_TYPES[$type]['size'];
        switch ($type) {
            case 'uchar':
            case 'ushort':
            case 'ulong':
                $v = (\unpack($unpackFmtStr, $signature)['v'] ?? null);
                if ($v === null) {
                    throw new ParseException('Premature end of signature');
                }
                $signature = \substr($signature, $fieldSize);
                return $v;
            case 'string':
                $length = (\unpack($unpackFmtStr, $signature)['v'] ?? null);
                if ($length === null) {
                    throw new ParseException('Premature end of signature');
                }
                if ($length & 0x8000) { /* For future use */
                    $length = ($length & 0xFF);
                }
                $v = \substr($signature, $fieldSize, $length);
                if (\strlen($v) !== $length) {
                    throw new ParseException('Premature end of signature');
                }
                $signature = \substr($signature, $fieldSize + $length);
                return $v;
            default:
                throw new ParseException('Unsupported variable type "' . $type . '"');
        }
    }
    
    /**
     * Decodes physical layer of signature
     * @param string $input
     * @return array
     * @throws ParseException
     * @throws VersionException
     */
    protected function parseStructure(string $input, AbstractFormatter $formatter): array {
        $signature = $formatter->parse($input);
		if (empty($signature)) {
			throw new ParseException('Not a valid base64 signature payload', 4);
        }
		$data = \unpack('Cversion/CfieldNum', $signature);
		if ($data['version'] !== static::VERSION) {
			throw new VersionException('Signature version not supported', 5);
        } else {
            $signature = \substr($signature, 2);
        }
		for ($i = 0; $i < $data['fieldNum']; ++$i) {
			$fieldId = \unpack('CfieldId', $signature)['fieldId'] ?? null;
			if ($fieldId === null) {
				throw new ParseException('Premature end of signature', 6);
            }
			if (!\array_key_exists($fieldId, self::FIELD_IDS)) { /* Determine field name and size */
				$fieldTypeDef = [ /* Guess field size, but leave unrecognized */
					'type' => ($t = self::FIELD_IDS[$fieldId & 0xC0]['type']),
					'name' => \sprintf('%s%02x', $t, $i)
				];
			} else {
				$fieldTypeDef = self::FIELD_IDS[$fieldId];
            }
			$data[$fieldTypeDef['name']] = $this->readStructureField($signature, $fieldTypeDef['type']);
		}
		unset($data['fieldNum']);
        return $data;
    }
    
}
