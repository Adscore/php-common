<?php

namespace AdScore\Common\Signature;

use AdScore\Common\Struct\StructFactory;
use AdScore\Common\Struct\AbstractStruct;
use AdScore\Common\Crypt\CryptFactory;
use AdScore\Common\Crypt\Symmetric\AbstractSymmetricCrypt;
use AdScore\Common\Formatter\AbstractFormatter;
use AdScore\Common\Signature\Exception\ParseException;
use AdScore\Common\Signature\Exception\VersionException;
use AdScore\Common\Signature\Exception\VerifyException;
use Closure;

/**
 * Signature v5 envelope/parser
 *
 * @author Bartosz Derleta <bartosz@derleta.com>
 */
class Signature5 extends AbstractSignature {

    public const VERSION = 5;
    protected const HEADER_LENGTH = 11;

    private const IPV4_SIZE = 4;
    private const IPV6_SIZE = 16;
    
    protected ?array $payload;
    protected ?int $zoneId;
    
    /**
     * Creates a new signature envelope
     * @param int|null $zoneId
     * @param array|null $payload
     */
    public function __construct(?int $zoneId = null, ?array $payload = null) {
        $this->zoneId = $zoneId;
        $this->payload = $payload;
    }

    /**
     * Retrieve zone ID
     * @return int|null
     */
    public function getZoneId(): ?int {
        return $this->zoneId;
    }

    /**
     * Embed new zone ID
     * @param int $zoneId
     * @return void
     */
    public function setZoneId(int $zoneId): void {
        $this->zoneId = $zoneId;
    }
    
    /**
     * Simplified signature parsing/validation
     * @param string $signature
     * @param array $ipAddresses
     * @param string $userAgent
     * @param Closure|string $cryptKey
     * @param AbstractFormatter|null $formatter
     * @return self
     */
    public static function createFromRequest(
        string $signature, array $ipAddresses, string $userAgent, $cryptKey, ?AbstractFormatter $formatter = null
    ) : self {
        $obj = new self();
        $obj->parse($signature, \is_string($cryptKey) ? (function ($zoneId) use ($cryptKey) { 
            return $cryptKey; 
        }) : $cryptKey, $formatter);
        $obj->verify($ipAddresses, $userAgent);
        return $obj;
    }
    
    /**
     * Default V5 signature validator
     * @param array $result
     * @param array $ipAddresses
     * @param string $userAgent
     * @throws VerifyException
     */
    public function verify(array $ipAddresses, string $userAgent): bool {
        $matchingIp = null;
        foreach ($ipAddresses as $ipAddress) {
            /* Some encoding methods like Rfc3986 don't preserve data types, hence typecasting is necessary */
            $bytesToCompareV4 = isset($this->payload['ipv4.v']) ? intval($this->payload['ipv4.v']) : self::IPV4_SIZE;
            $bytesToCompareV6 = isset($this->payload['ipv6.v']) ? intval($this->payload['ipv6.v']) : self::IPV6_SIZE;
            $nIpAddress = \inet_pton($ipAddress);
            if ((
                isset($this->payload['ipv4.ip']) && 
                ($this->bytesCompare($nIpAddress, \inet_pton($this->payload['ipv4.ip']), $bytesToCompareV4))
            ) || (
                isset($this->payload['ipv6.ip']) && 
                ($this->bytesCompare($nIpAddress, \inet_pton($this->payload['ipv6.ip']), $bytesToCompareV6))
            )) {
                $matchingIp = $ipAddress;
                break;
            }
        }
        if ($matchingIp === null) {
            throw new VerifyException('Signature IP mismatch', 13);
        }
        if (!isset($this->payload['b.ua'])) {
            throw new VerifyException('Signature contains no user agent', 15);
        }
        if (\strcmp($this->payload['b.ua'], $userAgent) !== 0) {
            throw new VerifyException('Signature user agent mismatch', 14);
        }
        $this->result = $this->payload['result'];
        return true;
    }
    
    /**
     * Produce an encrypted signature
     * @param AdScore\Common\Struct\AbstractStruct $struct
     * @param AdScore\Common\Crypt\Symmetric\AbstractSymmetricCrypt $crypt
     * @param string $cryptKey
     * @param AdScore\Common\Formatter\AbstractFormatter $formatter		Signature formatter
     * @return string
     */
    public function format(AbstractStruct $struct, AbstractSymmetricCrypt $crypt, string $cryptKey, ?AbstractFormatter $formatter = null): string {
        $formatter ??= $this->getDefaultFormatter();
        $serializedPayload = $struct->pack($this->payload);
        $encryptedPayload = $crypt->encryptWithKey($serializedPayload, $cryptKey);
        $header = \pack('CnJ', self::VERSION, \strlen($encryptedPayload), $this->zoneId);
        return $formatter->format($header . $encryptedPayload);
    }
    
    /**
     * Parses and decodes a signature
     * @param string $signature Formatted signature
     * @param Closure $onCryptKeyRequest Zone ID is passed as parameter, this callback should return a decryption key
     * @param AdScore\Common\Formatter\AbstractFormatter $formatter Signature format decoder
     */
    public function parse(string $signature, Closure $onCryptKeyRequest, ?AbstractFormatter $formatter = null): void {
        $formatter ??= $this->getDefaultFormatter();
        $payload = $formatter->parse($signature);
        if (\strlen($payload) <= self::HEADER_LENGTH) {
            throw new ParseException('Malformed signature', 1);
        }
        ['version' => $version, 'length' => $length, 'zone_id' => $zoneId] = \unpack('Cversion/nlength/Jzone_id', $payload);
        if ($version !== self::VERSION) {
            throw new VersionException('Invalid signature version', 2);
        }
        $encryptedPayload = \substr($payload, self::HEADER_LENGTH, $length);
        if (\strlen($encryptedPayload) < $length) {
            throw new ParseException('Truncated signature payload', 3);
        }
        $this->payload = $this->decryptPayload($encryptedPayload, $onCryptKeyRequest($zoneId));
        $this->zoneId = $zoneId;
    }

    /**
     * Decrypts and unpacks payload
     * @param string $payload
     * @param string $key
     * @return array
     */
    protected function decryptPayload(string $payload, string $key): array {
        $crypt = CryptFactory::createFromPayload($payload);
        $decryptedPayload = $crypt->decryptWithKey($payload, $key);
        $struct = StructFactory::createFromPayload($decryptedPayload);
        $unpackedPayload = $struct->unpack($decryptedPayload);
        if (!\is_array($unpackedPayload)) {
            throw new ParseException('Unexpected payload type ' . \gettype($unpackedPayload));
        }
        return $unpackedPayload;
    }

}
