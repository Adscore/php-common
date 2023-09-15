<?php

namespace AdScore\Common\Signature;

use AdScore\Common\Formatter\AbstractFormatter;
use AdScore\Common\Formatter\Base64;
use AdScore\Common\Signature\Exception\VerifyException;

/**
 * Abstract signature
 *
 * @author Bartosz Derleta <bartosz@derleta.com>
 */
abstract class AbstractSignature {

    protected ?array $payload;
    protected ?int $result = null;
    
    /**
     * Retrieve embedded payload
     * @return array|null
     */
    public function getPayload(): ?array {
        return $this->payload;
    }

    /**
     * Embed new payload
     * @param array $payload
     * @return void
     */
    public function setPayload(array $payload): void {
        $this->payload = $payload;
    }   
    
    /**
     * Returns verification result
     * @return int
     * @throws VerifyException
     */
    public function getResult(): int {
        if ($this->result === null) {
            throw new VerifyException('Result unavailable for unverified signature');
        }
        return $this->result;
    }
    
    /**
     * Simplified signature parsing/validation
     * @param string $signature                 Signature content
     * @param array $ipAddresses                Array of client's IP addresses
     * @param string $userAgent                 Client's User Agent
     * @param string $cryptKey                  Signature decoding key
     * @param AbstractFormatter|null $formatter Optional formatter (if signature content is not a standard Base64)
     * @return self
     */
    abstract public static function createFromRequest(
        string $signature, array $ipAddresses, string $userAgent, string $cryptKey, ?AbstractFormatter $formatter = null
    ) : self;
    
    /**
     * Returns default formatter
     * @return AbstractFormatter
     */
    protected function getDefaultFormatter(): AbstractFormatter {
        return new Base64(Base64::BASE64_VARIANT_URLSAFE_NO_PADDING, true);
    }
    
    /**
     * Compare n bytes between two strings
     * @param string $known
     * @param string $user
     * @param int $n
     * @return bool
     */
    public function bytesEquals(string $known, string $user, int $n) : bool {
        if ((\strlen($known) < $n) || (\strlen($user) < $n)) {
            return false;
        }
        return \hash_equals(\substr($known, 0, $n), \substr($user, 0, $n));
    }

}
