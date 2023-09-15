<?php

namespace AdScore\Common\Crypt;

use RuntimeException;

trait OpenSSLSafeCallTrait {
    
    /**
     * Safely call openssl_* functions with error checking
     * @param string $function
     * @param type $args
     * @return type
     * @throws RuntimeException
     */
    protected static function safeCall(string $function, &...$args) {
        while (\openssl_error_string() !== false) {}
        $result = ('openssl_' . $function)(...$args);
        if ($result === false) {
            $message = \openssl_error_string();
            if (empty($message)) {
                $message = \error_get_last()['message'] ?? ' Unknown error in ' . $function . ' call';
            }
            throw new RuntimeException($message);
        }
        return $result;
    }
    
}