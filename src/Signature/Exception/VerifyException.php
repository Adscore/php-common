<?php

namespace AdScore\Common\Signature\Exception;

use RuntimeException;

/**
 * Invalid or outdated signatures
 *
 * @author Bartosz Derleta <bartosz@derleta.com>
 */
class VerifyException extends RuntimeException implements SignatureExceptionInterface {
    
}
