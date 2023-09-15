<?php

namespace AdScore\Common\Signature\Exception;

use RuntimeException;

/**
 * Malformed or truncated signatures
 *
 * @author Bartosz Derleta <bartosz@derleta.com>
 */
class ParseException extends RuntimeException implements SignatureExceptionInterface {
    
}
