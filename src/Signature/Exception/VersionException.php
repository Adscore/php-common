<?php

namespace AdScore\Common\Signature\Exception;

use InvalidArgumentException;

/**
 * Occurs usually when invalid decoder is applied to signature
 *
 * @author Bartosz Derleta <bartosz@derleta.com>
 */
class VersionException extends InvalidArgumentException implements SignatureExceptionInterface {
    
}
