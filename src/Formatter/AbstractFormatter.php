<?php

namespace AdScore\Common\Formatter;

/**
 * @author Bartosz Derleta <bartosz@derleta.com>
 */
abstract class AbstractFormatter {

    /**
     * Binary to ASCII conversion
     * @param string $value
     * @return string
     */
    abstract public function format(string $value): string;

    /**
     * ASCII to binary conversion
     * @param string $value
     * @return string
     */
    abstract public function parse(string $value): string;

}
