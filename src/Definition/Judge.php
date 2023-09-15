<?php

namespace AdScore\Common\Definition;

/**
 * Definitions for Judge
 *
 * @author Bartosz Derleta <bartosz@derleta.com>
 */
class Judge {

    public const OK = 0;
	public const PU = 3;
	public const PROXY = 6;
	public const BOT = 9;

	public const RESULTS = [
		self::OK => ['verdict' => 'ok', 'name' => 'Clean'],
		self::PU => ['verdict' => 'junk', 'name' => 'Potentially unwanted'],
		self::PROXY => ['verdict' => 'proxy', 'name' => 'Proxy'],
		self::BOT => ['verdict' => 'bot', 'name' => 'Bot'],
	];

    public static function getResultMap(): array { 
        return \array_combine(
            \array_column(self::RESULTS, 'verdict'), 
            \array_keys(self::RESULTS)
        );
    }

}
