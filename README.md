# php-common

[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE.md)

This library provides various utilities for producing and parsing [Adscore](https://adscore.com) signatures, generating custom request payloads, and
virtually anything that might be useful for customers doing server-side integration with the service.

## Install

Via Composer

``` bash
$ composer require adscore/php-common
```

## Usage

### V4 signature verification

When zone's "Response signature algorithm" is set to "Hashing" or "Signing", it means that V4 signatures are in use. They provide basic means to check
incoming traffic for being organic and valuable, but do not carry any additional information.

``` php

/*  Replace <key> with "Zone Response Key" which you might find in "Zone Encryption" page for given zone. 
	Those keys are base64-encoded and the library expects raw binary, so we need to decode it now. */
$cryptKey = \base64_decode("<key>");

/*	Three things are necessary to verify the signature - at least one IP address, User Agent string 
	and the signature itself. */
$signature = $_GET['signature']; /* for example */
$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
/* 	You might want to use X-Forwarded-For or other IP-forwarding headers coming from for example load 
	balancing services, but make sure you trust them and they are not vulnerable to end-user modification! */
$ipAddresses = [ $_SERVER['REMOTE_ADDR'] ]; 

try {
	$parser = \AdScore\Common\Signature\Signature4::createFromRequest($signature, $ipAddresses, $userAgent, $cryptKey);
	/* 	Result contains numerical result value */
	$result = $parser->getResult();
	/* 	Judge is the module evaluating final result in the form of single score. RESULTS constant 
		in its definition contains array with human-readable descriptions of every numerical result, if needed. */
	$humanReadable = \AdScore\Common\Definition\Judge::RESULTS[$result];
	print $humanReadable['verdict'] . ' (' . $humanReadable['name'] . ')';
} catch (\AdScore\Common\Signature\Exception\VersionException $e) {
	/* 	It means that the signature is not the V4 one, check your zone settings and ensure the signatures 
		are coming from the chosen zone. */
} catch (\AdScore\Common\Signature\Exception\ParseException $e) {
	/* 	It means that the signature metadata is malformed and cannot be parsed, or contains invalid data, 
		check for corruption underway. */
} catch (\AdScore\Common\Signature\Exception\VerifyException $e) {
	/* 	Signature could not be verified - usually this is a matter of IP / user agent mismatch (or spoofing). 
		They must be bit-exact, so even excessive whitespace or casing change can trigger the problem. */
}

```

### V5 signature decryption

V5 is in fact an encrypted payload containing various metadata about the traffic. Its decryption does not rely on IP address nor User Agent string,
so it is immune for environment changes usually preventing V4 to be even decoded. Judge result is also included in the payload, but client doing the 
integration can make its own decision basing on the metadata accompanying.

Zone has to be set explicitly to V5 signature, if you don't see the option, please contact support as we are rolling this mode on customer's demand.
The format supports a wide variety of encryption and serialization methods, some of them are included in this repository, but it can be extended to
fulfill specific needs.

It can be integrated in V4-compatible mode, not making use of any V5 features (see V4 verification):

``` php

$cryptKey = \base64_decode("<key>");
$signature = $_GET['signature'];
$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
$ipAddresses = [ $_SERVER['REMOTE_ADDR'] ]; 

try {
	$parser = \AdScore\Common\Signature\Signature5::createFromRequest($signature, $ipAddresses, $userAgent, $cryptKey);
	$result = $parser->getResult();
	$humanReadable = \AdScore\Common\Definition\Judge::RESULTS[$result];
	print $humanReadable['verdict'] . ' (' . $humanReadable['name'] . ')';
} catch (\AdScore\Common\Signature\Exception\VersionException $e) {
	/* 	It means that the signature is not the V5 one, check your zone settings and ensure the signatures 
		are coming from the chosen zone. */
} catch (\AdScore\Common\Signature\Exception\ParseException $e) {
	/* 	It means that the signature metadata is malformed and cannot be parsed, or contains invalid data, 
		check for corruption underway. */
} catch (\AdScore\Common\Signature\Exception\VerifyException $e) {
	/* 	Signature could not be verified - see error message for details. */
}

```

The first difference is that now `$cryptKey` may be also a `Closure` instance (lambda function), accepting single `int` argument - zone ID 
and returning raw key as binary string. 
This is useful in scenarios, where signatures coming from different zones are handled at a single point. This is not possible for V4 signatures, as they
do not carry over any zone information.

As we can see, `createFromRequest` also requires a list of IP addresses and User Agent string. This is used for built-in verification routine, but
this time the verification is completely unrelated to decryption. Client integrating might want to replace the verification with its own implementation,
so here is the extended example (without any exception handling for readability):

``` php

$signature = $_GET['signature'];
/*	An example structure holding keys for every zone supported */
$cryptKeys = [
	123 => \base64_decode("123456789abcdefghijklmn")
];

$parser = new \AdScore\Common\Signature\Signature5();
/* 	Parsing/decryption stage */
$parser->parse($signature, function ($zoneId) use ($cryptKeys) {
	if (!isset($cryptKeys[$zoneId])) {
		throw new RuntimeException('Unsupported zone ' . $zoneId);
	}
	return $cryptKeys[$zoneId];
});
/* 	The payload now contains a decrypted signature data which might be used to verify the signature */
$payload = $parser->getPayload();
/* 	We can still make use of built-in signature validator and only then getResult() is being populated */
$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
$ipAddresses = [ $_SERVER['REMOTE_ADDR'] ]; 
$parser->verify($ipAddresses, $userAgent);
$result = $parser->getResult();

```

The `result` field and its associated `getResult()` getter method return result score only after a successful `verify()` call. This is expected behavior,
to preserve compliance with V4 behavior - the result is only valid when it's proven belonging to a visitor.
For custom integrations not relying on built-in verification routines (usually more tolerant), the result is present also in payload retrieved via 
`getPayload()` call, but it's then the integrator's reponsibility to ensure whether it's trusted or not. When desired validation is more strict than the built-in
one, the `verify()` can be called first, populating `getResult()` value, and after that any additional verification may take place.

Note: V4 signature parser also holds the payload, but it does not contain any useful informations, only timestamps and signed strings; especially - 
it does not contain any Judge result value, it is derived from the signature via several hashing/verification approaches.

## Integration

Any questions you have with custom integration, please contact our support@adscore.com. Please remember that we do require adequate technical knowledge 
in order to be able to help with the integration; there are other integration methods which do not require any, or require very little programming.