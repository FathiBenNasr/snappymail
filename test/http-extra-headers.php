<?php

// Run with: php test/http-extra-headers.php
define('APP_VERSION', 'test');
spl_autoload_register(static function (string $class): void {
	if (str_starts_with($class, 'Tachyon\\Util\\')) {
		$file = dirname(__DIR__).'/tachyon/v/0.0.0/app/libraries/tachyon_util/'.strtolower(str_replace('\\', '/', substr($class, 13))).'.php';
	} else {
		$file = dirname(__DIR__).'/tachyon/v/0.0.0/app/libraries/'.str_replace('\\', '/', $class).'.php';
	}
	if (is_file($file)) {
		require_once $file;
	}
});

function check(bool $condition, string $message): void
{
	if (!$condition) {
		throw new RuntimeException($message);
	}
}

use Tachyon\Util\HTTP\Request;

// An associative array becomes "Name: value" lines (integrity check, HIBP).
check(Request::headerLines(['Accept-Encoding' => 'gzip, deflate, br']) === ['Accept-Encoding: gzip, deflate, br'],
	'associative header was not turned into a header line');
check(Request::headerLines(['hibp-api-key' => 'k']) === ['hibp-api-key: k'], 'HIBP key header lost its name');

// A list of ready lines is left alone.
check(Request::headerLines(['Depth: 1', 'Content-Type: text/xml']) === ['Depth: 1', 'Content-Type: text/xml'],
	'a list of header lines was altered');

// A complete line filed under its own name stays one line (DAV client, socket 401 retry).
check(Request::headerLines(['Authorization' => 'Authorization: Basic dTpw']) === ['Authorization: Basic dTpw'],
	'a complete Authorization line was prefixed a second time');
check(Request::headerLines(['authorization' => 'Authorization: Bearer t']) === ['Authorization: Bearer t'],
	'the name match must ignore case');

// A value that merely mentions another header name is still prefixed.
check(Request::headerLines(['X-Note' => 'Authorization: none']) === ['X-Note: Authorization: none'],
	'only the header\'s own name may already be present');

// Both forms together, order kept.
check(Request::headerLines(['Depth: 0', 'Accept' => 'text/vcard']) === ['Depth: 0', 'Accept: text/vcard'],
	'mixed list lost an entry or its order');

echo "ok\n";
