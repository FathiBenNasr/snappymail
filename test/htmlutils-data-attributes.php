<?php

// Run with: php test/htmlutils-data-attributes.php
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

// BuildHtml() is what DoSaveMessage() and DoSendMessage() run the composed
// body through: every data-* attribute must be gone, however many an element has.
foreach ([
	'<p data-a="1">x</p>',
	'<p data-a="1" data-b="2">x</p>',
	'<p data-a="1" data-b="2" data-c="3" data-d="4">x</p>',
	'<p DATA-A="1" data-b="2" title="kept">x</p>',
] as $html) {
	$cids = $urls = $locations = [];
	$out = \MailSo\Base\HtmlUtils::BuildHtml("<html><body>{$html}</body></html>", $cids, $urls, $locations);
	check(!preg_match('/\sdata-[a-z]/i', $out), "data-* left in: {$out}");
}

// Other attributes survive.
$cids = $urls = $locations = [];
$out = \MailSo\Base\HtmlUtils::BuildHtml('<html><body><p data-a="1" title="kept" data-b="2">x</p></body></html>', $cids, $urls, $locations);
check(str_contains($out, 'title="kept"'), 'a non-data attribute was removed');

echo "htmlutils-data-attributes: ok\n";
