<?php

// Run with: php test/raw-inline-type.php
spl_autoload_register(static function (string $class): void {
	$file = dirname(__DIR__).'/snappymail/v/0.0.0/app/libraries/'.str_replace('\\', '/', $class).'.php';
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

class RawInlineType
{
	use \RainLoop\Actions\Raw;
}

$cases = [
	// shown as declared
	'image/png' => 'image/png',
	'IMAGE/JPEG; name="x.jpg"' => 'image/jpeg',
	'application/pdf' => 'application/pdf',
	'video/mp4' => 'video/mp4',
	'audio/ogg; codecs=opus' => 'audio/ogg',
	'text/plain; charset=utf-8' => 'text/plain',
	// shown as source, never rendered
	'text/html' => 'text/plain',
	'Text/HTML; charset=utf-8' => 'text/plain',
	'text/xml' => 'text/plain',
	// downloaded
	// Shown inline: mail uses SVG for logos, an <img> never runs script, and the
	// caller sends 'Content-Security-Policy: sandbox' alongside it.
	'image/svg+xml' => 'image/svg+xml',
	'image/svg+xml; charset=utf-8' => 'image/svg+xml',
	'application/xhtml+xml' => null,
	'application/xml' => null,
	'application/octet-stream' => null,
	'multipart/related' => null,
	'' => null,
];
foreach ($cases as $in => $expected) {
	$got = RawInlineType::inlineContentType($in);
	check($expected === $got, "'{$in}': expected ".var_export($expected, true).', got '.var_export($got, true));
}

echo "raw-inline-type: ok\n";
