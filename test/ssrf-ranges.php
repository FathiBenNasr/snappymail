<?php

// Run with: php test/ssrf-ranges.php (needs no network: only IP literals)
spl_autoload_register(static function (string $class): void {
	$base = dirname(__DIR__).'/snappymail/v/0.0.0/app/libraries/';
	$file = str_starts_with($class, 'SnappyMail\\')
		? $base.strtolower(str_replace('\\', '/', $class)).'.php'
		: $base.str_replace('\\', '/', $class).'.php';
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

$Request = 'SnappyMail\\HTTP\\Request';
$public = fn(string $host) => $Request::URIHasPublicHost("http://{$host}/x.png");

foreach (['100.64.0.1', '100.100.100.200', '100.127.255.254', '192.0.0.1', '198.18.0.1',
	'198.19.255.254', '224.0.0.1', '239.255.255.250', '[fec0::1]', '[ff02::1]',
	'127.0.0.1', '10.0.0.1', '169.254.169.254', '[::1]', '[fc00::1]', '[::ffff:100.64.0.1]',
	// 6to4 (RFC 3056) carries the IPv4 address in bytes 2 to 5
	'[2002:7f00:1::1]', '[2002:a00:5::]', '[2002:a9fe:a9fe::]', '[2002:6440:1::]',
	// S-06: documentation (PHP 8.5 lets 2001:db8::/32 through), NAT64 local-use,
	// discard-only, TEST-NETs, 0/8, 240/4, link-local in both families,
	// NAT64 well-known wrapping loopback, and non-standard numeric loopback
	'[2001:db8::1]', '[2001:db8:1::53]', '[64:ff9b:1::a00:1]', '[100::1]', '192.0.2.1',
	'198.51.100.1', '203.0.113.7', '0.0.0.0', '0.1.2.3', '240.0.0.1', '255.255.255.255',
	'[fe80::1]', '169.254.0.1', '[64:ff9b::7f00:1]', '[64:ff9b::a9fe:a9fe]', '2130706433',
	'0x7f000001', '127.1', '017700000001', '[::]', '[::ffff:7f00:1]'] as $host) {
	check(!$public($host), "{$host} treated as public");
}
foreach (['100.63.255.255', '100.128.0.1', '198.17.255.255', '198.20.0.1', '8.8.8.8',
	'[2001:4860:4860::8888]',
	// 6to4 wrapping a public address stays reachable
	'[2002:808:808::]'] as $host) {
	check($public($host), "{$host} wrongly blocked");
}

// The server's own addresses. With --network=none only loopback exists, so
// hand the cache an address to stand for this host's public IP. (Public
// addresses, since the documentation ranges are now refused on their own.)
$prop = new ReflectionProperty($Request, 'aLocalAddresses');
$prop->setValue(null, [inet_pton('8.8.4.4'), inet_pton('2001:4860:4860::8844')]);
check(!$public('8.8.4.4'), "the server's own IPv4 address treated as public");
check(!$public('[2001:4860:4860::8844]'), "the server's own IPv6 address treated as public");
check($public('8.8.4.5'), 'a neighbouring address wrongly blocked');

// The pinned list is exactly what was checked.
check(['8.8.8.8'] === $Request::ResolvePublicHost('https://8.8.8.8/'), 'literal not returned for pinning');
check(['127.0.0.1'] !== $Request::ResolvePublicHost('https://2130706433/'), 'numeric loopback pinned');
check(null === $Request::ResolvePublicHost('https:///nohost'), 'missing host accepted');

echo "ssrf-ranges: ok\n";
