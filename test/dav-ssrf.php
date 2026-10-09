<?php
/**
 * S-06 (audit 2026-10): the CardDAV sync client must not reach internal hosts,
 * must not speak plain http, and must verify TLS.
 * Run with: php test/dav-ssrf.php (no network: IP literals and /etc/hosts only)
 */
define('APP_VERSION', '0.0.0-test');
spl_autoload_register(static function (string $class): void {
	$base = dirname(__DIR__).'/snappymail/v/0.0.0/app/libraries/';
	$file = str_starts_with($class, 'SnappyMail\\')
		? $base.strtolower(str_replace('\\', '/', $class)).'.php'
		: $base.str_replace('\\', '/', $class).'.php';
	if (is_file($file)) {
		require_once $file;
	}
});

$iChecks = 0;
function check(bool $condition, string $message): void
{
	global $iChecks;
	++$iChecks;
	if (!$condition) {
		fwrite(STDERR, "FAIL: {$message}\n");
		exit(1);
	}
}

// The real trait, in a minimal host class (the trait is what ships).
class DavHost
{
	use \RainLoop\Providers\AddressBook\CardDAV;
	public array $aAllowed = [];
	public array $aLog = [];
	protected function davAllowedHosts() : array { return $this->aAllowed; }
	public function logMask($s) : void {}
	public function logWrite(string $s, int $i = 0, string $n = '') : bool { $this->aLog[] = $s; return true; }
	public function client(string $sUrl) : ?\SnappyMail\DAV\Client
	{
		return $this->getDavClientFromUrl($sUrl, 'user', 'secret');
	}
}

$refuse = static fn(string $u, array $a = []) : ?string
	=> (new ReflectionMethod(DavHost::class, 'davUrlRefusal'))->invoke(null, $u, $a);

// Abuse cases first: each must be refused.
foreach ([
	'http://8.8.8.8',               // plain http: Basic credentials in clear
	'https://127.0.0.1',
	'https://127.0.0.1:8008',
	'https://localhost',            // name resolving to loopback (/etc/hosts)
	'https://10.89.8.2',
	'https://169.254.169.254',      // cloud metadata
	'https://100.64.0.1',           // CGNAT
	'https://[::1]',
	'https://[fe80::1]',
	'https://[fc00::1]',
	'https://[2001:db8::1]',        // documentation, let through by PHP 8.5
	'https://[64:ff9b::a00:1]',     // NAT64 to 10.0.0.1
	'https://[::ffff:127.0.0.1]',
	'https://2130706433',           // 127.0.0.1 in decimal
	'https://0x7f000001',
	'ftp://8.8.8.8',
	'https://',
] as $sUrl) {
	check(null !== $refuse($sUrl), "{$sUrl} accepted");
}

// The administrator's list lifts the address check, not the https rule.
$aList = ['smail-local.convergent.cc:8008', 'pim.convergent.cc'];
check(null === $refuse('https://smail-local.convergent.cc:8008', $aList), 'listed host:port refused');
check(null === $refuse('https://pim.convergent.cc', $aList), 'listed host refused');
check(null === $refuse('https://PIM.convergent.cc:443', $aList), 'listed host with port refused');
check(null !== $refuse('http://pim.convergent.cc', $aList), 'listed host accepted over http');
check(null !== $refuse('https://smail-local.convergent.cc:9999', ['smail-local.convergent.cc:8008', '127.0.0.1']),
	'listed host:port accepted on another port');
check(null !== $refuse('https://127.0.0.1', ['convergent.cc']), 'no suffix match: list must be exact');
check(null !== $refuse('https://evil.pim.convergent.cc', $aList), 'subdomain of a listed host accepted');

// A public literal is fine.
check(null === $refuse('https://8.8.8.8'), 'public address refused');

// End to end through getDavClientFromUrl(): internal -> no client at all.
$oHost = new DavHost;
check(null === $oHost->client('https://127.0.0.1:8008/dav/'), 'client built for loopback');
check(null === $oHost->client('http://8.8.8.8/dav/'), 'client built for plain http');
check(null === $oHost->client('10.0.0.1/dav/'), 'client built for a bare internal host');
check(1 <= count($oHost->aLog) && str_contains(end($oHost->aLog), 'refused'), 'refusal not logged');

$oClient = $oHost->client('https://8.8.8.8/dav/');
check($oClient instanceof \SnappyMail\DAV\Client, 'no client for a public https host');
$oHTTP = (new ReflectionProperty($oClient, 'HTTP'))->getValue($oClient);
check(true === $oHTTP->verify_peer, 'TLS peer not verified');
check(true === $oHTTP->block_private_ips, 'private addresses not blocked for an unlisted host');

$oHost->aAllowed = ['127.0.0.1:8008'];
$oClient = $oHost->client('https://127.0.0.1:8008/dav/');
check($oClient instanceof \SnappyMail\DAV\Client, 'listed internal host refused end to end');
$oHTTP = (new ReflectionProperty($oClient, 'HTTP'))->getValue($oClient);
check(false === $oHTTP->block_private_ips, 'listed host still blocked');
check(true === $oHTTP->verify_peer, 'TLS not verified for a listed host');

// The DAV client itself fails closed when built without the flag.
$oDirect = new \SnappyMail\DAV\Client(['baseUri' => 'https://127.0.0.1', 'userName' => 'u', 'password' => 'p']);
$oHTTP = (new ReflectionProperty($oDirect, 'HTTP'))->getValue($oDirect);
check(true === $oHTTP->block_private_ips && true === $oHTTP->verify_peer, 'DAV client defaults are open');
// And the request itself is refused before any socket is opened.
$bThrown = false;
set_error_handler(static fn() => true, E_USER_WARNING);
try {
	$oHTTP->doRequest('PROPFIND', 'https://127.0.0.1:8008/dav/');
} catch (\RuntimeException $e) {
	$bThrown = true;
}
restore_error_handler();
check($bThrown, 'request to loopback was sent');

echo "dav-ssrf: ok ({$iChecks} checks)\n";
