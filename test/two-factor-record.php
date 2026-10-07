<?php

// Run with: php test/two-factor-record.php
// The stored second-factor record and the TOTP step, without the plugin around them.
define('APP_VERSION', 'test');
spl_autoload_register(static function (string $class): void {
	$base = dirname(__DIR__).'/tachyon/v/0.0.0/app/libraries/';
	$file = str_starts_with($class, 'Tachyon\\Util\\')
		? $base.'tachyon_util/'.strtolower(str_replace('\\', '/', substr($class, 13))).'.php'
		: $base.str_replace('\\', '/', $class).'.php';
	if (is_file($file)) {
		require_once $file;
	}
});
require dirname(__DIR__).'/plugins/two-factor-auth/providers/interface.php';
require dirname(__DIR__).'/plugins/two-factor-auth/providers/totp.php';
require dirname(__DIR__).'/plugins/two-factor-auth/providers/record.php';

function check(bool $condition, string $message): void
{
	if (!$condition) {
		throw new RuntimeException($message);
	}
}

// RFC 6238, appendix B (SHA-1, seed "12345678901234567890"), last six digits.
$rfc = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
foreach ([59 => '287082', 1111111109 => '081804', 1111111111 => '050471',
	1234567890 => '005924', 2000000000 => '279037', 20000000000 => '353130'] as $t => $code) {
	check($code === TwoFactorAuthTotpSlice::code($rfc, intdiv($t, 30)), "RFC 6238 vector at T={$t}");
}
check(1 === TwoFactorAuthTotpSlice::match($rfc, '287082', 59), 'the matching step is not returned');
check(1 === TwoFactorAuthTotpSlice::match($rfc, '287082', 89), 'one step of drift is refused');
check(null === TwoFactorAuthTotpSlice::match($rfc, '287082', 120), 'two steps of drift are accepted');
check(null === TwoFactorAuthTotpSlice::match($rfc, '28708', 59), 'five digits accepted as a code');
check(\Tachyon\Util\TOTP::Verify($rfc, TwoFactorAuthTotpSlice::code($rfc, intdiv(time(), 30))), 'the core TOTP disagrees');

// Sealing.
$key = TwoFactorRecord::key('salt-of-this-install');
$box = TwoFactorRecord::seal('JBSWY3DPEHPK3PXP', $key);
check(!str_contains($box, 'JBSWY3DPEHPK3PXP'), 'the secret is readable in the box');
check('JBSWY3DPEHPK3PXP' === TwoFactorRecord::unseal($box, $key), 'the secret does not come back out');
check(null === TwoFactorRecord::unseal($box, TwoFactorRecord::key('other')), 'another installation opens the box');
$raw = base64_decode($box);
$raw[30] = chr(ord($raw[30]) ^ 1);
check(null === TwoFactorRecord::unseal(base64_encode($raw), $key), 'a tampered box is accepted');

// Backup codes.
$codes = TwoFactorRecord::newBackupCodes();
check(8 === count($codes), 'not eight backup codes');
check(8 === count(array_filter($codes, fn ($s) => is_string($s) && preg_match('/^\d{9}$/', $s))), 'a backup code is not nine digits');
check(8 === count(array_unique($codes)), 'two backup codes are the same');

$record = TwoFactorRecord::create('a@example.com', $rfc, $codes, $key);
$json = json_encode($record);
check(!str_contains($json, $rfc), 'the secret is stored in clear');
foreach ($codes as $code) {
	check(!str_contains($json, $code), 'a backup code is stored in clear');
}

$slice59 = fn (string $s, string $c) => TwoFactorAuthTotpSlice::match($s, $c, 59);
[$out, $record] = TwoFactorRecord::check($record, $codes[3], $key, 1000, $slice59);
check('ok' === $out, 'a backup code is refused');
check(7 === count($record['BackupHashes']), 'a used backup code is not spent');
[$out] = TwoFactorRecord::check($record, $codes[3], $key, 1001, $slice59);
check('wrong' === $out, 'a backup code works twice');

// Replay.
$record = TwoFactorRecord::create('a@example.com', $rfc, $codes, $key);
[$out, $record] = TwoFactorRecord::check($record, '287082', $key, 1000, $slice59);
check('ok' === $out, 'a valid code is refused');
[$out, $record] = TwoFactorRecord::check($record, '287082', $key, 1010, $slice59);
check('replay' === $out, 'the same code works twice, or is not named a replay');
[$out] = TwoFactorRecord::check($record, '000000', $key, 1020, fn () => 0);
check('replay' === $out, 'a code from an older step is accepted');

// Lockout.
$record = TwoFactorRecord::create('a@example.com', $rfc, $codes, $key);
$none = fn () => null;
for ($i = 0; $i < 4; ++$i) {
	[, $record] = TwoFactorRecord::check($record, '111111', $key, 5000 + $i, $none);
}
check(!TwoFactorRecord::isLocked($record, 5004), 'locked after four failures');
[, $record] = TwoFactorRecord::check($record, '111111', $key, 5004, $none);
check(TwoFactorRecord::isLocked($record, 5005), 'not locked after five failures');
[$out] = TwoFactorRecord::check($record, '287082', $key, 5010, $slice59);
check('locked' === $out, 'a valid code goes through the lock');
[$out] = TwoFactorRecord::check($record, $codes[0], $key, 5010, $slice59);
check('locked' === $out, 'a backup code goes through the lock');
[$out] = TwoFactorRecord::check($record, '287082', $key, 5004 + 901, $slice59);
check('ok' === $out, 'still locked after fifteen minutes');
$spread = TwoFactorRecord::create('a@example.com', $rfc, $codes, $key);
foreach ([0, 1000, 2000, 3000, 4000] as $t) {
	[, $spread] = TwoFactorRecord::check($spread, '111111', $key, 10000 + $t, $none);
}
check(!TwoFactorRecord::isLocked($spread, 14001), 'failures far apart add up');

// A record written by 2.19.1 (clear JSON) keeps working, sealed.
$old = ['User' => 'a@example.com', 'Enable' => true, 'Secret' => $rfc, 'BackupCodes' => '123456789 987654321', 'QRCode' => 'x'];
check(TwoFactorRecord::isLegacy($old), 'a 2.19.1 record is not recognised');
$new = TwoFactorRecord::normalise($old, $key);
check(!isset($new['Secret']) && !isset($new['BackupCodes']) && !isset($new['QRCode']), 'an old record keeps clear data');
check(!TwoFactorRecord::isLegacy($new), 'a sealed record is taken for an old one');
check($rfc === TwoFactorRecord::unseal($new['SecretBox'], $key), 'an old secret is lost');
check('ok' === TwoFactorRecord::check($new, '987654321', $key, 1, $slice59)[0], 'an old backup code no longer works');
check($new['Enable'] && $new['Tested'], 'an old enabled record is switched off or untested');

// The URI and the QR code.
check('otpauth://totp/Webmail:a%40example.com?secret=ABC&issuer=Webmail&algorithm=SHA1&digits=6&period=30'
	=== TwoFactorRecord::uri('a@example.com', 'ABC', 'Webmail'), 'the issuer does not name the service');
check('otpauth://totp/a%40example.com?secret=ABC&algorithm=SHA1&digits=6&period=30'
	=== TwoFactorRecord::uri('a@example.com', 'ABC'), 'an empty issuer is written');
$qr = \Tachyon\Util\QRCode::getMinimumQRCode(TwoFactorRecord::uri('a@example.com', 'JBSWY3DPEHPK3PXP', 'Webmail'),
	\Tachyon\Util\QRCode::ERROR_CORRECT_LEVEL_M);
$svg = TwoFactorRecord::svg($qr->getModuleCount(), fn (int $r, int $c) => $qr->isDark($r, $c));
check(str_starts_with($svg, 'data:image/svg+xml;base64,'), 'the QR code is not an SVG data URI');
$xml = base64_decode(substr($svg, 26));
check(1 === preg_match('/^<svg [^>]*viewBox="0 0 (\d+) \1"/', $xml, $m) && (int) $m[1] === $qr->getModuleCount() + 8, 'no quiet zone around the QR code');

echo "two-factor-record: ok\n";
