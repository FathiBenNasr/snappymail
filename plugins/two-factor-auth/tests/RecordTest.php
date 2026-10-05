<?php
/**
 * two-factor-auth 2.21.0 — the record and the TOTP step, without SnappyMail.
 *
 * Run: php plugins/two-factor-auth/tests/RecordTest.php
 * (from the root of the snappymail tree; the core's TOTP class is loaded from it).
 */
declare(strict_types=1);

require __DIR__ . '/../../../snappymail/v/0.0.0/app/libraries/snappymail/totp.php';
require __DIR__ . '/../providers/interface.php';
require __DIR__ . '/../providers/totp.php';
require __DIR__ . '/../providers/record.php';

$iFail = 0;
function check(string $sWhat, $mGot, $mWant) : void
{
	global $iFail;
	$b = $mGot === $mWant;
	echo ($b ? '  ok   ' : '  FAIL ') . $sWhat . ($b ? '' : ' — got ' . \var_export($mGot, true) . ', want ' . \var_export($mWant, true)) . "\n";
	$b || ++$iFail;
}

/* ---- RFC 6238, appendix B (SHA-1, seed "12345678901234567890"), last six digits ---- */
$sRfc = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
foreach (array(59 => '287082', 1111111109 => '081804', 1111111111 => '050471',
	1234567890 => '005924', 2000000000 => '279037', 20000000000 => '353130') as $iT => $sCode) {
	check("RFC 6238 at T=$iT", TwoFactorAuthTotpSlice::code($sRfc, \intdiv($iT, 30)), $sCode);
}
check('the matching step is returned', TwoFactorAuthTotpSlice::match($sRfc, '287082', 59), 1);
check('one step of drift is accepted', TwoFactorAuthTotpSlice::match($sRfc, '287082', 89), 1);
check('two steps are not', TwoFactorAuthTotpSlice::match($sRfc, '287082', 120), null);
check('the core agrees with us', \SnappyMail\TOTP::Verify($sRfc, TwoFactorAuthTotpSlice::code($sRfc, \intdiv(\time(), 30))), true);
check('not six digits, not a code', TwoFactorAuthTotpSlice::match($sRfc, '28708', 59), null);

/* ---- sealing ---- */
$sKey = TwoFactorRecord::key('salt-of-this-install');
$sBox = TwoFactorRecord::seal('JBSWY3DPEHPK3PXP', $sKey);
check('the secret is not in the box', \str_contains($sBox, 'JBSWY3DPEHPK3PXP'), false);
check('and comes back out', TwoFactorRecord::unseal($sBox, $sKey), 'JBSWY3DPEHPK3PXP');
check('another installation cannot open it', TwoFactorRecord::unseal($sBox, TwoFactorRecord::key('other')), null);
$sRaw = \base64_decode($sBox); $sRaw[30] = \chr(\ord($sRaw[30]) ^ 1);
check('a tampered box is refused, not guessed', TwoFactorRecord::unseal(\base64_encode($sRaw), $sKey), null);

/* ---- backup codes ---- */
$aCodes = TwoFactorRecord::newBackupCodes();
check('eight codes', \count($aCodes), 8);
check('nine digits each', \count(\array_filter($aCodes, fn ($s) => (bool) \preg_match('/^\d{9}$/', $s))), 8);
check('all different', \count(\array_unique($aCodes)), 8);
check('random_int, not rand(): the source says so', \str_contains((string) \file_get_contents(__DIR__ . '/../index.php'), '\\rand('), false);

$aRec = TwoFactorRecord::create('a@x.tn', $sRfc, $aCodes, $sKey);
$sJson = \json_encode($aRec);
check('neither the secret nor a backup code is stored in clear',
	\str_contains($sJson, $sRfc) || \str_contains($sJson, $aCodes[0]), false);

$fSlice = fn (string $sS, string $sC) => TwoFactorAuthTotpSlice::match($sS, $sC, 59);
[$sOut, $aRec] = TwoFactorRecord::check($aRec, $aCodes[3], $sKey, 1000, $fSlice);
check('a backup code works', $sOut, 'ok');
check('and is spent', \count($aRec['BackupHashes']), 7);
[$sOut, $aRec] = TwoFactorRecord::check($aRec, $aCodes[3], $sKey, 1001, $fSlice);
check('only once', $sOut, 'wrong');

/* ---- replay ---- */
$aRec = TwoFactorRecord::create('a@x.tn', $sRfc, $aCodes, $sKey);
[$sOut, $aRec] = TwoFactorRecord::check($aRec, '287082', $sKey, 1000, $fSlice);
check('a code from the phone works', $sOut, 'ok');
[$sOut, $aRec] = TwoFactorRecord::check($aRec, '287082', $sKey, 1010, $fSlice);
check('the same code again is a REPLAY, named as such', $sOut, 'replay');
$fBefore = fn (string $sS, string $sC) => 0;
[$sOut] = TwoFactorRecord::check($aRec, '000000', $sKey, 1020, $fBefore);
check('an older step too', $sOut, 'replay');

/* ---- lockout ---- */
$aRec = TwoFactorRecord::create('a@x.tn', $sRfc, $aCodes, $sKey);
$fNone = fn (string $sS, string $sC) => null;
for ($i = 0; $i < 4; ++$i) {
	[$sOut, $aRec] = TwoFactorRecord::check($aRec, '111111', $sKey, 5000 + $i, $fNone);
}
check('four wrong codes: not yet locked', TwoFactorRecord::isLocked($aRec, 5004), false);
[$sOut, $aRec] = TwoFactorRecord::check($aRec, '111111', $sKey, 5004, $fNone);
check('the fifth locks', TwoFactorRecord::isLocked($aRec, 5005), true);
[$sOut] = TwoFactorRecord::check($aRec, '287082', $sKey, 5010, $fSlice);
check('a correct code is refused while locked', $sOut, 'locked');
[$sOut] = TwoFactorRecord::check($aRec, '287082', $sKey, 5004 + 901, $fSlice);
check('fifteen minutes later it opens again', $sOut, 'ok');
$aSpread = TwoFactorRecord::create('a@x.tn', $sRfc, $aCodes, $sKey);
foreach (array(0, 1000, 2000, 3000, 4000) as $t) {
	[, $aSpread] = TwoFactorRecord::check($aSpread, '111111', $sKey, 10000 + $t, $fNone);
}
check('failures far apart do not add up', TwoFactorRecord::isLocked($aSpread, 14001), false);

/* ---- a record written by 2.20.0 ---- */
$aOld = array('User' => 'a@x.tn', 'Enable' => true, 'Secret' => $sRfc, 'BackupCodes' => '123456789 987654321', 'QRCode' => 'x');
$aNew = TwoFactorRecord::normalise($aOld, $sKey);
check('an old record is sealed on read', isset($aNew['Secret']) || isset($aNew['BackupCodes']) || isset($aNew['QRCode']), false);
check('its secret survives', TwoFactorRecord::unseal($aNew['SecretBox'], $sKey), $sRfc);
check('its backup codes still work', TwoFactorRecord::check($aNew, '987654321', $sKey, 1, $fSlice)[0], 'ok');
check('and it stays on', $aNew['Enable'], true);

/* ---- the URI ---- */
check('the issuer names the service', TwoFactorRecord::uri('a@x.tn', 'ABC', 'smail.tn'),
	'otpauth://totp/smail.tn:a%40x.tn?secret=ABC&issuer=smail.tn');
check('without an issuer, the URI of 2.20.0', TwoFactorRecord::uri('a@x.tn', 'ABC'), 'otpauth://totp/a%40x.tn?secret=ABC');

echo "\n", $iFail ? "$iFail failed\n" : "0 failed\n";
exit($iFail ? 1 : 0);
