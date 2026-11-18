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
	'otpauth://totp/smail.tn:a%40x.tn?secret=ABC&issuer=smail.tn&algorithm=SHA1&digits=6&period=30');
check('the image comes last, encoded', TwoFactorRecord::uri('a@x.tn', 'ABC', 'smail.tn', 'https://cdn.x/i.png'),
	'otpauth://totp/smail.tn:a%40x.tn?secret=ABC&issuer=smail.tn&algorithm=SHA1&digits=6&period=30&image=https%3A%2F%2Fcdn.x%2Fi.png');

/* ---- the QR code is an image a scanner reads back ---- */
require_once __DIR__ . '/../../../snappymail/v/0.0.0/app/libraries/snappymail/qrcode.php';
$sUri = TwoFactorRecord::uri('fathi.bennasr@smail.tn', 'JBSWY3DPEHPK3PXPJBSWY3DP', 'smail.tn',
	'https://cdn.convergent.tn/assets/images/smail-otp-icon.png');
$oQr = \SnappyMail\QRCode::getMinimumQRCode($sUri, \SnappyMail\QRCode::ERROR_CORRECT_LEVEL_M);
$sData = TwoFactorRecord::svg($oQr->getModuleCount(), fn (int $r, int $c) => $oQr->isDark($r, $c));
check('an SVG data URI', \str_starts_with($sData, 'data:image/svg+xml;base64,'), true);
$sZbar = \trim((string) \shell_exec('command -v zbarimg'));
$sPy = '/var/www/pdfenv/bin/python3';
if ('' !== $sZbar && \is_executable($sPy)) {
	$sDir = \sys_get_temp_dir() . '/qr-' . \bin2hex(\random_bytes(4));
	\mkdir($sDir);
	\file_put_contents("$sDir/qr.svg", \base64_decode(\substr($sData, \strlen('data:image/svg+xml;base64,'))));
	\shell_exec(\escapeshellarg($sPy) . ' -c ' . \escapeshellarg("import cairosvg; cairosvg.svg2png(url='$sDir/qr.svg', write_to='$sDir/qr.png', output_width=480)"));
	$sRead = \trim((string) \shell_exec('zbarimg --raw -q ' . \escapeshellarg("$sDir/qr.png")));
	check('zbarimg reads back exactly the URI', $sRead, $sUri);
	@\unlink("$sDir/qr.svg"); @\unlink("$sDir/qr.png"); @\rmdir($sDir);
} else {
	echo "  skip  zbarimg or cairosvg absent: the scan is not proven here\n";
}

/* ---- 2.28.0: security keys in the record ---- */
$sKeyR = TwoFactorRecord::key('salt-of-this-install');
$aB = TwoFactorRecord::blank('rym@smail.tn');
check('a blank record: no factor', array(TwoFactorRecord::isOn($aB, $sKeyR), TwoFactorRecord::hasFactor($aB, $sKeyR)), array(false, false));
$aK = TwoFactorRecord::withPasskeys($aB, array(array('Id' => 'abc', 'Name' => 'YubiKey')), $sKeyR);
check('with a key: on, and enrolled', array(TwoFactorRecord::isOn($aK, $sKeyR), TwoFactorRecord::hasFactor($aK, $sKeyR)), array(true, true));
check('the key list comes back out of its box', TwoFactorRecord::passkeys($aK, $sKeyR), array(array('Id' => 'abc', 'Name' => 'YubiKey')));
check('the box does not show the key in clear', \str_contains(\json_encode($aK), 'YubiKey'), false);
check('under another salt the box does not open: on at login (fail closed), not enrolled',
	array(TwoFactorRecord::passkeys($aK, TwoFactorRecord::key('other')), TwoFactorRecord::isOn($aK, TwoFactorRecord::key('other')), TwoFactorRecord::hasFactor($aK, TwoFactorRecord::key('other'))),
	array(null, true, false));
check('no key left: the box is gone', isset(TwoFactorRecord::withPasskeys($aK, array(), $sKeyR)['PasskeysBox']), false);

$aC = TwoFactorRecord::addChallenge($aB, 'c1', 'login', 'browser-1', 1000, 300, $sKeyR);
check('a challenge is kept with a keyed hash of the browser, not the token', \str_contains(\json_encode($aC), 'browser-1'), false);
[$bOk, $aAfter] = TwoFactorRecord::takeChallenge($aC, 'c1', 'login', 'browser-1', 1100, $sKeyR);
check('taken once, by the same purpose and browser, in time', array($bOk, $aAfter['Challenges']), array(true, array()));
check('taken twice: no', TwoFactorRecord::takeChallenge($aAfter, 'c1', 'login', 'browser-1', 1100, $sKeyR)[0], false);
[$bOk, $aAfter] = TwoFactorRecord::takeChallenge($aC, 'c1', 'reauth', 'browser-1', 1100, $sKeyR);
check('another purpose: refused, and spent all the same', array($bOk, $aAfter['Challenges']), array(false, array()));
check('another browser: refused', TwoFactorRecord::takeChallenge($aC, 'c1', 'login', 'browser-2', 1100, $sKeyR)[0], false);
check('no binding at all: refused', TwoFactorRecord::takeChallenge(TwoFactorRecord::addChallenge($aB, 'c1', 'login', '', 1000, 300, $sKeyR), 'c1', 'login', '', 1100, $sKeyR)[0], false);
check('expired: refused', TwoFactorRecord::takeChallenge($aC, 'c1', 'login', 'browser-1', 1300, $sKeyR)[0], false);
$aMany = $aB;
for ($i = 0; $i < 20; ++$i) { $aMany = TwoFactorRecord::addChallenge($aMany, "c$i", 'login', 'b', 1000, 300, $sKeyR); }
check('at most ' . TwoFactorRecord::MAX_CHALLENGES . ' pending, the newest kept', array(\count($aMany['Challenges']), \end($aMany['Challenges'])['c']), array(TwoFactorRecord::MAX_CHALLENGES, 'c19'));
check('expired ones are dropped when a new one comes', \count(TwoFactorRecord::addChallenge($aMany, 'n', 'login', 'b', 5000, 300, $sKeyR)['Challenges']), 1);

/* ---- 2.32.0: codes held until their keeper proves it ---- */
$aCodesP = TwoFactorRecord::newBackupCodes();
$aOld = TwoFactorRecord::create('u@x', 'SECRET', array('111111111'), $sKeyR);
$aKey = array('Id' => 'kid-nothex', 'Alg' => -7, 'Key' => 'k', 'SignCount' => 0);
$aP = TwoFactorRecord::startPending(TwoFactorRecord::blank('u@x'), $aCodesP, $aKey, 'browser-1', 1000, $sKeyR);
check('pending: nothing active, the codes only as hashes, the key sealed',
	array(TwoFactorRecord::isOn($aP, $sKeyR), \str_contains(\json_encode($aP), $aCodesP[0]), \str_contains(\json_encode($aP), 'kid-nothex'), \count($aP['Pending']['h'])), array(false, false, false, 8));
check('pending: valid for 15 minutes, then not', array(null !== TwoFactorRecord::pending($aP, 1000 + 899), null !== TwoFactorRecord::pending($aP, 1000 + 900)), array(true, false));
$iAsk = $aP['Pending']['ask'];
[$sO, $aR] = TwoFactorRecord::confirmPending($aP, $aCodesP[$iAsk], 'browser-1', 1100, $sKeyR);
check('confirm with the asked code: ok, key and codes in force, pending gone',
	array($sO, TwoFactorRecord::isOn($aR, $sKeyR), \count($aR['BackupHashes']), isset($aR['Pending']), TwoFactorRecord::passkeys($aR, $sKeyR)[0]['Id']), array('ok', true, 8, false, 'kid-nothex'));
check('the asked code is not spent', TwoFactorRecord::spendBackupCode($aR, $aCodesP[$iAsk], $sKeyR) !== null, true);
$sOther = $aCodesP[($iAsk + 1) % 8];
check('another code of the list: wrong, counted', array(TwoFactorRecord::confirmPending($aP, $sOther, 'browser-1', 1100, $sKeyR)[0], TwoFactorRecord::confirmPending($aP, $sOther, 'browser-1', 1100, $sKeyR)[1]['Pending']['n']), array('wrong', 1));
check('another browser: refused, not counted', array(TwoFactorRecord::confirmPending($aP, $aCodesP[$iAsk], 'browser-2', 1100, $sKeyR)[0], TwoFactorRecord::confirmPending($aP, $aCodesP[$iAsk], 'browser-2', 1100, $sKeyR)[1]['Pending']['n']), array('binding', 0));
check('no browser token at all: refused', TwoFactorRecord::confirmPending($aP, $aCodesP[$iAsk], '', 1100, $sKeyR)[0], 'binding');
check('expired: no proof', TwoFactorRecord::confirmPending($aP, $aCodesP[$iAsk], 'browser-1', 2000, $sKeyR)[0], 'none');
$aT = $aP;
for ($i = 0; $i < TwoFactorRecord::PENDING_TRIES; ++$i) { [$sO, $aT] = TwoFactorRecord::confirmPending($aT, '000000000', 'browser-1', 1100, $sKeyR); }
check('the fifth wrong proof discards the codes and the key', array($sO, isset($aT['Pending']), TwoFactorRecord::isOn($aT, $sKeyR)), array('wrong', false, false));
foreach (array('', 'abcdefghi', '12345678', '1234567890', "12345678\n") as $sBad) {
	check('hostile proof ' . \json_encode($sBad), TwoFactorRecord::confirmPending($aP, $sBad, 'browser-1', 1100, $sKeyR)[0], 'wrong');
}
$aRg = TwoFactorRecord::startPending($aOld, $aCodesP, null, 'browser-1', 1000, $sKeyR);
check('regeneration: the old codes hold until the proof', TwoFactorRecord::spendBackupCode($aRg, '111111111', $sKeyR) !== null, true);
[$sO, $aRg2] = TwoFactorRecord::confirmPending($aRg, $aCodesP[$aRg['Pending']['ask']], 'browser-1', 1100, $sKeyR);
check('regeneration confirmed: the old codes are gone, the new are in force, the authenticator untouched',
	array($sO, TwoFactorRecord::spendBackupCode($aRg2, '111111111', $sKeyR), \count($aRg2['BackupHashes']), isset($aRg2['SecretBox'])), array('ok', null, 8, true));
$aTamper = $aP; $aTamper['Pending']['kb'] = 'garbage';
check('a tampered key box cannot be confirmed into the account', array(TwoFactorRecord::confirmPending($aTamper, $aCodesP[$iAsk], 'browser-1', 1100, $sKeyR)[0], TwoFactorRecord::isOn(TwoFactorRecord::confirmPending($aTamper, $aCodesP[$iAsk], 'browser-1', 1100, $sKeyR)[1], $sKeyR)), array('none', false));
$aTamper2 = $aP; $aTamper2['Pending']['ask'] = 99;
check('a rank out of the list matches nothing', TwoFactorRecord::confirmPending($aTamper2, $aCodesP[0], 'browser-1', 1100, $sKeyR)[0], 'wrong');

/* ---- 2.33.0: a code sent to the recovery address ---- */
$sKeyE = TwoFactorRecord::key('salt');
$aE = TwoFactorRecord::blank('x@smail.tn');
check('a fresh email code: 8 digits', (bool) \preg_match('/^\d{8}$/D', TwoFactorRecord::newEmailCode()), true);
check('the email factor counts as on and as a factor', array(TwoFactorRecord::isOn($aE + array('EmailOn' => true), $sKeyE), TwoFactorRecord::hasFactor($aE + array('EmailOn' => true), $sKeyE)), array(true, true));
$aE1 = TwoFactorRecord::addEmailCode($aE, '12345678', 'b1', 'login', 1000, $sKeyE) + array('EmailOn' => true);
check('kept as a keyed hash only', \str_contains(\json_encode($aE1), '12345678'), false);
$fNo = fn () => null;
check('8 digits without an email context: wrong', TwoFactorRecord::check($aE1, '12345678', $sKeyE, 1001, $fNo)[0], 'wrong');
check('… for login with the factor off: wrong', TwoFactorRecord::check(array('EmailOn' => false) + $aE1, '12345678', $sKeyE, 1001, $fNo, array('b' => 'b1', 'p' => 'login'))[0], 'wrong');
[$sO, $aE2] = TwoFactorRecord::check($aE1, '12345678', $sKeyE, 1001, $fNo, array('b' => 'b1', 'p' => 'login'));
check('right browser, purpose, time: ok, and spent', array($sO, \count($aE2['EmailCodes'])), array('ok', 0));
check('another browser: wrong', TwoFactorRecord::check($aE1, '12345678', $sKeyE, 1001, $fNo, array('b' => 'b2', 'p' => 'login'))[0], 'wrong');
check('another purpose: wrong', TwoFactorRecord::check($aE1, '12345678', $sKeyE, 1001, $fNo, array('b' => 'b1', 'p' => 'reauth'))[0], 'wrong');
check('expired: wrong', TwoFactorRecord::check($aE1, '12345678', $sKeyE, 1000 + TwoFactorRecord::EMAIL_TTL, $fNo, array('b' => 'b1', 'p' => 'login'))[0], 'wrong');
check('no browser token: wrong', TwoFactorRecord::takeEmailCode($aE1, '12345678', '', 'login', 1001, $sKeyE)[0], false);
$aT = $aE1;
for ($i = 0; $i < TwoFactorRecord::EMAIL_TRIES; ++$i) { [, $aT] = TwoFactorRecord::takeEmailCode($aT, '00000000', 'b1', 'login', 1001, $sKeyE); }
check('five wrong tries discard the code of that browser', array(\count($aT['EmailCodes']), TwoFactorRecord::takeEmailCode($aT, '12345678', 'b1', 'login', 1002, $sKeyE)[0]), array(0, false));
[, $aT2] = TwoFactorRecord::takeEmailCode($aE1, '00000000', 'b2', 'login', 1001, $sKeyE);
check('… and tries from another browser do not count against it', $aT2['EmailCodes'][0]['n'], 0);
$aL = $aE;
foreach (array('11111111', '22222222', '33333333', '44444444') as $i => $c) { $aL = TwoFactorRecord::addEmailCode($aL, $c, 'b1', 'login', 1000 + $i, $sKeyE); }
check('at most 3 live, the oldest goes', array(\count($aL['EmailCodes']), TwoFactorRecord::takeEmailCode($aL, '11111111', 'b1', 'login', 1005, $sKeyE)[0], TwoFactorRecord::takeEmailCode($aL, '44444444', 'b1', 'login', 1005, $sKeyE)[0]), array(3, false, true));
$aS = $aE;
$aS['EmailSends'] = array(1000, 1001);
check('2 sends in 15 min: one more allowed', TwoFactorRecord::emailSendAllowed($aS, 1002), true);
$aS['EmailSends'][] = 1002;
check('3: no more', TwoFactorRecord::emailSendAllowed($aS, 1003), false);
check('… until the window passes', TwoFactorRecord::emailSendAllowed($aS, 1000 + TwoFactorRecord::EMAIL_SENDS_WINDOW + 1), true);
$aS['EmailSends'] = \range(10000, 10000 + 9 * 1000, 1000);
check('10 in a day: no more, even spread out', TwoFactorRecord::emailSendAllowed($aS, 10000 + 9 * 1000 + 1000), false);
check('… sends from the future do not count (clock set back)', TwoFactorRecord::emailSendAllowed(array('EmailSends' => array(5000, 5001, 5002)), 1000), true);
check('the email codes are not taken for backup codes, nor these for email codes', array(\strlen(TwoFactorRecord::newBackupCodes()[0]), TwoFactorRecord::EMAIL_DIGITS), array(9, 8));
$aPe = TwoFactorRecord::startPending($aE, array('123456789', '223456789'), null, 'b1', 1000, $sKeyE, true);
[$sO, $aPe2] = TwoFactorRecord::confirmPending($aPe, array('123456789', '223456789')[$aPe['Pending']['ask']], 'b1', 1001, $sKeyE);
check('confirmed pending codes switch the email factor on', array($sO, $aPe2['EmailOn'] ?? false, TwoFactorRecord::isOn($aPe2, $sKeyE)), array('ok', true, true));
$aPn = TwoFactorRecord::startPending($aE, array('123456789'), null, 'b1', 1000, $sKeyE);
check('… and plain regenerated codes do not', TwoFactorRecord::confirmPending($aPn, '123456789', 'b1', 1001, $sKeyE)[1]['EmailOn'] ?? false, false);

/* ---- 2.35.0: the code by SMS, a channel of its own, never alone ---- */
$mE = \str_repeat('a', 64); $mE2 = \str_repeat('b', 64);
$aTo = $aE; $aTo['Enable'] = true;               // a record with an authenticator on
$aSm = TwoFactorRecord::addEmailCode($aTo, '87654321', 'b1', 'login', 1000, $sKeyE, 'sms', $mE);
check('an SMS code is kept in its own list, not the email one', array(\count($aSm['SmsCodes']), isset($aSm['EmailCodes']) ? \count($aSm['EmailCodes']) : 0, \count($aSm['SmsSends'])), array(1, 0, 1));
check('… hashed with its own prefix: the stored hash is not the email one', $aSm['SmsCodes'][0]['h'] !== TwoFactorRecord::hashCode('email|87654321', $sKeyE), true);
check('SMS off: no SMS code opens a login, even a right one', TwoFactorRecord::check($aSm, '87654321', $sKeyE, 1001, $fNo, array('b' => 'b1', 'p' => 'login', 'c' => 'both', 'm' => $mE))[0], 'wrong');
$aSm['SmsOn'] = true; $aSm['SmsNum'] = $mE;
check('SMS on beside an authenticator: the right code opens the login', TwoFactorRecord::check($aSm, '87654321', $sKeyE, 1001, $fNo, array('b' => 'b1', 'p' => 'login', 'c' => 'both', 'm' => $mE))[0], 'ok');
check('… and answers to the sms channel alone as well', TwoFactorRecord::check($aSm, '87654321', $sKeyE, 1001, $fNo, array('b' => 'b1', 'p' => 'login', 'c' => 'sms', 'm' => $mE))[0], 'ok');
check('… but not where only the email channel is asked (the session proofs)', TwoFactorRecord::check($aSm, '87654321', $sKeyE, 1001, $fNo, array('b' => 'b1', 'p' => 'login'))[0], 'wrong');
check('… nor with no context at all', TwoFactorRecord::check($aSm, '87654321', $sKeyE, 1001, $fNo)[0], 'wrong');
check('… nor in the "reauth" purpose', TwoFactorRecord::check($aSm, '87654321', $sKeyE, 1001, $fNo, array('b' => 'b1', 'p' => 'reauth', 'c' => 'both', 'm' => $mE))[0], 'wrong');
check('… nor from another browser', TwoFactorRecord::check($aSm, '87654321', $sKeyE, 1001, $fNo, array('b' => 'b2', 'p' => 'login', 'c' => 'both', 'm' => $mE))[0], 'wrong');
check('… nor after ten minutes', TwoFactorRecord::check($aSm, '87654321', $sKeyE, 1000 + TwoFactorRecord::EMAIL_TTL, $fNo, array('b' => 'b1', 'p' => 'login', 'c' => 'both', 'm' => $mE))[0], 'wrong');
[$sOk, $aSpent] = TwoFactorRecord::check($aSm, '87654321', $sKeyE, 1001, $fNo, array('b' => 'b1', 'p' => 'login', 'c' => 'both', 'm' => $mE));
check('… used once', TwoFactorRecord::check($aSpent, '87654321', $sKeyE, 1002, $fNo, array('b' => 'b1', 'p' => 'login', 'c' => 'both', 'm' => $mE))[0], 'wrong');
$aT3 = $aSm;
for ($i = 0; $i < TwoFactorRecord::EMAIL_TRIES; ++$i) { [, $aT3] = TwoFactorRecord::takeEmailCode($aT3, '00000000', 'b1', 'login', 1001, $sKeyE, 'sms', $mE); }
check('five wrong tries discard the SMS code of that browser', array(\count($aT3['SmsCodes']), TwoFactorRecord::takeEmailCode($aT3, '87654321', 'b1', 'login', 1002, $sKeyE, 'sms', $mE)[0]), array(0, false));
$aBoth = TwoFactorRecord::addEmailCode($aSm, '11112222', 'b1', 'login', 1000, $sKeyE);
$aBoth['EmailOn'] = true;
check('the two channels answer each for its own code', array(
	TwoFactorRecord::check($aBoth, '11112222', $sKeyE, 1001, $fNo, array('b' => 'b1', 'p' => 'login', 'c' => 'both', 'm' => $mE))[0],
	TwoFactorRecord::check($aBoth, '87654321', $sKeyE, 1001, $fNo, array('b' => 'b1', 'p' => 'login', 'c' => 'both', 'm' => $mE))[0]), array('ok', 'ok'));
check('the SMS channel does not take the email code, nor the reverse', array(
	TwoFactorRecord::check($aBoth, '11112222', $sKeyE, 1001, $fNo, array('b' => 'b1', 'p' => 'login', 'c' => 'sms', 'm' => $mE))[0],
	TwoFactorRecord::check($aBoth, '87654321', $sKeyE, 1001, $fNo, array('b' => 'b1', 'p' => 'login', 'c' => 'email'))[0]), array('wrong', 'wrong'));
// Never alone.
$aAlone = $aSm; $aAlone['Enable'] = false;
check('SMS on with no other factor: not active, not a way in', array(TwoFactorRecord::smsActive($aAlone, $sKeyE), TwoFactorRecord::isOn($aAlone, $sKeyE), TwoFactorRecord::hasFactor($aAlone, $sKeyE)), array(false, false, false));
check('… and its code opens nothing', TwoFactorRecord::check($aAlone, '87654321', $sKeyE, 1001, $fNo, array('b' => 'b1', 'p' => 'login', 'c' => 'both', 'm' => $mE))[0], 'wrong');
check('… it is dropped when the record is read or written', array(isset(TwoFactorRecord::normalise($aAlone, $sKeyE)['SmsOn']), isset(TwoFactorRecord::dropSmsAlone($aAlone, $sKeyE)['SmsCodes'])), array(false, false));
check('… but kept while another factor stands (authenticator, or email)', array(isset(TwoFactorRecord::dropSmsAlone($aSm, $sKeyE)['SmsOn']), isset(TwoFactorRecord::dropSmsAlone(\array_merge($aAlone, array('EmailOn' => true)), $sKeyE)['SmsOn'])), array(true, true));
$aKeyBox = $aAlone; $aKeyBox['PasskeysBox'] = 'not a box';
check('… and not dropped on a doubt: an unreadable key box', isset(TwoFactorRecord::dropSmsAlone($aKeyBox, $sKeyE)['SmsOn']), true);
$aK = TwoFactorRecord::withPasskeys($aAlone, array(array('Id' => 'k1')), $sKeyE);
check('a security key counts as the other factor', TwoFactorRecord::smsActive($aK, $sKeyE), true);
// Sends are counted per channel.
$aSn = $aE; $aSn['SmsSends'] = array(1000, 1001, 1002);
check('SMS sends: 3 in 15 min is the cap, and the email count is separate', array(TwoFactorRecord::emailSendAllowed($aSn, 1003, 'sms'), TwoFactorRecord::emailSendAllowed($aSn, 1003)), array(false, true));

/* ---- 2.35.1: bound to the number, usable factors, reserve, live codes ---- */
$aCtx = fn (array $x = array()) => $x + array('b' => 'b1', 'p' => 'login', 'c' => 'both', 'm' => $mE);
check('bound: the number changed since the enrolment — the code sent to the old one opens nothing', TwoFactorRecord::check($aSm, '87654321', $sKeyE, 1001, $fNo, $aCtx(array('m' => $mE2)))[0], 'wrong');
check('bound: no fingerprint published (console without key): no SMS way in', TwoFactorRecord::check($aSm, '87654321', $sKeyE, 1001, $fNo, $aCtx(array('m' => '')))[0], 'wrong');
$aNoNum = $aSm; unset($aNoNum['SmsNum']);
check('bound: an enrolment with no number kept (legacy) does not count', TwoFactorRecord::check($aNoNum, '87654321', $sKeyE, 1001, $fNo, $aCtx())[0], 'wrong');
check('bound: a code issued for the old number is not taken even when the record is re-bound to the new one',
	TwoFactorRecord::check(array_merge($aSm, array('SmsNum' => $mE2)), '87654321', $sKeyE, 1001, $fNo, $aCtx(array('m' => $mE2)))[0], 'wrong');
check('bound: smsBound', array(TwoFactorRecord::smsBound($aSm, $mE), TwoFactorRecord::smsBound($aSm, $mE2), TwoFactorRecord::smsBound($aSm, '')), array(true, false, false));
// Usable factors.
$aEm = $aSm; $aEm['Enable'] = false; $aEm['EmailOn'] = true;
check('usable: EmailOn counts as the other factor only while the email way can be used',
	array(TwoFactorRecord::otherUsable($aEm, $sKeyE, true), TwoFactorRecord::otherUsable($aEm, $sKeyE, false), TwoFactorRecord::otherUsable($aSm, $sKeyE, false)), array(true, false, true));
check('usable: the email factor is on but cannot answer: the SMS alone opens nothing',
	TwoFactorRecord::check($aEm, '87654321', $sKeyE, 1001, $fNo, $aCtx(array('u' => false)))[0], 'wrong');
check('usable: … and where it can answer, it does', TwoFactorRecord::check($aEm, '87654321', $sKeyE, 1001, $fNo, $aCtx(array('u' => true)))[0], 'ok');
check('usable: an authenticator that is on needs no help', TwoFactorRecord::check($aSm, '87654321', $sKeyE, 1001, $fNo, $aCtx(array('u' => false)))[0], 'ok');
check('usable: the flag is kept when only the usability fails (not dropped, only suspended)', isset(TwoFactorRecord::dropSmsAlone($aEm, $sKeyE)['SmsOn']), true);
// The reserve of a browser that has signed in.
$aKn = TwoFactorRecord::addKnownBrowser($aE, 'bX', $sKeyE);
check('known: remembered as a keyed hash, never the token', array(TwoFactorRecord::isKnownBrowser($aKn, 'bX', $sKeyE), TwoFactorRecord::isKnownBrowser($aKn, 'bY', $sKeyE), TwoFactorRecord::isKnownBrowser($aKn, '', $sKeyE), \str_contains(\json_encode($aKn), 'bX')), array(true, false, false, false));
$aKm = $aE; for ($i = 0; $i < 8; ++$i) { $aKm = TwoFactorRecord::addKnownBrowser($aKm, 'b' . $i, $sKeyE); }
check('known: at most five, the oldest go, and one browser is kept once', array(\count($aKm['Known']), TwoFactorRecord::isKnownBrowser($aKm, 'b0', $sKeyE), TwoFactorRecord::isKnownBrowser($aKm, 'b7', $sKeyE), \count(TwoFactorRecord::addKnownBrowser($aKm, 'b7', $sKeyE)['Known'])), array(5, false, true, 5));
$aRs = $aE; $aRs['SmsSends'] = array(1000, 1001, 1002);
check('reserve: three in 15 minutes stop an unknown browser, a known one has two more',
	array(TwoFactorRecord::emailSendAllowed($aRs, 1003, 'sms', false), TwoFactorRecord::emailSendAllowed($aRs, 1003, 'sms', true)), array(false, true));
$aRs['SmsSends'] = array(1000, 1001, 1002, 1003, 1004);
check('reserve: … two more, not three', TwoFactorRecord::emailSendAllowed($aRs, 1005, 'sms', true), false);
$aRs['SmsSends'] = \range(10000, 10000 + 9 * 1000, 1000);
check('reserve: ten in a day stop an unknown browser; a known one has five more', array(TwoFactorRecord::emailSendAllowed($aRs, 20000, 'sms', false), TwoFactorRecord::emailSendAllowed($aRs, 20000, 'sms', true)), array(false, true));
// Live codes, and the way a login was opened.
check('live codes: only for this browser, not expired', array(TwoFactorRecord::hasLiveCode($aSm, 'b1', 1001, $sKeyE), TwoFactorRecord::hasLiveCode($aSm, 'b2', 1001, $sKeyE), TwoFactorRecord::hasLiveCode($aSm, 'b1', 1000 + TwoFactorRecord::EMAIL_TTL, $sKeyE), TwoFactorRecord::hasLiveCode($aSm, '', 1001, $sKeyE)), array(true, false, false, false));
check('the way a login was opened is kept: sms, email, backup', array(
	TwoFactorRecord::check($aSm, '87654321', $sKeyE, 1001, $fNo, $aCtx())[1]['LastFactor']['f'] ?? '',
	TwoFactorRecord::check($aBoth, '11112222', $sKeyE, 1001, $fNo, $aCtx(array('u' => true)))[1]['LastFactor']['f'] ?? '',
	TwoFactorRecord::check(array_merge($aE, array('BackupHashes' => array(TwoFactorRecord::hashCode('111111111', $sKeyE)))), '111111111', $sKeyE, 1001, $fNo)[1]['LastFactor']['f'] ?? ''), array('sms', 'email', 'backup'));

echo "\n", $iFail ? "$iFail failed\n" : "0 failed\n";
exit($iFail ? 1 : 0);
