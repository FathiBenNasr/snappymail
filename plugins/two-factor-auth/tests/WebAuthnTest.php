<?php
/**
 * two-factor-auth 2.28.0 — the WebAuthn verifier on its own (providers/webauthn.php).
 *
 * Two sources of truth, neither of them the code under test:
 *  1. keys generated here (openssl, sodium) and a software authenticator
 *     that builds the bytes from the specification (tests/authenticator.php);
 *  2. output recorded from REAL authenticators: the test vectors of
 *     py_webauthn (Duo Security, BSD-3-Clause, tests/test_verify_*.py) —
 *     a YubiKey with packed attestation (ES256 and Ed25519), a Chrome
 *     registration with attestation "none", an ES256 and an RS256 assertion.
 *
 * Run: php plugins/two-factor-auth/tests/WebAuthnTest.php
 */
declare(strict_types=1);

require __DIR__ . '/../providers/webauthn.php';
require __DIR__ . '/authenticator.php';

$iFail = 0;
$iCount = 0;
function check(string $sWhat, $mGot, $mWant) : void
{
	global $iFail, $iCount;
	++$iCount;
	$b = $mGot === $mWant;
	echo ($b ? '  ok   ' : '  FAIL ') . $sWhat . ($b ? '' : ' — got ' . \var_export($mGot, true) . ', want ' . \var_export($mWant, true)) . "\n";
	$b || ++$iFail;
}
/** The reason a call is refused, or 'accepted'. */
function refusal(callable $f) : string
{
	try {
		$f();
		return 'accepted';
	} catch (TwoFactorWebAuthnError $e) {
		return $e->getMessage();
	}
}

$b64u = fn (string $s) => SoftAuthenticator::b64u($s);
$EXPECT = array('origins' => array('https://webmail.smail.tn'), 'rpId' => 'smail.tn', 'requireUV' => false, 'counter' => 'refuse');
$stored = function (array $aReg) { return array('Id' => $aReg['Id'], 'Alg' => $aReg['Alg'], 'Key' => $aReg['Key'], 'SignCount' => $aReg['SignCount']); };

/* ---- 1. recorded from real authenticators (py_webauthn test vectors) ---- */
$LOCAL = array('origins' => array('http://localhost:5000'), 'rpId' => 'localhost');

$aNone = array('rawId' => '9y1xA8Tmg1FEmT-c7_fvWZ_uoTuoih3OvR45_oAK-cwHWhAbXrl2q62iLVTjiyEZ7O7n-CROOY494k7Q3xrs_w', 'type' => 'public-key', 'response' => array(
	'attestationObject' => 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAFwAAAAAAAAAAAAAAAAAAAAAAQPctcQPE5oNRRJk_nO_371mf7qE7qIodzr0eOf6ACvnMB1oQG165dqutoi1U44shGezu5_gkTjmOPeJO0N8a7P-lAQIDJiABIVggSFbUJF-42Ug3pdM8rDRFu_N5oiVEysPDB6n66r_7dZAiWCDUVnB39FlGypL-qAoIO9xWHtJygo2jfDmHl-_eKFRLDA',
	'clientDataJSON' => 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiVHdON240V1R5R0tMYzRaWS1xR3NGcUtuSE00bmdscXN5VjBJQ0psTjJUTzlYaVJ5RnRya2FEd1V2c3FsLWdrTEpYUDZmbkYxTWxyWjUzTW00UjdDdnciLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9'));
$r = TwoFactorWebAuthn::register($aNone, $LOCAL + array('challenge' => 'TwN7n4WTyGKLc4ZY-qGsFqKnHM4nglqsyV0ICJlN2TO9XiRyFtrkaDwUvsql-gkLJXP6fnF1MlrZ53Mm4R7Cvw'));
check('real (Chrome, "none"): registered, ES256, counter 23, UV', array($r['Id'], $r['Alg'], $r['SignCount'], $r['UV'], $r['Fmt']),
	array('9y1xA8Tmg1FEmT-c7_fvWZ_uoTuoih3OvR45_oAK-cwHWhAbXrl2q62iLVTjiyEZ7O7n-CROOY494k7Q3xrs_w', -7, 23, true, 'none'));
check('real (Chrome, "none"): the same answer to another challenge is refused',
	refusal(fn () => TwoFactorWebAuthn::register($aNone, $LOCAL + array('challenge' => 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'))), 'challenge');
check('real (Chrome, "none"): from another origin it is refused',
	refusal(fn () => TwoFactorWebAuthn::register($aNone, array('origins' => array('https://webmail.smail.tn'), 'rpId' => 'localhost', 'challenge' => 'TwN7n4WTyGKLc4ZY-qGsFqKnHM4nglqsyV0ICJlN2TO9XiRyFtrkaDwUvsql-gkLJXP6fnF1MlrZ53Mm4R7Cvw'))), 'origin');
check('real (Chrome, "none"): for another relying party it is refused',
	refusal(fn () => TwoFactorWebAuthn::register($aNone, array('origins' => array('http://localhost:5000'), 'rpId' => 'smail.tn', 'challenge' => 'TwN7n4WTyGKLc4ZY-qGsFqKnHM4nglqsyV0ICJlN2TO9XiRyFtrkaDwUvsql-gkLJXP6fnF1MlrZ53Mm4R7Cvw'))), 'rpid');

$aYubi = array('rawId' => 'syGQPDZRUYdb4m3rdWeyPaIMYlbmydGp1TP_33vE_lqJ3PHNyTd0iKsnKr5WjnCcBzcesZrDEfB_RBLFzU3k4w', 'type' => 'public-key', 'response' => array(
	'attestationObject' => 'o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIhAOfrFlQpbavT6dJeTDJSCDzYSYPjBDHli2-syT2c1IiKAiAx5gQ2z5cHjdQX-jEHTb7JcjfQoVSW8fXszF5ihSgeOGN4NWOBWQLBMIICvTCCAaWgAwIBAgIEKudiYzANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEnMCUGA1UEAwweWXViaWNvIFUyRiBFRSBTZXJpYWwgNzE5ODA3MDc1MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKgOGXmBD2Z4R_xCqJVRXhL8Jr45rHjsyFykhb1USGozZENOZ3cdovf5Ke8fj2rxi5tJGn_VnW4_6iQzKdIaeP6NsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjEwEwYLKwYBBAGC5RwCAQEEBAMCBDAwIQYLKwYBBAGC5RwBAQQEEgQQbUS6m_bsLkm5MAyP6SDLczAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQByV9A83MPhFWmEkNb4DvlbUwcjc9nmRzJjKxHc3HeK7GvVkm0H4XucVDB4jeMvTke0WHb_jFUiApvpOHh5VyMx5ydwFoKKcRs5x0_WwSWL0eTZ5WbVcHkDR9pSNcA_D_5AsUKOBcbpF5nkdVRxaQHuuIuwV4k1iK2IqtMNcU8vL6w21U261xCcWwJ6sMq4zzVO8QCKCQhsoIaWrwz828GDmPzfAjFsJiLJXuYivdHACkeJ5KHMt0mjVLpfJ2BCML7_rgbmvwL7wBW80VHfNdcKmKjkLcpEiPzwcQQhiN_qHV90t-p4iyr5xRSpurlP5zic2hlRkLKxMH2_kRjhqSn4aGF1dGhEYXRhWMRJlg3liA6MaHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XY0UAAAA0bUS6m_bsLkm5MAyP6SDLcwBAsyGQPDZRUYdb4m3rdWeyPaIMYlbmydGp1TP_33vE_lqJ3PHNyTd0iKsnKr5WjnCcBzcesZrDEfB_RBLFzU3k46UBAgMmIAEhWCBAX_i3O3DvBnkGq_uLNk_PeAX5WwO_MIxBp0mhX6Lw7yJYIOW-1-Fch829McWvRUYAHTWZTx5IycKSGECL1UzUaK_8',
	'clientDataJSON' => 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiOExCQ2lPWTNxMWNCWkhGQVd0UzRBWlpDaHpHcGh5NjdsSzdJNzB6S2k0eUM3cGdyUTJQY2g3bkFqTGsxd3E5Z3Jlc2hJQXNXMkFqaWJoWGpqSTBUbVEiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9'));
$sYubiChallenge = '8LBCiOY3q1cBZHFAWtS4AZZChzGphy67lK7I70zKi4yC7pgrQ2Pch7nAjLk1wq9greshIAsW2AjibhXjjI0TmQ';
$r = TwoFactorWebAuthn::register($aYubi, $LOCAL + array('challenge' => $sYubiChallenge));
check('real (YubiKey, packed with a certificate): its statement verifies', array($r['Alg'], $r['Fmt']), array(-7, 'packed'));
// The attestation signature, one bit off: the same object must now be refused.
$sAtt = TwoFactorWebAuthn::unb64u($aYubi['response']['attestationObject']);
$iSig = \strpos($sAtt, "\x63sigXG") + 6 + 10;
$aBad = $aYubi; $aBad['response']['attestationObject'] = $b64u(\substr_replace($sAtt, \chr(\ord($sAtt[$iSig]) ^ 1), $iSig, 1));
check('real (YubiKey): a statement signature one bit off is refused',
	refusal(fn () => TwoFactorWebAuthn::register($aBad, $LOCAL + array('challenge' => $sYubiChallenge))), 'attestation');

$aOkp = array('rawId' => 'WlHiMqH6UhUs-d43z-aGlE3nsXuEOQpa9P9pwpqb4tmvtBMBfGvAV2wUrqBCDENjkkxd6kIRzZQKcluyOFlyW_vXVZSAEgod1xj-1QmFpuwyBVnlkQGefRbmUjbEt5iE4q3tdjy65EWIekO0SNjCQx3LxIJMzi25fgUkI9Y-gg0', 'type' => 'public-key', 'response' => array(
	'attestationObject' => 'o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgB3c0BvOsyJut14wj4XVWxXliicWZMZLDNF621Zz7h_8CIQCIOqRyWOazVhqlBrD-HL-83KWAvGZRgvW-4A9SE8BLFWN4NWOBWQLBMIICvTCCAaWgAwIBAgIEK_F8eDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEnMCUGA1UEAwweWXViaWNvIFUyRiBFRSBTZXJpYWwgNzM3MjQ2MzI4MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdMLHhCPIcS6bSPJZWGb8cECuTN8H13fVha8Ek5nt-pI8vrSflxb59Vp4bDQlH8jzXj3oW1ZwUDjHC6EnGWB5i6NsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjcwEwYLKwYBBAGC5RwCAQEEBAMCAiQwIQYLKwYBBAGC5RwBAQQEEgQQxe9V_62aS5-1gK3rr-Am0DAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQCLbpN2nXhNbunZANJxAn_Cd-S4JuZsObnUiLnLLS0FPWa01TY8F7oJ8bE-aFa4kTe6NQQfi8-yiZrQ8N-JL4f7gNdQPSrH-r3iFd4SvroDe1jaJO4J9LeiFjmRdcVa-5cqNF4G1fPCofvw9W4lKnObuPakr0x_icdVq1MXhYdUtQk6Zr5mBnc4FhN9qi7DXqLHD5G7ZFUmGwfIcD2-0m1f1mwQS8yRD5-_aDCf3vutwddoi3crtivzyromwbKklR4qHunJ75LGZLZA8pJ_mXnUQ6TTsgRqPvPXgQPbSyGMf2z_DIPbQqCD_Bmc4dj9o6LozheBdDtcZCAjSPTAd_uiaGF1dGhEYXRhWOFJlg3liA6MaHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XY0EAAAACxe9V_62aS5-1gK3rr-Am0ACAWlHiMqH6UhUs-d43z-aGlE3nsXuEOQpa9P9pwpqb4tmvtBMBfGvAV2wUrqBCDENjkkxd6kIRzZQKcluyOFlyW_vXVZSAEgod1xj-1QmFpuwyBVnlkQGefRbmUjbEt5iE4q3tdjy65EWIekO0SNjCQx3LxIJMzi25fgUkI9Y-gg2kAQEDJyAGIVggnB_oUZDQU0esRlNPmjEO96aMDTgs34D8Dv31tAwhUZo',
	'clientDataJSON' => 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiN0pVQmpXWkZkRm96dWx4YjcxRHZIa2gzUDZXS1VHNEVsVW83d0VrS2ljMkpFVEpNQUlLQ2Y3ckJFOVlrc0k1b05qRHpRNkhxaDZFNzNPeTZTUGNNbnciLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9'));
$r = TwoFactorWebAuthn::register($aOkp, $LOCAL + array('challenge' => '7JUBjWZFdFozulxb71DvHkh3P6WKUG4ElUo7wEkKic2JETJMAIKCf7rBE9YksI5oNjDzQ6Hqh6E73Oy6SPcMnw'));
check('real (YubiKey, Ed25519 key, 128-byte id): registered as EdDSA', array($r['Alg'], \strlen(\base64_decode($r['Key']))), array(-8, 32));
check('real (YubiKey, Ed25519): refused when EdDSA was not offered',
	refusal(fn () => TwoFactorWebAuthn::register($aOkp, $LOCAL + array('algorithms' => array(-7, -257), 'challenge' => '7JUBjWZFdFozulxb71DvHkh3P6WKUG4ElUo7wEkKic2JETJMAIKCf7rBE9YksI5oNjDzQ6Hqh6E73Oy6SPcMnw'))), 'alg');

// Assertions recorded from real authenticators, against their stored keys.
$keyFromCose = function (string $sCose, string $sId, int $iCount) {
	[$iAlg, $sKey] = TwoFactorWebAuthn::coseKey(TwoFactorWebAuthn::cborWhole(TwoFactorWebAuthn::unb64u($sCose)), TwoFactorWebAuthn::algorithms());
	return array('Id' => $sId, 'Alg' => $iAlg, 'Key' => \base64_encode($sKey), 'SignCount' => $iCount);
};
$sEcId = 'EDx9FfAbp4obx6oll2oC4-CZuDidRVV4gZhxC529ytlnqHyqCStDUwfNdm1SNHAe3X5KvueWQdAX3x9R1a2b9Q';
$aEcKey = $keyFromCose('pQECAyYgASFYIIeDTe-gN8A-zQclHoRnGFWN8ehM1b7yAsa8I8KIvmplIlgg4nFGT5px8o6gpPZZhO01wdy9crDSA_Ngtkx0vGpvPHI', $sEcId, 77);
$aEcGet = array('rawId' => $sEcId, 'type' => 'public-key', 'response' => array(
	'authenticatorData' => 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAATg',
	'clientDataJSON' => 'eyJjaGFsbGVuZ2UiOiJ4aTMwR1BHQUZZUnhWRHBZMXNNMTBEYUx6VlFHNjZudi1fN1JVYXpIMHZJMll2RzhMWWdERW52TjVmWlpOVnV2RUR1TWk5dGUzVkxxYjQyTjBma0xHQSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6NTAwMCIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ',
	'signature' => 'MEUCIGisVZOBapCWbnJJvjelIzwpixxIwkjCCb5aCHafQu68AiEA88v-2pJNNApPFwAKFiNuf82-2hBxYW5kGwVweeoxCwo'));
$sEcChallenge = 'xi30GPGAFYRxVDpY1sM10DaLzVQG66nv-_7RUazH0vI2YvG8LYgDEnvN5fZZNVuvEDuMi9te3VLqb42N0fkLGA';
$a = TwoFactorWebAuthn::assert($aEcGet, $LOCAL + array('challenge' => $sEcChallenge), array($aEcKey));
check('real ES256 assertion: verified, counter 77 → 78, no UV', array($a['index'], $a['signCount'], $a['regression'], $a['uv']), array(0, 78, false, false));
check('real ES256 assertion: replayed against a stored counter of 78, refused as a counter regression',
	refusal(fn () => TwoFactorWebAuthn::assert($aEcGet, $LOCAL + array('challenge' => $sEcChallenge), array(array('SignCount' => 78) + $aEcKey))), 'counter');
check('real ES256 assertion: requiring user verification refuses it (UV flag absent)',
	refusal(fn () => TwoFactorWebAuthn::assert($aEcGet, $LOCAL + array('challenge' => $sEcChallenge, 'requireUV' => true), array($aEcKey))), 'verification');

$sRsaId = 'ZoIKP1JQvKdrYj1bTUPJ2eTUsbLeFkv-X5xJQNr4k6s';
$aRsaKey = $keyFromCose('pAEDAzkBACBZAQDfV20epzvQP-HtcdDpX-cGzdOxy73WQEvsU7Dnr9UWJophEfpngouvgnRLXaEUn_d8HGkp_HIx8rrpkx4BVs6X_B6ZjhLlezjIdJbLbVeb92BaEsmNn1HW2N9Xj2QM8cH-yx28_vCjf82ahQ9gyAr552Bn96G22n8jqFRQKdVpO-f-bvpvaP3IQ9F5LCX7CUaxptgbog1SFO6FI6ob5SlVVB00lVXsaYg8cIDZxCkkENkGiFPgwEaZ7995SCbiyCpUJbMqToLMgojPkAhWeyktu7TlK6UBWdJMHc3FPAIs0lH_2_2hKS-mGI1uZAFVAfW1X-mzKL0czUm2P1UlUox7IUMBAAE', $sRsaId, 0);
$aRsaGet = array('rawId' => $sRsaId, 'type' => 'public-key', 'response' => array(
	'authenticatorData' => 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAQ',
	'clientDataJSON' => 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiaVBtQWkxUHAxWEw2b0FncTNQV1p0WlBuWmExekZVRG9HYmFRMF9LdlZHMWxGMnMzUnRfM280dVN6Y2N5MHRtY1RJcFRUVDRCVTFULUk0bWFhdm5kalEiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9',
	'signature' => 'iOHKX3erU5_OYP_r_9HLZ-CexCE4bQRrxM8WmuoKTDdhAnZSeTP0sjECjvjfeS8MJzN1ArmvV0H0C3yy_FdRFfcpUPZzdZ7bBcmPh1XPdxRwY747OrIzcTLTFQUPdn1U-izCZtP_78VGw9pCpdMsv4CUzZdJbEcRtQuRS03qUjqDaovoJhOqEBmxJn9Wu8tBi_Qx7A33RbYjlfyLm_EDqimzDZhyietyop6XUcpKarKqVH0M6mMrM5zTjp8xf3W7odFCadXEJg-ERZqFM0-9Uup6kJNLbr6C5J4NDYmSm3HCSA6lp2iEiMPKU8Ii7QZ61kybXLxsX4w4Dm3fOLjmDw',
	'userHandle' => 'T1RWa1l6VXdPRFV0WW1NNVlTMDBOVEkxTFRnd056Z3RabVZpWVdZNFpEVm1ZMk5p'));
$sRsaChallenge = 'iPmAi1Pp1XL6oAgq3PWZtZPnZa1zFUDoGbaQ0_KvVG1lF2s3Rt_3o4uSzccy0tmcTIpTTT4BU1T-I4maavndjQ';
$a = TwoFactorWebAuthn::assert($aRsaGet, $LOCAL + array('challenge' => $sRsaChallenge, 'userHandle' => 'T1RWa1l6VXdPRFV0WW1NNVlTMDBOVEkxTFRnd056Z3RabVZpWVdZNFpEVm1ZMk5p'), array($aRsaKey));
check('real RS256 assertion: verified, with user verification and its user handle', array($a['signCount'], $a['uv']), array(1, true));
check('real RS256 assertion: the user handle of another account is refused',
	refusal(fn () => TwoFactorWebAuthn::assert($aRsaGet, $LOCAL + array('challenge' => $sRsaChallenge, 'userHandle' => 'b3RoZXItYWNjb3VudA'), array($aRsaKey))), 'user');
check('real RS256 assertion: verified against the EC key of another credential, refused (no key for this id)',
	refusal(fn () => TwoFactorWebAuthn::assert($aRsaGet, $LOCAL + array('challenge' => $sRsaChallenge), array($aEcKey))), 'unknown-credential');
check('real RS256 assertion: the right id but another key, the signature does not verify',
	refusal(fn () => TwoFactorWebAuthn::assert($aRsaGet, $LOCAL + array('challenge' => $sRsaChallenge), array(array('Id' => $sRsaId) + $aEcKey))), 'signature');

/* ---- 2. generated keys, every algorithm, every check ---- */
foreach (array(-7 => 'ES256', -257 => 'RS256', -8 => 'EdDSA') as $iAlg => $sAlg) {
	$k = new SoftAuthenticator($iAlg);
	foreach (array('none', 'packed') as $sFmt) {
		$aReg = TwoFactorWebAuthn::register($k->create('Y2hhbGxlbmdlLXJlZ2lzdGVyLTE', array('fmt' => $sFmt)), $EXPECT + array('challenge' => 'Y2hhbGxlbmdlLXJlZ2lzdGVyLTE'));
		check("$sAlg, attestation $sFmt: registered", array($aReg['Alg'], $aReg['Fmt'], $aReg['Id']), array($iAlg, $sFmt, $b64u($k->credentialId)));
	}
	$a = TwoFactorWebAuthn::assert($k->get('Y2hhbGxlbmdlLWxvZ2luLTE'), $EXPECT + array('challenge' => 'Y2hhbGxlbmdlLWxvZ2luLTE'), array($stored($aReg)));
	check("$sAlg: a valid assertion", array($a['index'], $a['signCount']), array(0, 1));
	$aGet = $k->get('Y2hhbGxlbmdlLWxvZ2luLTE');
	// One bit flipped (setting a byte to a value could leave it unchanged, once in 256 runs).
	$sSig = TwoFactorWebAuthn::unb64u($aGet['response']['signature']);
	$aGet['response']['signature'] = $b64u(\substr_replace($sSig, \chr(\ord($sSig[-2]) ^ 1), -2, 1));
	check("$sAlg: a signature changed by one byte is refused",
		refusal(fn () => TwoFactorWebAuthn::assert($aGet, $EXPECT + array('challenge' => 'Y2hhbGxlbmdlLWxvZ2luLTE'), array($stored($aReg)))), 'signature');
}

$k = new SoftAuthenticator(-7);
$sC = 'Y2hhbGxlbmdlLXJlZ2lzdGVyLTE';
$aReg = TwoFactorWebAuthn::register($k->create($sC), $EXPECT + array('challenge' => $sC));
$aKeys = array($stored($aReg));
$sG = 'Y2hhbGxlbmdlLWxvZ2luLTI';
$assert = fn (array $o = array(), array $e = array(), ?array $aK = null) => refusal(fn () => TwoFactorWebAuthn::assert($k->get($o['challenge'] ?? $sG, $o), $e + $EXPECT + array('challenge' => $sG), $aK ?? $aKeys));
$register = fn (array $o = array(), array $e = array()) => refusal(fn () => TwoFactorWebAuthn::register($k->create($o['challenge'] ?? $sC, $o), $e + $EXPECT + array('challenge' => $sC)));

check('the same assertion, every check passing: accepted', $assert(), 'accepted');
check('wrong origin (a look-alike) is refused', $assert(array('origin' => 'https://webmail.smail.tn.evil.com')), 'origin');
check('http:// for the https:// origin is refused', $assert(array('origin' => 'http://webmail.smail.tn')), 'origin');
check('a cross-origin frame is refused', $assert(array('client' => array('crossOrigin' => true))), 'origin');
check('wrong rpId (another domain) is refused', $assert(array('rpId' => 'evil.tn')), 'rpid');
check('a challenge the server did not issue is refused', $assert(array('challenge' => 'b3RoZXItY2hhbGxlbmdlLXh4eA')), 'challenge');
check('no pending challenge (spent or expired): nothing can match', $assert(array(), array('challenge' => null)), 'challenge');
check('a registration answer presented as a login is refused (type)', $assert(array('type' => 'webauthn.create')), 'type');
check('user not present (UP flag clear) is refused', $assert(array('flags' => 0x04)), 'presence');
check('user verification required and absent is refused', $assert(array('flags' => 0x01), array('requireUV' => true)), 'verification');
check('user verification required and present is accepted', $assert(array('flags' => 0x05), array('requireUV' => true)), 'accepted');
check('attested-data flag in an assertion is refused (no attested data follows)', $assert(array('flags' => 0x45)), 'authdata');
$aTen = array(array('SignCount' => 10) + $aKeys[0]);
check('signCount regression (10 stored, 5 received) is refused', $assert(array('counter' => 5), array(), $aTen), 'counter');
check('signCount equal (10, 10) is refused too', $assert(array('counter' => 10), array(), $aTen), 'counter');
check('signCount growing (10, 11) is accepted', $assert(array('counter' => 11), array(), $aTen), 'accepted');
check('signCount regression accepted when the setting says warn', $assert(array('counter' => 5), array('counter' => 'warn'), $aTen), 'accepted');
check('signCount 0 and 0 (an authenticator without counter): accepted', $assert(array('counter' => 0), array(), array(array('SignCount' => 0) + $aKeys[0])), 'accepted');
$aOther = $stored(TwoFactorWebAuthn::register((new SoftAuthenticator(-7))->create($sC), $EXPECT + array('challenge' => $sC)));
check('a credential of another account (not in this account\'s list) is refused', $assert(array(), array(), array($aOther)), 'unknown-credential');
check('an empty list of keys refuses everything', $assert(array(), array(), array()), 'unknown-credential');

check('registration: valid', $register(), 'accepted');
check('registration: wrong origin', $register(array('origin' => 'https://smail.tn.example')), 'origin');
check('registration: wrong rpId', $register(array('rpId' => 'example.com')), 'rpid');
check('registration: a login answer presented as a registration', $register(array('type' => 'webauthn.get')), 'type');
check('registration: replayed against a later challenge', $register(array(), array('challenge' => 'bmV3LWNoYWxsZW5nZS0wMDAwMQ')), 'challenge');
check('registration: user not present', $register(array('flags' => 0x44)), 'presence');
check('registration: no attested credential', $register(array('flags' => 0x05)), 'authdata');
check('registration: rawId not the credential id in authenticatorData', $register(array('rawId' => \random_bytes(32))), 'id');
check('registration: an attestation format not supported (tpm)', $register(array('fmt' => 'tpm', 'attStmt' => array('alg' => -7))), 'attestation');
check('registration: "none" with a statement', $register(array('attStmt' => array('x' => 1))), 'attestation');
check('registration: packed self-attestation signed by another key', $register(array('fmt' => 'packed', 'attStmt' => array('alg' => -7, 'sig' => (new SoftAuthenticator(-7))->sign('x')))), 'attestation');
check('registration: packed self-attestation naming another algorithm', $register(array('fmt' => 'packed', 'attStmt' => array('alg' => -257, 'sig' => 'x'))), 'attestation');
$aCose = $k->cose(); $aCose[-3] = \str_repeat("\x01", 32);
check('registration: an EC point not on the curve', $register(array('cose' => $aCose)), 'cose');
$aCose = $k->cose(); $aCose[-1] = 2;
check('registration: an EC key on another curve (P-384 label)', $register(array('cose' => $aCose)), 'cose');
$aCose = $k->cose(); $aCose[3] = -36;
check('registration: an algorithm not offered (ES512)', $register(array('cose' => $aCose)), 'alg');
check('registration: an RSA key of 1024 bits', refusal(fn () => TwoFactorWebAuthn::register((new SoftAuthenticator(-257, null, 1024))->create($sC), $EXPECT + array('challenge' => $sC))), 'cose');
check('registration: trailing bytes after the key in authenticatorData', $register(array('trailing' => "\x00")), 'authdata');
check('registration: extensions announced (ED) are read, and accepted', $register(array('flags' => 0xC5, 'trailing' => Cbor::encode(array('credProtect' => 2)))), 'accepted');
check('registration: a credential id of 1024 bytes', refusal(fn () => TwoFactorWebAuthn::register((new SoftAuthenticator(-7, \str_repeat('i', 1024)))->create($sC), $EXPECT + array('challenge' => $sC))), 'authdata');

/* ---- 3. CBOR, strictly bounded ---- */
$cbor = fn (string $s) => refusal(fn () => TwoFactorWebAuthn::cborWhole($s));
check('CBOR: a well-formed map', TwoFactorWebAuthn::cborWhole(Cbor::encode(array(1 => 2, -1 => 'x', 'fmt' => new CborText('none')))), array(1 => 2, -1 => 'x', 'fmt' => 'none'));
check('CBOR: empty input', $cbor(''), 'cbor');
check('CBOR: truncated (a map of 2 with 1 item)', $cbor("\xa2\x01\x02"), 'cbor');
check('CBOR: a byte string longer than the input', $cbor("\x5a\x7f\xff\xff\xff" . 'abc'), 'cbor');
check('CBOR: a 64-bit length beyond PHP_INT_MAX', $cbor("\x5b\xff\xff\xff\xff\xff\xff\xff\xff"), 'cbor');
check('CBOR: indefinite length', $cbor("\x5f\x41a\xff"), 'cbor');
check('CBOR: indefinite map', $cbor("\xbf\x01\x02\xff"), 'cbor');
check('CBOR: reserved additional information (28)', $cbor("\x1c"), 'cbor');
check('CBOR: a tag', $cbor("\xc0\x60"), 'cbor');
check('CBOR: a float', $cbor("\xfa\x00\x00\x00\x00"), 'cbor');
check('CBOR: undefined', $cbor("\xf7"), 'cbor');
check('CBOR: trailing bytes after the item', $cbor("\x01\x02"), 'cbor');
check('CBOR: nesting beyond ' . TwoFactorWebAuthn::MAX_CBOR_DEPTH . ' levels', $cbor(\str_repeat("\x81", 20) . "\x01"), 'cbor');
check('CBOR: an array announcing 65 items', $cbor("\x98\x41" . \str_repeat("\x01", 65)), 'cbor');
check('CBOR: an array announcing 2^32 items (no allocation, refused first)', $cbor("\x9a\xff\xff\xff\xff"), 'cbor');
check('CBOR: more than ' . TwoFactorWebAuthn::MAX_CBOR_NODES . ' items in all', $cbor("\x98\x40" . \str_repeat("\x98\x40" . \str_repeat("\x01", 64), 64)), 'cbor');
check('CBOR: a duplicate key', $cbor("\xa2\x01\x02\x01\x03"), 'cbor');
check('CBOR: a text key PHP would turn into an integer ("1")', $cbor("\xa1\x61\x31\x02"), 'cbor');
check('CBOR: a map key that is an array', $cbor("\xa1\x80\x01"), 'cbor');
check('CBOR: text that is not UTF-8', $cbor("\x62\xc3\x28"), 'cbor');
check('CBOR: input over ' . TwoFactorWebAuthn::MAX_INPUT . ' bytes', $cbor("\x5a" . \pack('N', 20000) . \str_repeat('a', 20000)), 'cbor');
check('base64url: a character outside the alphabet', refusal(fn () => TwoFactorWebAuthn::unb64u('ab+c')), 'encoding');
check('base64url: an impossible length', refusal(fn () => TwoFactorWebAuthn::unb64u('abcde')), 'encoding');
check('the credential: not JSON', refusal(fn () => TwoFactorWebAuthn::decodeCredential('{')), 'format');
check('the credential: not a public-key credential', refusal(fn () => TwoFactorWebAuthn::decodeCredential('{"type":"password","rawId":"","response":{}}')), 'format');
check('client data: not JSON', refusal(fn () => TwoFactorWebAuthn::clientData('nope', 'webauthn.get', 'x', array('o'))), 'clientdata');
check('client data: too long', refusal(fn () => TwoFactorWebAuthn::clientData(\str_repeat(' ', 5000) . '{}', 'webauthn.get', 'x', array('o'))), 'clientdata');

echo "\n{$iCount} checks, ", $iFail ? "$iFail failed\n" : "0 failed\n";
exit($iFail ? 1 : 0);
