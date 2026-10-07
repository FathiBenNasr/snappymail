<?php

class TwoFactorAuthTotp implements TwoFactorAuthInterface
{
	public function Label() : string
	{
		return 'Two Factor Authenticator Code';
	}

	public function VerifyCode(string $sSecret, string $sCode) : bool
	{
		return null !== TwoFactorAuthTotpSlice::match($sSecret, $sCode, \time());
	}

	/**
	 * The 30-second time step the code belongs to, or null. The core's
	 * \Tachyon\Util\TOTP::Verify() only answers yes or no; refusing a replay
	 * needs to know WHICH step matched.
	 */
	public function MatchingSlice(string $sSecret, string $sCode, ?int $iNow = null) : ?int
	{
		return TwoFactorAuthTotpSlice::match($sSecret, $sCode, $iNow ?? \time());
	}

	public function CreateSecret() : string
	{
		return \Tachyon\Util\TOTP::CreateSecret();
	}

}

/**
 * The same RFC 6238 computation as the core's TOTP::Verify() (SHA-1, six
 * digits, 30-second steps, one step of drift each way), reusing its base32
 * decoder, but returning the step that matched.
 */
abstract class TwoFactorAuthTotpSlice extends \Tachyon\Util\TOTP
{
	public static function code(string $sSecret, int $iSlice) : string
	{
		$sKey = static::Base32Decode($sSecret);
		$sCounter = \str_pad(\pack('N*', $iSlice), 8, "\x00", STR_PAD_LEFT);
		$sHmac = \hash_hmac('SHA1', $sCounter, $sKey, true);
		$aValue = \unpack('N', \substr($sHmac, \ord(\substr($sHmac, -1)) & 0x0F, 4));
		return \str_pad((string) (($aValue[1] & 0x7FFFFFFF) % 1000000), 6, '0', STR_PAD_LEFT);
	}

	public static function match(string $sSecret, string $sCode, int $iNow) : ?int
	{
		if (!\preg_match('/^\d{6}$/', $sCode) || '' === $sSecret) {
			return null;
		}
		$iSlice = \intdiv($iNow, 30);
		foreach (array($iSlice - 1, $iSlice, $iSlice + 1) as $i) {
			if (\hash_equals(static::code($sSecret, $i), $sCode)) {
				return $i;
			}
		}
		return null;
	}
}
