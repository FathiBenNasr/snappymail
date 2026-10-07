<?php

/**
 * The stored second-factor record, and every decision taken on it.
 *
 * Pure: no storage, no session, no clock of its own; the plugin passes the
 * time in. That is what lets each rule below be tested on its own.
 *
 * What changed from 2.19.1, and why:
 *
 * 1. The secret and the backup codes were stored in clear JSON: whoever could
 *    read the storage directory held everyone's second factor. The secret is
 *    now sealed (libsodium secretbox, key derived from APP_SALT, which lives
 *    elsewhere on disk) and backup codes are kept as keyed hashes only; they
 *    are shown once, at creation, and never again.
 * 2. A code was valid for its whole +-1 window, so one code read over a
 *    shoulder could be replayed for 90 seconds. The last accepted time step is
 *    kept and a code from that step or an earlier one is refused, and logged
 *    as a replay, which is not the same event as a wrong code.
 * 3. Nothing slowed down guessing. The password is already known by then, and
 *    each window holds three valid codes out of a million: five failures in
 *    fifteen minutes now lock the second factor for fifteen minutes, correct
 *    code or not. Counted per account, so it also holds behind a shared NAT.
 */
final class TwoFactorRecord
{
	public const MAX_FAILURES = 5;
	public const FAILURE_WINDOW = 900;
	public const LOCK_SECONDS = 900;
	public const BACKUP_CODES = 8;
	public const BACKUP_DIGITS = 9;

	/** A 32-byte key for this installation, derived from its salt. */
	public static function key(string $sSalt) : string
	{
		return \hash_hkdf('sha256', $sSalt, 32, 'tachyon/two-factor-auth/v1');
	}

	public static function seal(string $sSecret, string $sKey) : string
	{
		$sNonce = \random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
		return \base64_encode($sNonce . \sodium_crypto_secretbox($sSecret, $sNonce, $sKey));
	}

	/** The secret, or null when the box was tampered with or sealed under another key. */
	public static function unseal(string $sBox, string $sKey) : ?string
	{
		$sRaw = (string) \base64_decode($sBox, true);
		if (\strlen($sRaw) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
			return null;
		}
		$m = \sodium_crypto_secretbox_open(\substr($sRaw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES),
			\substr($sRaw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES), $sKey);
		return false === $m ? null : $m;
	}

	/** @return string[] fresh backup codes, from a CSPRNG */
	public static function newBackupCodes() : array
	{
		$aCodes = array();
		while (\count($aCodes) < self::BACKUP_CODES) {
			$s = \str_pad((string) \random_int(0, 10 ** self::BACKUP_DIGITS - 1), self::BACKUP_DIGITS, '0', STR_PAD_LEFT);
			$aCodes[$s] = true;
		}
		// PHP turns numeric string keys into integers: "000123456" stays a
		// string, "123456789" comes back an int. Cast every one back.
		return \array_map('strval', \array_keys($aCodes));
	}

	public static function hashCode(string $sCode, string $sKey) : string
	{
		return \hash_hmac('sha256', $sCode, $sKey);
	}

	/** A new record: the secret sealed, the codes hashed. */
	public static function create(string $sUser, string $sSecret, array $aCodes, string $sKey) : array
	{
		return array(
			'User' => $sUser,
			'Enable' => false,
			'Tested' => false,
			'SecretBox' => self::seal($sSecret, $sKey),
			'BackupHashes' => \array_map(fn ($s) => self::hashCode((string) $s, $sKey), \array_values($aCodes)),
			'LastSlice' => 0,
			'Failures' => array(),
			'LockedUntil' => 0
		);
	}

	/** Whether the stored data is in the clear format of 2.19.1 and earlier. */
	public static function isLegacy(array $a) : bool
	{
		return isset($a['Secret']) && !isset($a['SecretBox']);
	}

	/**
	 * A stored record in the current shape. Records written by 2.19.1 and
	 * earlier carry the secret and the codes in clear; they come back sealed,
	 * and the plugin writes them back at once. A record that was enabled was
	 * in use, so it counts as tested.
	 */
	public static function normalise(array $a, string $sKey) : array
	{
		if (self::isLegacy($a)) {
			$a['SecretBox'] = self::seal((string) $a['Secret'], $sKey);
			$a['BackupHashes'] = \array_map(fn ($s) => self::hashCode($s, $sKey),
				\array_values(\array_filter(\explode(' ', \trim((string) \preg_replace('/[^\d]+/', ' ', (string) ($a['BackupCodes'] ?? '')))), 'strlen')));
			$a['Tested'] = !empty($a['Enable']);
			unset($a['Secret'], $a['BackupCodes'], $a['QRCode']);
		}
		return $a + array('Enable' => false, 'Tested' => false, 'BackupHashes' => array(),
			'LastSlice' => 0, 'Failures' => array(), 'LockedUntil' => 0);
	}

	public static function isLocked(array $a, int $iNow) : bool
	{
		return (int) ($a['LockedUntil'] ?? 0) > $iNow;
	}

	public static function recordFailure(array $a, int $iNow) : array
	{
		$aRecent = \array_values(\array_filter((array) ($a['Failures'] ?? array()),
			fn ($t) => (int) $t > $iNow - self::FAILURE_WINDOW));
		$aRecent[] = $iNow;
		$a['Failures'] = $aRecent;
		if (\count($aRecent) >= self::MAX_FAILURES) {
			$a['LockedUntil'] = $iNow + self::LOCK_SECONDS;
			$a['Failures'] = array();
		}
		return $a;
	}

	public static function recordSuccess(array $a, ?int $iSlice) : array
	{
		$a['Failures'] = array();
		if (null !== $iSlice) {
			$a['LastSlice'] = \max((int) ($a['LastSlice'] ?? 0), $iSlice);
		}
		return $a;
	}

	/**
	 * Spends a backup code: the record without it, or null when it is not one
	 * of this account's. Compared in constant time.
	 */
	public static function spendBackupCode(array $a, string $sCode, string $sKey) : ?array
	{
		$sHash = self::hashCode($sCode, $sKey);
		foreach ((array) ($a['BackupHashes'] ?? array()) as $i => $sStored) {
			if (\hash_equals((string) $sStored, $sHash)) {
				unset($a['BackupHashes'][$i]);
				$a['BackupHashes'] = \array_values($a['BackupHashes']);
				return $a;
			}
		}
		return null;
	}

	/**
	 * The outcome of one code against a record:
	 * `['ok', record]`, `['replay', record]`, `['wrong', record]` or `['locked', record]`.
	 * The record returned is the one to store, failures and spent codes
	 * included, whatever the outcome.
	 *
	 * A code of more than six digits is a backup code, as in 2.19.1: codes
	 * issued before 2.20.0 keep working.
	 *
	 * @param callable $fSlice fn(string $secret, string $code): ?int, the
	 *        matching time step, or null
	 */
	public static function check(array $a, string $sCode, string $sKey, int $iNow, callable $fSlice) : array
	{
		if (self::isLocked($a, $iNow)) {
			return array('locked', $a);
		}
		$sCode = \trim($sCode);
		if (6 < \strlen($sCode) && \ctype_digit($sCode)) {
			$aSpent = self::spendBackupCode($a, $sCode, $sKey);
			return null === $aSpent
				? array('wrong', self::recordFailure($a, $iNow))
				: array('ok', self::recordSuccess($aSpent, null));
		}
		$sSecret = self::unseal((string) ($a['SecretBox'] ?? ''), $sKey);
		$iSlice = (null !== $sSecret && \preg_match('/^\d{6}$/', $sCode)) ? $fSlice($sSecret, $sCode) : null;
		if (null === $iSlice) {
			return array('wrong', self::recordFailure($a, $iNow));
		}
		if ($iSlice <= (int) ($a['LastSlice'] ?? 0)) {
			return array('replay', self::recordFailure($a, $iNow));
		}
		return array('ok', self::recordSuccess($a, $iSlice));
	}

	/**
	 * The QR code as an SVG data URI: black squares on white, a quiet zone of
	 * four modules. The text QR code drawn in a <pre> depends on the font and
	 * line height; with the issuer in the URI the code grows, and some
	 * authenticators no longer read it. An image is what scanners read.
	 *
	 * @param callable $fDark fn(int $row, int $col): bool
	 */
	public static function svg(int $iModules, callable $fDark) : string
	{
		$iQuiet = 4;
		$iSize = $iModules + 2 * $iQuiet;
		$sPath = '';
		for ($r = 0; $r < $iModules; ++$r) {
			for ($c = 0; $c < $iModules; ++$c) {
				if ($fDark($r, $c)) {
					$sPath .= 'M' . ($c + $iQuiet) . ' ' . ($r + $iQuiet) . 'h1v1h-1z';
				}
			}
		}
		$sSvg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' . $iSize . ' ' . $iSize . '" shape-rendering="crispEdges">'
			. '<rect width="100%" height="100%" fill="#fff"/><path fill="#000" d="' . $sPath . '"/></svg>';
		return 'data:image/svg+xml;base64,' . \base64_encode($sSvg);
	}

	/**
	 * The otpauth URI. The issuer goes in the label AND as a parameter: it is
	 * what names the service in the authenticator. Without it the account
	 * shows up as a bare address, which stops being readable at the second one.
	 */
	public static function uri(string $sEmail, string $sSecret, string $sIssuer = '') : string
	{
		$sLabel = \rawurlencode($sEmail);
		if ('' !== $sIssuer) {
			$sLabel = \rawurlencode($sIssuer) . ':' . $sLabel;
		}
		$sUri = "otpauth://totp/{$sLabel}?secret={$sSecret}";
		if ('' !== $sIssuer) {
			$sUri .= '&issuer=' . \rawurlencode($sIssuer);
		}
		// Stated rather than left to defaults: some authenticators read them,
		// and they are what this server computes.
		return $sUri . '&algorithm=SHA1&digits=6&period=30';
	}
}
