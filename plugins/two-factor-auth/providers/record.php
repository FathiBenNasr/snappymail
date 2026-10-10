<?php

/**
 * The stored second-factor record, and every decision taken on it.
 *
 * Pure: no storage, no session, no clock of its own — the plugin passes the
 * time in. That is what lets each rule below be tested on its own.
 *
 * What changed from 2.20.0, and why (audit of 19 September 2026):
 *
 * 1. Backup codes came from rand() — a Mersenne Twister, not a CSPRNG — and
 *    they bypass the TOTP. They now come from random_int().
 * 2. The secret and the backup codes were stored in clear JSON: whoever could
 *    read the storage directory held everyone's second factor. The secret is
 *    now sealed (libsodium secretbox, key derived from APP_SALT, which lives
 *    elsewhere on disk) and backup codes are kept as keyed hashes only — they
 *    are shown once, at creation, and never again.
 * 3. A code was valid for its whole ±1 window, so one read over a shoulder
 *    could be replayed for 90 seconds. The last accepted time step is kept and
 *    a code from that step or an earlier one is refused — and logged as a
 *    replay, which is not the same event as a wrong code.
 * 4. Nothing slowed down guessing. The password is already known by then, and
 *    each window holds three valid codes out of a million: five failures in
 *    fifteen minutes now lock the second factor for fifteen minutes, correct
 *    code or not. Counted per account, so it holds behind a shared NAT too.
 */
final class TwoFactorRecord
{
	public const MAX_FAILURES = 5;
	public const FAILURE_WINDOW = 900;
	public const LOCK_SECONDS = 900;
	public const BACKUP_CODES = 8;
	public const BACKUP_DIGITS = 9;
	/** Pending WebAuthn challenges kept per account; the oldest goes first. */
	public const MAX_CHALLENGES = 8;

	/** A 32-byte key for this installation, derived from its salt. */
	public static function key(string $sSalt) : string
	{
		return \hash_hkdf('sha256', $sSalt, 32, 'snappymail/two-factor-auth/v1');
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
		// ⚠️ PHP turns the numeric keys into integers: "000123456" stays a
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

	/**
	 * A stored record in the current shape. Records written by 2.20.0 and
	 * earlier carry the secret and the codes in clear; they are rewritten
	 * sealed the next time the plugin saves them.
	 */
	public static function normalise(array $a, string $sKey) : array
	{
		if (isset($a['Secret']) && !isset($a['SecretBox'])) {
			$a['SecretBox'] = self::seal((string) $a['Secret'], $sKey);
			$a['BackupHashes'] = \array_map(fn ($s) => self::hashCode($s, $sKey),
				\array_values(\array_filter(\explode(' ', \trim((string) \preg_replace('/[^\d]+/', ' ', (string) ($a['BackupCodes'] ?? '')))), 'strlen')));
			unset($a['Secret'], $a['BackupCodes'], $a['QRCode']);
		}
		return $a + array('Enable' => false, 'Tested' => false, 'BackupHashes' => array(),
			'LastSlice' => 0, 'Failures' => array(), 'LockedUntil' => 0, 'Challenges' => array());
	}

	/** A record with no TOTP secret: the account registers a security key first (2.28.0). */
	public static function blank(string $sUser) : array
	{
		return array(
			'User' => $sUser,
			'Enable' => false,
			'Tested' => false,
			'BackupHashes' => array(),
			'LastSlice' => 0,
			'Failures' => array(),
			'LockedUntil' => 0,
			'Challenges' => array()
		);
	}

	/* ---- security keys (WebAuthn, 2.28.0) ---- */

	/**
	 * The registered security keys, or null when their box cannot be opened.
	 *
	 * Sealed like the TOTP secret, and for a reason of its own: a public key
	 * is no secret, but whoever could WRITE the storage could otherwise add
	 * a key of theirs to anyone's account. The box is authenticated: without
	 * APP_SALT, nothing can be added that opens.
	 */
	public static function passkeys(array $a, string $sKey) : ?array
	{
		if (empty($a['PasskeysBox'])) {
			return array();
		}
		$s = self::unseal((string) $a['PasskeysBox'], $sKey);
		if (null === $s) {
			return null;
		}
		try {
			$l = \json_decode($s, true, 8, JSON_THROW_ON_ERROR);
		} catch (\Throwable $e) {
			return null;
		}
		return \is_array($l) ? \array_values($l) : null;
	}

	public static function withPasskeys(array $a, array $aKeys, string $sKey) : array
	{
		if (!$aKeys) {
			unset($a['PasskeysBox']);
			return $a;
		}
		$a['PasskeysBox'] = self::seal(\json_encode(\array_values($aKeys)), $sKey);
		return $a;
	}

	/**
	 * Whether a login must pass a second factor: TOTP on, or a key registered.
	 * A key box that cannot be opened counts as ON — the login is refused
	 * rather than let through on the password alone (fail closed).
	 */
	public static function isOn(array $a, string $sKey) : bool
	{
		if (!empty($a['Enable'])) {
			return true;
		}
		$aKeys = self::passkeys($a, $sKey);
		return null === $aKeys || \count($aKeys) > 0;
	}

	/**
	 * Whether the account has a second factor it can actually use — what
	 * "enrolled" means for enforcement. An unreadable key box is NOT one:
	 * counted as not set up, as an unreadable record already is.
	 */
	public static function hasFactor(array $a, string $sKey) : bool
	{
		return !empty($a['Enable']) || (bool) self::passkeys($a, $sKey);
	}

	/**
	 * A challenge, kept until it is used or expires. Bound to a purpose
	 * (login, register, reauth) and to the browser that asked (a keyed hash
	 * of its connection token): one issued at login cannot confirm a removal,
	 * nor one issued to one browser serve in another.
	 */
	public static function addChallenge(array $a, string $sChallenge, string $sPurpose, string $sBinding, int $iNow, int $iTtl, string $sKey) : array
	{
		$aList = \array_values(\array_filter((array) ($a['Challenges'] ?? array()),
			fn ($c) => \is_array($c) && (int) ($c['e'] ?? 0) > $iNow));
		$aList[] = array('c' => $sChallenge, 'p' => $sPurpose, 'b' => self::hashCode($sBinding, $sKey), 'e' => $iNow + $iTtl);
		$a['Challenges'] = \array_slice($aList, -self::MAX_CHALLENGES);
		return $a;
	}

	/**
	 * Spends a challenge: [usable, record without it]. Removed whatever the
	 * outcome — a challenge is used once, even by a failed attempt — and
	 * expired ones are dropped on the way. Usable only for the same purpose,
	 * from the same browser, before it expires.
	 */
	public static function takeChallenge(array $a, ?string $sChallenge, string $sPurpose, string $sBinding, int $iNow, string $sKey) : array
	{
		$bUsable = false;
		$aList = array();
		foreach ((array) ($a['Challenges'] ?? array()) as $c) {
			if (!\is_array($c) || (int) ($c['e'] ?? 0) <= $iNow) {
				continue;
			}
			if (null !== $sChallenge && \is_string($c['c'] ?? null) && \hash_equals($c['c'], $sChallenge)) {
				$bUsable = $sPurpose === ($c['p'] ?? '') && '' !== $sBinding
					&& \hash_equals((string) ($c['b'] ?? ''), self::hashCode($sBinding, $sKey));
				continue;
			}
			$aList[] = $c;
		}
		$a['Challenges'] = $aList;
		return array($bUsable, $a);
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
	 * The record returned is the one to store — failures and spent codes
	 * included — whatever the outcome.
	 *
	 * @param callable $fSlice fn(string $secret, string $code): ?int — the
	 *        matching time step, or null
	 */
	public static function check(array $a, string $sCode, string $sKey, int $iNow, callable $fSlice) : array
	{
		if (self::isLocked($a, $iNow)) {
			return array('locked', $a);
		}
		$sCode = \trim($sCode);
		if (\strlen($sCode) === self::BACKUP_DIGITS && \ctype_digit($sCode)) {
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
	 * The QR code as an SVG data URI — black squares on white, a quiet zone of
	 * four modules. 2.20.0 drew it as text in a `<pre>`: with the issuer and
	 * the image URL the code grows, and FreeOTP+ would not read the characters
	 * (5 October 2026). An image is what Pharos shows, and what scanners read.
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
	 * what names the service in the authenticator — without it the account
	 * shows up as a bare address, which stops being readable at the second one.
	 */
	public static function uri(string $sEmail, string $sSecret, string $sIssuer = '', string $sImage = '') : string
	{
		$sLabel = \rawurlencode($sEmail);
		if ('' !== $sIssuer) {
			$sLabel = \rawurlencode($sIssuer) . ':' . $sLabel;
		}
		$sUri = "otpauth://totp/{$sLabel}?secret={$sSecret}";
		if ('' !== $sIssuer) {
			$sUri .= '&issuer=' . \rawurlencode($sIssuer);
		}
		// Stated rather than left to defaults, as Pharos does: FreeOTP+ and a
		// few others read them, and they are what this server computes.
		$sUri .= '&algorithm=SHA1&digits=6&period=30';
		if ('' !== $sImage) {
			$sUri .= '&image=' . \rawurlencode($sImage);
		}
		return $sUri;
	}
}
