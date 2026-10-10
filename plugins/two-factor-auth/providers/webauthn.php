<?php

/**
 * WebAuthn (security keys and passkeys) as a SECOND factor — the ceremonies,
 * verified on the server, with no third-party library (2.28.0).
 *
 * Pure: no storage, no session, no clock — the plugin passes in what it
 * expects (challenge, origins, relying party, stored keys) and stores what
 * comes out. Every check below is therefore testable on its own, with real
 * keys and real authenticator output (tests/WebAuthnTest.php).
 *
 * What it accepts, and nothing else:
 *  - algorithms ES256 (-7, P-256), RS256 (-257, 2048 to 4096 bits) through
 *    openssl, EdDSA (-8, Ed25519) through sodium;
 *  - attestation "none" (what browsers send when "none" is asked, as here)
 *    and "packed" — self-attestation verified with the credential key, x5c
 *    verified with the leaf certificate's key. The certificate chain is NOT
 *    checked against any root: attestation is never used here to trust a
 *    model of authenticator, only to refuse a statement that does not verify;
 *  - CBOR as the WebAuthn data actually uses it: definite lengths only, no
 *    floats, no tags, bounded depth, size and item count, no duplicate key,
 *    and no text key PHP would silently turn into an integer.
 *
 * Every refusal is a TwoFactorWebAuthnError whose message is a short reason
 * ('origin', 'rpid', 'challenge', 'signature', 'counter'...): the log says
 * which check failed, the person is only told "refused".
 */
final class TwoFactorWebAuthnError extends \RuntimeException
{
}

final class TwoFactorWebAuthn
{
	public const ALG_ES256 = -7;
	public const ALG_EDDSA = -8;
	public const ALG_RS256 = -257;

	public const FLAG_UP = 0x01;
	public const FLAG_UV = 0x04;
	public const FLAG_BE = 0x08;
	public const FLAG_BS = 0x10;
	public const FLAG_AT = 0x40;
	public const FLAG_ED = 0x80;

	/** Bounds of what the browser may send: a few KB at most, in practice. */
	public const MAX_INPUT = 16384;
	public const MAX_CLIENT_DATA = 4096;
	public const MAX_CREDENTIAL_ID = 1023;
	public const MAX_CBOR_DEPTH = 8;
	public const MAX_CBOR_ITEMS = 64;
	public const MAX_CBOR_NODES = 512;

	/** The algorithms this server verifies, in order of preference. */
	public static function algorithms() : array
	{
		$a = array(self::ALG_ES256);
		if (\function_exists('sodium_crypto_sign_verify_detached')) {
			$a[] = self::ALG_EDDSA;
		}
		$a[] = self::ALG_RS256;
		return $a;
	}

	/* ---- base64url ---- */

	public static function b64u(string $s) : string
	{
		return \rtrim(\strtr(\base64_encode($s), '+/', '-_'), '=');
	}

	/** Strict: the alphabet of base64url, without padding or with the exact one. */
	public static function unb64u(string $s) : string
	{
		if (\strlen($s) > 2 * self::MAX_INPUT || !\preg_match('/^[A-Za-z0-9_-]*={0,2}$/', $s)) {
			throw new TwoFactorWebAuthnError('encoding');
		}
		$s = \rtrim($s, '=');
		if (1 === \strlen($s) % 4) {
			throw new TwoFactorWebAuthnError('encoding');
		}
		$r = \base64_decode(\strtr($s, '-_', '+/') . \str_repeat('=', (4 - \strlen($s) % 4) % 4), true);
		if (false === $r) {
			throw new TwoFactorWebAuthnError('encoding');
		}
		return $r;
	}

	/* ---- CBOR (RFC 8949), the subset WebAuthn uses ---- */

	/**
	 * One CBOR item from $s at $i; $i is moved past it. Byte strings and text
	 * strings both come back as PHP strings (text checked to be UTF-8).
	 */
	public static function cbor(string $s, int &$i = 0, int $iDepth = 0, ?int &$iNodes = null) : mixed
	{
		$iNodes = ($iNodes ?? 0) + 1;
		if ($iDepth > self::MAX_CBOR_DEPTH || $iNodes > self::MAX_CBOR_NODES || \strlen($s) > self::MAX_INPUT) {
			throw new TwoFactorWebAuthnError('cbor');
		}
		$n = \strlen($s);
		if ($i >= $n) {
			throw new TwoFactorWebAuthnError('cbor');
		}
		$b = \ord($s[$i++]);
		$iMajor = $b >> 5;
		$iInfo = $b & 31;
		if (7 === $iMajor) {
			// false, true, null; no float, no undefined, no simple value.
			switch ($iInfo) {
				case 20: return false;
				case 21: return true;
				case 22: return null;
			}
			throw new TwoFactorWebAuthnError('cbor');
		}
		if ($iInfo < 24) {
			$iLen = $iInfo;
		} else if ($iInfo <= 27) {
			$k = 1 << ($iInfo - 24);
			if ($i + $k > $n) {
				throw new TwoFactorWebAuthnError('cbor');
			}
			$sRaw = \substr($s, $i, $k);
			$i += $k;
			if (8 === $k && \ord($sRaw[0]) & 0x80) {
				// Beyond PHP_INT_MAX: no WebAuthn field is that large.
				throw new TwoFactorWebAuthnError('cbor');
			}
			$iLen = 0;
			for ($j = 0; $j < $k; ++$j) {
				$iLen = ($iLen << 8) | \ord($sRaw[$j]);
			}
		} else {
			// 28-30 reserved, 31 indefinite length: refused.
			throw new TwoFactorWebAuthnError('cbor');
		}
		switch ($iMajor) {
			case 0:
				return $iLen;
			case 1:
				return -1 - $iLen;
			case 2:
			case 3:
				if ($iLen > $n - $i) {
					throw new TwoFactorWebAuthnError('cbor');
				}
				$v = \substr($s, $i, $iLen);
				$i += $iLen;
				if (3 === $iMajor && !\mb_check_encoding($v, 'UTF-8')) {
					throw new TwoFactorWebAuthnError('cbor');
				}
				return $v;
			case 4:
				if ($iLen > self::MAX_CBOR_ITEMS) {
					throw new TwoFactorWebAuthnError('cbor');
				}
				$a = array();
				for ($j = 0; $j < $iLen; ++$j) {
					$a[] = self::cbor($s, $i, $iDepth + 1, $iNodes);
				}
				return $a;
			case 5:
				if ($iLen > self::MAX_CBOR_ITEMS) {
					throw new TwoFactorWebAuthnError('cbor');
				}
				$a = array();
				for ($j = 0; $j < $iLen; ++$j) {
					$k = self::cbor($s, $i, $iDepth + 1, $iNodes);
					// A text key "1" would become the integer key 1 in PHP and
					// collide with COSE's labels: refused rather than confused.
					if (!\is_int($k) && !(\is_string($k) && !\preg_match('/^(0|-?[1-9][0-9]*)$/', $k))) {
						throw new TwoFactorWebAuthnError('cbor');
					}
					if (\array_key_exists($k, $a)) {
						throw new TwoFactorWebAuthnError('cbor');
					}
					$a[$k] = self::cbor($s, $i, $iDepth + 1, $iNodes);
				}
				return $a;
		}
		// Major type 6 (tags): not used by WebAuthn.
		throw new TwoFactorWebAuthnError('cbor');
	}

	/** One CBOR item that must fill $s exactly. */
	public static function cborWhole(string $s) : mixed
	{
		$i = 0;
		$v = self::cbor($s, $i);
		if ($i !== \strlen($s)) {
			throw new TwoFactorWebAuthnError('cbor');
		}
		return $v;
	}

	/* ---- authenticator data (WebAuthn §6.1) ---- */

	public static function parseAuthData(string $s) : array
	{
		$n = \strlen($s);
		if ($n < 37 || $n > self::MAX_INPUT) {
			throw new TwoFactorWebAuthnError('authdata');
		}
		$a = array(
			'rpIdHash' => \substr($s, 0, 32),
			'flags' => \ord($s[32]),
			'signCount' => \unpack('N', \substr($s, 33, 4))[1],
			'aaguid' => null,
			'credentialId' => null,
			'cose' => null
		);
		$i = 37;
		if ($a['flags'] & self::FLAG_AT) {
			if ($n < $i + 18) {
				throw new TwoFactorWebAuthnError('authdata');
			}
			$a['aaguid'] = \substr($s, $i, 16);
			$iLen = \unpack('n', \substr($s, $i + 16, 2))[1];
			$i += 18;
			if ($iLen < 16 || $iLen > self::MAX_CREDENTIAL_ID || $n < $i + $iLen) {
				throw new TwoFactorWebAuthnError('authdata');
			}
			$a['credentialId'] = \substr($s, $i, $iLen);
			$i += $iLen;
			$a['cose'] = self::cbor($s, $i);
			if (!\is_array($a['cose'])) {
				throw new TwoFactorWebAuthnError('cose');
			}
		}
		if ($a['flags'] & self::FLAG_ED) {
			if (!\is_array(self::cbor($s, $i))) {
				throw new TwoFactorWebAuthnError('authdata');
			}
		}
		if ($i !== $n) {
			// Trailing bytes the flags do not announce.
			throw new TwoFactorWebAuthnError('authdata');
		}
		return $a;
	}

	/* ---- COSE keys (RFC 9053) ---- */

	/**
	 * A COSE public key, checked, as what is stored: [alg, key] where key is
	 * the DER SubjectPublicKeyInfo (ES256, RS256) or the raw 32 bytes (EdDSA).
	 */
	public static function coseKey(array $c, array $aAllowed) : array
	{
		$iAlg = $c[3] ?? null;
		if (!\is_int($iAlg) || !\in_array($iAlg, $aAllowed, true) || !\in_array($iAlg, self::algorithms(), true)) {
			throw new TwoFactorWebAuthnError('alg');
		}
		$iKty = $c[1] ?? null;
		switch ($iAlg) {
			case self::ALG_ES256:
				$x = $c[-2] ?? null;
				$y = $c[-3] ?? null;
				if (2 !== $iKty || 1 !== ($c[-1] ?? null) || !\is_string($x) || !\is_string($y) || 32 !== \strlen($x) || 32 !== \strlen($y)) {
					throw new TwoFactorWebAuthnError('cose');
				}
				$sDer = \hex2bin('3059301306072a8648ce3d020106082a8648ce3d030107034200') . "\x04" . $x . $y;
				// OpenSSL refuses a point that is not on the curve.
				$k = @\openssl_pkey_get_public(self::pem($sDer));
				$d = $k ? \openssl_pkey_get_details($k) : false;
				if (!$d || OPENSSL_KEYTYPE_EC !== $d['type'] || 'prime256v1' !== ($d['ec']['curve_name'] ?? '')) {
					throw new TwoFactorWebAuthnError('cose');
				}
				return array($iAlg, $sDer);
			case self::ALG_RS256:
				$sN = $c[-1] ?? null;
				$sE = $c[-2] ?? null;
				if (3 !== $iKty || !\is_string($sN) || !\is_string($sE) || '' === $sE || \strlen($sE) > 8) {
					throw new TwoFactorWebAuthnError('cose');
				}
				$sN = \ltrim($sN, "\x00");
				if (\strlen($sN) < 256 || \strlen($sN) > 512) {
					throw new TwoFactorWebAuthnError('cose');
				}
				$sDer = self::der(0x30,
					self::der(0x30, \hex2bin('06092a864886f70d010101') . "\x05\x00")
					. self::der(0x03, "\x00" . self::der(0x30, self::derInt($sN) . self::derInt($sE))));
				$k = @\openssl_pkey_get_public(self::pem($sDer));
				$d = $k ? \openssl_pkey_get_details($k) : false;
				if (!$d || OPENSSL_KEYTYPE_RSA !== $d['type'] || $d['bits'] < 2048) {
					throw new TwoFactorWebAuthnError('cose');
				}
				return array($iAlg, $sDer);
			case self::ALG_EDDSA:
				$x = $c[-2] ?? null;
				if (1 !== $iKty || 6 !== ($c[-1] ?? null) || !\is_string($x) || 32 !== \strlen($x)) {
					throw new TwoFactorWebAuthnError('cose');
				}
				return array($iAlg, $x);
		}
		throw new TwoFactorWebAuthnError('alg');
	}

	public static function verify(int $iAlg, string $sKey, string $sData, string $sSignature) : bool
	{
		if ('' === $sSignature || \strlen($sSignature) > 1024) {
			return false;
		}
		switch ($iAlg) {
			case self::ALG_ES256:
			case self::ALG_RS256:
				return 1 === @\openssl_verify($sData, $sSignature, self::pem($sKey), OPENSSL_ALGO_SHA256);
			case self::ALG_EDDSA:
				return 64 === \strlen($sSignature) && 32 === \strlen($sKey)
					&& \sodium_crypto_sign_verify_detached($sSignature, $sData, $sKey);
		}
		return false;
	}

	public static function pem(string $sDer, string $sLabel = 'PUBLIC KEY') : string
	{
		return "-----BEGIN {$sLabel}-----\n" . \chunk_split(\base64_encode($sDer), 64, "\n") . "-----END {$sLabel}-----\n";
	}

	private static function der(int $iTag, string $s) : string
	{
		$n = \strlen($s);
		if ($n < 128) {
			return \chr($iTag) . \chr($n) . $s;
		}
		$sLen = \ltrim(\pack('N', $n), "\x00");
		return \chr($iTag) . \chr(0x80 | \strlen($sLen)) . $sLen . $s;
	}

	private static function derInt(string $s) : string
	{
		$s = \ltrim($s, "\x00");
		if ('' === $s || \ord($s[0]) & 0x80) {
			$s = "\x00" . $s;
		}
		return self::der(0x02, $s);
	}

	/* ---- client data (WebAuthn §5.8.1) ---- */

	/**
	 * The decoded clientDataJSON, checked: type, challenge, origin, and not
	 * from a cross-origin frame.
	 *
	 * @param ?string $sChallenge base64url of the challenge this server issued;
	 *        null when none is pending — then nothing can match.
	 */
	public static function clientData(string $sRaw, string $sType, ?string $sChallenge, array $aOrigins) : array
	{
		if (\strlen($sRaw) > self::MAX_CLIENT_DATA) {
			throw new TwoFactorWebAuthnError('clientdata');
		}
		try {
			$a = \json_decode($sRaw, true, 4, JSON_THROW_ON_ERROR);
		} catch (\Throwable $e) {
			throw new TwoFactorWebAuthnError('clientdata');
		}
		if (!\is_array($a) || !\is_string($a['type'] ?? null) || !\is_string($a['challenge'] ?? null) || !\is_string($a['origin'] ?? null)) {
			throw new TwoFactorWebAuthnError('clientdata');
		}
		if ($sType !== $a['type']) {
			throw new TwoFactorWebAuthnError('type');
		}
		if (null === $sChallenge || '' === $sChallenge || !\hash_equals($sChallenge, $a['challenge'])) {
			throw new TwoFactorWebAuthnError('challenge');
		}
		if (!\in_array($a['origin'], $aOrigins, true)) {
			throw new TwoFactorWebAuthnError('origin');
		}
		if (true === ($a['crossOrigin'] ?? false)) {
			throw new TwoFactorWebAuthnError('origin');
		}
		return $a;
	}

	/** The challenge the browser says it signed, or null: to spend it whatever happens next. */
	public static function presentedChallenge(array $aCredential) : ?string
	{
		try {
			$a = \json_decode(self::unb64u((string) ($aCredential['response']['clientDataJSON'] ?? '')), true, 4, JSON_THROW_ON_ERROR);
			return \is_array($a) && \is_string($a['challenge'] ?? null) && \preg_match('/^[A-Za-z0-9_-]{16,128}$/', $a['challenge'])
				? $a['challenge'] : null;
		} catch (\Throwable $e) {
			return null;
		}
	}

	/** The credential as the browser sent it (JSON), bounded. */
	public static function decodeCredential(string $sJson) : array
	{
		if ('' === $sJson || \strlen($sJson) > 2 * self::MAX_INPUT) {
			throw new TwoFactorWebAuthnError('format');
		}
		try {
			$a = \json_decode($sJson, true, 6, JSON_THROW_ON_ERROR);
		} catch (\Throwable $e) {
			throw new TwoFactorWebAuthnError('format');
		}
		if (!\is_array($a) || 'public-key' !== ($a['type'] ?? null) || !\is_string($a['rawId'] ?? null) || !\is_array($a['response'] ?? null)) {
			throw new TwoFactorWebAuthnError('format');
		}
		return $a;
	}

	/* ---- the two ceremonies ---- */

	/**
	 * Registration (WebAuthn §7.1). $aExpect: challenge (base64url or null),
	 * origins, rpId, requireUV, algorithms.
	 *
	 * @return array the credential to store: Id (base64url), Alg, Key
	 *         (base64), SignCount, UV, BE, Fmt
	 */
	public static function register(array $aCredential, array $aExpect) : array
	{
		$r = $aCredential['response'];
		$sClientData = self::unb64u((string) ($r['clientDataJSON'] ?? ''));
		self::clientData($sClientData, 'webauthn.create', $aExpect['challenge'] ?? null, (array) $aExpect['origins']);

		$sAtt = self::unb64u((string) ($r['attestationObject'] ?? ''));
		$aAtt = self::cborWhole($sAtt);
		if (!\is_array($aAtt) || !\is_string($aAtt['fmt'] ?? null) || !\is_array($aAtt['attStmt'] ?? null) || !\is_string($aAtt['authData'] ?? null)) {
			throw new TwoFactorWebAuthnError('format');
		}
		$aAuth = self::parseAuthData($aAtt['authData']);
		self::checkAuthData($aAuth, $aExpect);
		if (!($aAuth['flags'] & self::FLAG_AT) || null === $aAuth['credentialId']) {
			throw new TwoFactorWebAuthnError('flags');
		}
		if (!\hash_equals($aAuth['credentialId'], self::unb64u($aCredential['rawId']))) {
			throw new TwoFactorWebAuthnError('id');
		}
		[$iAlg, $sKey] = self::coseKey($aAuth['cose'], (array) ($aExpect['algorithms'] ?? self::algorithms()));

		$sSigned = $aAtt['authData'] . \hash('sha256', $sClientData, true);
		$aStmt = $aAtt['attStmt'];
		switch ($aAtt['fmt']) {
			case 'none':
				if ($aStmt) {
					throw new TwoFactorWebAuthnError('attestation');
				}
				break;
			case 'packed':
				$iStmtAlg = $aStmt['alg'] ?? null;
				$sSig = $aStmt['sig'] ?? null;
				if (!\is_int($iStmtAlg) || !\is_string($sSig)) {
					throw new TwoFactorWebAuthnError('attestation');
				}
				if (isset($aStmt['x5c'])) {
					// Signed by the attestation certificate: its key verifies the
					// statement; its chain is not trusted, nor needed to be.
					$sCert = \is_array($aStmt['x5c']) && \is_string($aStmt['x5c'][0] ?? null) ? $aStmt['x5c'][0] : '';
					$oKey = '' === $sCert ? false : @\openssl_pkey_get_public(self::pem($sCert, 'CERTIFICATE'));
					if (!$oKey || !\in_array($iStmtAlg, array(self::ALG_ES256, self::ALG_RS256), true)
					 || 1 !== @\openssl_verify($sSigned, $sSig, $oKey, OPENSSL_ALGO_SHA256)) {
						throw new TwoFactorWebAuthnError('attestation');
					}
				} else {
					// Self-attestation: the new credential signs its own birth.
					if ($iStmtAlg !== $iAlg || !self::verify($iAlg, $sKey, $sSigned, $sSig)) {
						throw new TwoFactorWebAuthnError('attestation');
					}
				}
				break;
			default:
				throw new TwoFactorWebAuthnError('attestation');
		}

		return array(
			'Id' => self::b64u($aAuth['credentialId']),
			'Alg' => $iAlg,
			'Key' => \base64_encode($sKey),
			'SignCount' => $aAuth['signCount'],
			'UV' => (bool) ($aAuth['flags'] & self::FLAG_UV),
			'BE' => (bool) ($aAuth['flags'] & self::FLAG_BE),
			'Fmt' => $aAtt['fmt']
		);
	}

	/**
	 * Assertion (WebAuthn §7.2). $aExpect as for register(), plus userHandle
	 * (base64url, '' to skip) and counter ('refuse' or 'warn'). $aKeys: the
	 * stored credentials of THIS account — a credential of anyone else is
	 * simply not in it.
	 *
	 * @return array index (in $aKeys), signCount, regression (bool), uv (bool)
	 */
	public static function assert(array $aCredential, array $aExpect, array $aKeys) : array
	{
		$sId = self::b64u(self::unb64u($aCredential['rawId']));
		$iIndex = null;
		foreach (\array_values($aKeys) as $i => $aKey) {
			if (\is_string($aKey['Id'] ?? null) && \hash_equals($aKey['Id'], $sId)) {
				$iIndex = $i;
			}
		}
		if (null === $iIndex) {
			throw new TwoFactorWebAuthnError('unknown-credential');
		}
		$aKey = \array_values($aKeys)[$iIndex];
		$r = $aCredential['response'];

		$sHandle = (string) ($r['userHandle'] ?? '');
		if ('' !== $sHandle && '' !== (string) ($aExpect['userHandle'] ?? '')
		 && !\hash_equals((string) $aExpect['userHandle'], self::b64u(self::unb64u($sHandle)))) {
			throw new TwoFactorWebAuthnError('user');
		}

		$sClientData = self::unb64u((string) ($r['clientDataJSON'] ?? ''));
		self::clientData($sClientData, 'webauthn.get', $aExpect['challenge'] ?? null, (array) $aExpect['origins']);

		$sAuth = self::unb64u((string) ($r['authenticatorData'] ?? ''));
		$aAuth = self::parseAuthData($sAuth);
		if ($aAuth['flags'] & self::FLAG_AT) {
			throw new TwoFactorWebAuthnError('flags');
		}
		self::checkAuthData($aAuth, $aExpect);

		$sSig = self::unb64u((string) ($r['signature'] ?? ''));
		$sKey = (string) \base64_decode((string) ($aKey['Key'] ?? ''), true);
		if (!self::verify((int) ($aKey['Alg'] ?? 0), $sKey, $sAuth . \hash('sha256', $sClientData, true), $sSig)) {
			throw new TwoFactorWebAuthnError('signature');
		}

		// §7.2 step 21: a counter that does not grow may mean a cloned key.
		// Both zero is an authenticator without a counter (most passkeys).
		$iStored = (int) ($aKey['SignCount'] ?? 0);
		$iNew = $aAuth['signCount'];
		$bRegression = ($iNew || $iStored) && $iNew <= $iStored;
		if ($bRegression && 'warn' !== ($aExpect['counter'] ?? 'refuse')) {
			throw new TwoFactorWebAuthnError('counter');
		}
		return array(
			'index' => $iIndex,
			'signCount' => \max($iNew, $iStored),
			'regression' => $bRegression,
			'uv' => (bool) ($aAuth['flags'] & self::FLAG_UV)
		);
	}

	/** rpIdHash, user present, user verified when required. */
	private static function checkAuthData(array $aAuth, array $aExpect) : void
	{
		if (!\hash_equals(\hash('sha256', (string) $aExpect['rpId'], true), $aAuth['rpIdHash'])) {
			throw new TwoFactorWebAuthnError('rpid');
		}
		if (!($aAuth['flags'] & self::FLAG_UP)) {
			throw new TwoFactorWebAuthnError('presence');
		}
		if (!empty($aExpect['requireUV']) && !($aAuth['flags'] & self::FLAG_UV)) {
			throw new TwoFactorWebAuthnError('verification');
		}
	}
}
