<?php
/**
 * A software authenticator for the tests: real key pairs (openssl for ES256
 * and RS256, sodium for Ed25519), and the bytes a browser would send —
 * clientDataJSON, authenticatorData, attestationObject, signatures —
 * built here from the specification, not by the code under test.
 *
 * Its own CBOR encoder is deliberately separate from the plugin's decoder:
 * a test that encoded with the decoder's own idea of CBOR would prove
 * nothing about it.
 */
declare(strict_types=1);

/** A CBOR text string (a PHP string alone is encoded as bytes). */
final class CborText { public function __construct(public string $s) {} }

final class Cbor
{
	public static function head(int $iMajor, int $n) : string
	{
		if ($n < 24) { return \chr($iMajor << 5 | $n); }
		if ($n < 0x100) { return \chr($iMajor << 5 | 24) . \chr($n); }
		if ($n < 0x10000) { return \chr($iMajor << 5 | 25) . \pack('n', $n); }
		if ($n < 0x100000000) { return \chr($iMajor << 5 | 26) . \pack('N', $n); }
		return \chr($iMajor << 5 | 27) . \pack('J', $n);
	}

	public static function encode(mixed $v) : string
	{
		if ($v instanceof CborText) { return self::head(3, \strlen($v->s)) . $v->s; }
		if (\is_int($v)) { return $v >= 0 ? self::head(0, $v) : self::head(1, -1 - $v); }
		if (\is_string($v)) { return self::head(2, \strlen($v)) . $v; }
		if (\is_bool($v)) { return $v ? "\xf5" : "\xf4"; }
		if (null === $v) { return "\xf6"; }
		if (\is_array($v) && \array_is_list($v) && $v) {
			return self::head(4, \count($v)) . \implode('', \array_map([self::class, 'encode'], $v));
		}
		$s = self::head(5, \count($v));
		foreach ($v as $k => $x) {
			$s .= (\is_int($k) ? self::encode($k) : self::encode(new CborText($k))) . self::encode($x);
		}
		return $s;
	}
}

final class SoftAuthenticator
{
	public string $credentialId;
	public int $counter = 0;
	private $private;
	private array $cose;

	public function __construct(public int $alg = -7, ?string $sId = null, int $iRsaBits = 2048)
	{
		$this->credentialId = $sId ?? \random_bytes(32);
		switch ($alg) {
			case -7:
				$this->private = \openssl_pkey_new(array('private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1'));
				$d = \openssl_pkey_get_details($this->private)['ec'];
				$this->cose = array(1 => 2, 3 => -7, -1 => 1,
					-2 => \str_pad($d['x'], 32, "\0", STR_PAD_LEFT), -3 => \str_pad($d['y'], 32, "\0", STR_PAD_LEFT));
				break;
			case -257:
				$this->private = \openssl_pkey_new(array('private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => $iRsaBits));
				$d = \openssl_pkey_get_details($this->private)['rsa'];
				$this->cose = array(1 => 3, 3 => -257, -1 => $d['n'], -2 => $d['e']);
				break;
			case -8:
				$this->private = \sodium_crypto_sign_keypair();
				$this->cose = array(1 => 1, 3 => -8, -1 => 6, -2 => \sodium_crypto_sign_publickey($this->private));
				break;
			default:
				throw new \InvalidArgumentException("alg $alg");
		}
	}

	public function cose() : array { return $this->cose; }

	public function sign(string $sData) : string
	{
		if (-8 === $this->alg) {
			return \sodium_crypto_sign_detached($sData, \sodium_crypto_sign_secretkey($this->private));
		}
		\openssl_sign($sData, $sSig, $this->private, OPENSSL_ALGO_SHA256);
		return $sSig;
	}

	public static function b64u(string $s) : string { return \rtrim(\strtr(\base64_encode($s), '+/', '-_'), '='); }

	public static function clientData(string $sType, string $sChallenge, string $sOrigin, array $aExtra = array()) : string
	{
		return \json_encode($aExtra + array('type' => $sType, 'challenge' => $sChallenge, 'origin' => $sOrigin, 'crossOrigin' => false), JSON_UNESCAPED_SLASHES);
	}

	/**
	 * navigator.credentials.create(), serialised as the plugin's JavaScript
	 * sends it. $o: fmt ('none', 'packed' self-attestation), flags, rpId,
	 * origin, type, cose (override), attStmt (override), trailing (bytes).
	 */
	public function create(string $sChallenge, array $o = array()) : array
	{
		$sClientData = self::clientData($o['type'] ?? 'webauthn.create', $sChallenge, $o['origin'] ?? 'https://webmail.smail.tn', $o['client'] ?? array());
		$sAuth = \hash('sha256', $o['rpId'] ?? 'smail.tn', true) . \chr($o['flags'] ?? 0x45) . \pack('N', $this->counter)
			. \str_repeat("\0", 16) . \pack('n', \strlen($this->credentialId)) . $this->credentialId
			. Cbor::encode($o['cose'] ?? $this->cose) . ($o['trailing'] ?? '');
		$sFmt = $o['fmt'] ?? 'none';
		$aStmt = $o['attStmt'] ?? ('packed' === $sFmt
			? array('alg' => $this->alg, 'sig' => $this->sign($sAuth . \hash('sha256', $sClientData, true)))
			: array());
		return array(
			'id' => self::b64u($this->credentialId),
			'rawId' => self::b64u($o['rawId'] ?? $this->credentialId),
			'type' => 'public-key',
			'response' => array(
				'clientDataJSON' => self::b64u($sClientData),
				'attestationObject' => self::b64u(Cbor::encode(array('fmt' => new CborText($sFmt), 'attStmt' => $aStmt, 'authData' => $sAuth)))
			)
		);
	}

	/** navigator.credentials.get(): $o as above, plus counter, userHandle, signature (override). */
	public function get(string $sChallenge, array $o = array()) : array
	{
		$this->counter = $o['counter'] ?? $this->counter + 1;
		$sClientData = self::clientData($o['type'] ?? 'webauthn.get', $sChallenge, $o['origin'] ?? 'https://webmail.smail.tn', $o['client'] ?? array());
		$sAuth = \hash('sha256', $o['rpId'] ?? 'smail.tn', true) . \chr($o['flags'] ?? 0x05) . \pack('N', $this->counter);
		$a = array(
			'id' => self::b64u($this->credentialId),
			'rawId' => self::b64u($this->credentialId),
			'type' => 'public-key',
			'response' => array(
				'clientDataJSON' => self::b64u($sClientData),
				'authenticatorData' => self::b64u($sAuth),
				'signature' => self::b64u($o['signature'] ?? $this->sign($sAuth . \hash('sha256', $sClientData, true)))
			)
		);
		isset($o['userHandle']) && $a['response']['userHandle'] = $o['userHandle'];
		return $a;
	}
}
