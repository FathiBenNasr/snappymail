<?php
/**
 * two-factor-auth 2.21.0 — the actions, through the real plugin class, with
 * the core reduced to what the plugin touches.
 *
 * Run: php plugins/two-factor-auth/tests/ActionsTest.php (from the snappymail tree)
 */
declare(strict_types=1);

namespace RainLoop\Exceptions { class ClientException extends \Exception {} }
namespace RainLoop { class Notifications { const AuthError = 102; }
	class Api { public static function Config() { return new class { public function Get($a, $b, $c = null) { return 'smail.tn'; } }; } } }
namespace RainLoop\Model { class MainAccount { public function __construct(private string $e) {} public function Email() : string { return $this->e; } } }
namespace RainLoop\Providers\Storage\Enumerations { class StorageType { const CONFIG = 1; } }
namespace RainLoop\Enumerations { class PluginPropertyType { const BOOL = 1; const STRING = 2; } }
namespace RainLoop\Plugins {
	class Property { public static function NewInstance($n) { return new self; } public function __call($m, $a) { return $this; } }
	abstract class AbstractPlugin
	{
		public array $params = array();
		public array $config = array();
		public function UseLangs($b) : void {}
		public function addJs($f) : void {}
		public function addHook($a, $b) : void {}
		public function addJsonHook($a, $b) : void {}
		public function addTemplate($f) : void {}
		public function jsonParam(string $k, $d = null) { return $this->params[$k] ?? $d; }
		public function jsonResponse(string $f, $m) : array { return array('Result' => $m); }
		public function Config() { $c = $this->config; return new class ($c) { public function __construct(private array $c) {} public function Get($s, $k, $d = null) { return $this->c[$k] ?? $d; } }; }
		public function logWrite($m, $l = 0) {}
	}
}

namespace {
	define('APP_SALT', 'salt-of-this-install');
	require __DIR__ . '/../../../snappymail/v/0.0.0/app/libraries/snappymail/totp.php';
	require __DIR__ . '/../../../snappymail/v/0.0.0/app/libraries/snappymail/qrcode.php';
	require __DIR__ . '/../index.php';

	final class Storage
	{
		public array $data = array();
		public function Get($a, $t, $k) { return $this->data[$a->Email()] ?? ''; }
		public function Put($a, $t, $k, $v) : bool { $this->data[$a->Email()] = $v; return true; }
		public function Clear($a, $t, $k) : bool { unset($this->data[$a->Email()]); return true; }
	}
	// The real class declares typed accessors; the double swaps them through a subclass hook.
	final class P extends TwoFactorAuthPlugin
	{
		public Storage $oStore;
		public \RainLoop\Model\MainAccount $oAccount;
		public array $log = array();
		public int $authFailures = 0;
		public function __construct() { $this->oStore = new Storage(); $this->oAccount = new \RainLoop\Model\MainAccount('rym@smail.tn'); }
		protected function Logger() : \MailSo\Log\Logger { return new \MailSo\Log\Logger($this); }
		protected function getMainAccountFromToken() : \RainLoop\Model\MainAccount { return $this->oAccount; }
		protected function StorageProvider() : \RainLoop\Providers\Storage { return new \RainLoop\Providers\Storage($this->oStore); }
		protected function logAuthFailure(\RainLoop\Model\MainAccount $o, string $s) : void { ++$this->authFailures; }
		public function Manager() { $p = $this; return new class ($p) { public function __construct(private $p) {} public function Actions() { $p = $this->p; return new class ($p) {
			public function __construct(private $p) {}
			public function HasActionParam($k) { return false; } }; } }; }
	}
}
namespace MailSo\Log { class Logger { public function __construct(private $p) {} public function Write($m) { $this->p->log[] = $m; } } }
namespace RainLoop\Providers { class Storage { public function __construct(private $s) {}
	public function Get($a, $t, $k) { return $this->s->Get($a, $t, $k); }
	public function Put($a, $t, $k, $v) { return $this->s->Put($a, $t, $k, $v); }
	public function Clear($a, $t, $k) { return $this->s->Clear($a, $t, $k); } } }

namespace {
	$iFail = 0;
	$check = function (string $w, $g, $e) use (&$iFail) { $b = $g === $e;
		echo ($b ? '  ok   ' : '  FAIL ') . $w . ($b ? '' : ' — got ' . \var_export($g, true)) . "\n"; $b || ++$iFail; };
	$current = fn (string $s) => TwoFactorAuthTotpSlice::code($s, \intdiv(\time(), 30));
	$previous = fn (string $s) => TwoFactorAuthTotpSlice::code($s, \intdiv(\time(), 30) - 1);

	$p = new P();
	$c = $p->DoCreateTwoFactorSecret()['Result'];
	$sSecret = $c['Secret'];
	$check('creation shows the secret, the QR with the service name, and 8 codes once',
		array(\strlen($sSecret) >= 16, \str_starts_with($c['QRCode'], 'data:image/svg+xml;base64,'), \count(\explode(' ', $c['BackupCodes']))), array(true, true, 8));
	$check('the stored record holds neither', \str_contains(\reset($p->oStore->data), $sSecret), false);
	$check('the info screen never sees secret, codes or QR', \array_keys($p->DoGetTwoFactorInfo()['Result']), array('User', 'IsSet', 'Enable', 'Tested'));

	$p->params = array('Enable' => '1');
	$check('cannot switch on before the phone was tested', $p->DoEnableTwoFactor()['Result'], false);
	$p->params = array('Code' => '000000');
	$check('a wrong test code is refused', $p->DoVerifyTwoFactorCode()['Result'], false);
	$p->params = array('Code' => $previous($sSecret));
	$check('a right one passes', $p->DoVerifyTwoFactorCode()['Result'], true);
	$p->params = array('Enable' => '1');
	$check('now it switches on', $p->DoEnableTwoFactor()['Result'], true);
	$check('the secret is no longer shown once on', $p->DoShowTwoFactorSecret()['Result'], false);
	$check('nor can it be re-created over itself', $p->DoCreateTwoFactorSecret()['Result'], false);

	$p->params = array('Enable' => '0');
	$check('switching off without a code is refused', $p->DoEnableTwoFactor()['Result'], false);
	$p->params = array();
	$check('clearing without a code is refused', $p->DoClearTwoFactorInfo()['Result'], false);
	$check('still on', $p->DoGetTwoFactorInfo()['Result']['Enable'], true);

	$p->params = array('totp_code' => $current($sSecret));
	$p->DoLogin($p->oAccount);
	$check('login with the current code', \end($p->log), 'TFA: Code verified for rym@smail.tn');
	try { $p->DoLogin($p->oAccount); $check('the same code again is refused', false, true); }
	catch (\RainLoop\Exceptions\ClientException $e) { $check('the same code again is refused', \in_array('TFA: replay for rym@smail.tn', $p->log, true), true); }
	$check('and reaches the auth log fail2ban reads', $p->authFailures, 1);

	$p->params = array('totp_code' => \explode(' ', $c['BackupCodes'])[0]);
	$p->DoLogin($p->oAccount);
	$check('a backup code logs in', \end($p->log), 'TFA: Code verified for rym@smail.tn');

	for ($i = 0; $i < 5; ++$i) {
		$p->params = array('totp_code' => '12345' . $i);
		try { $p->DoLogin($p->oAccount); } catch (\RainLoop\Exceptions\ClientException $e) {}
	}
	$p->params = array('totp_code' => \explode(' ', $c['BackupCodes'])[1]);
	try { $p->DoLogin($p->oAccount); $check('locked after five wrong codes, even a good one', false, true); }
	catch (\RainLoop\Exceptions\ClientException $e) { $check('locked after five wrong codes, even a good one', \end($p->log), 'TFA: locked for rym@smail.tn'); }

	/* ---- app passwords: required while the second factor is on ---- */
	require_once '/root/Development/SnappyMail/SnappyMail-mots-de-passe-appli/auth/Appli.php';
	$sRoot = \sys_get_temp_dir() . '/appli-2fa-' . \getmypid();
	\file_put_contents("$sRoot.conf", '<?php return ' . \var_export(array('racine' => $sRoot, 'domaines' => array('smail.tn')), true) . ';');
	$q = new P();
	$q->config = array('app_passwords_conf' => "$sRoot.conf");
	$c2 = $q->DoCreateTwoFactorSecret()['Result'];
	$q->params = array('Code' => TwoFactorAuthTotpSlice::code($c2['Secret'], \intdiv(\time(), 30) - 1));
	$q->DoVerifyTwoFactorCode();
	$q->params = array('Enable' => '1');
	$q->DoEnableTwoFactor();
	$check('switching on requires app passwords for IMAP', \Convergent\Appli\Appli::lire("$sRoot/smail.tn/rym.json")['exige'], true);
	$q->params = array('Enable' => '0', 'Code' => TwoFactorAuthTotpSlice::code($c2['Secret'], \intdiv(\time(), 30)));
	$q->DoEnableTwoFactor();
	$check('switching off releases them', \Convergent\Appli\Appli::lire("$sRoot/smail.tn/rym.json")['exige'], false);
	@\unlink("$sRoot/smail.tn/rym.json"); @\rmdir("$sRoot/smail.tn"); @\rmdir($sRoot); @\unlink("$sRoot.conf");

	echo "\n", $iFail ? "$iFail failed\n" : "0 failed\n";
	exit($iFail ? 1 : 0);
}
