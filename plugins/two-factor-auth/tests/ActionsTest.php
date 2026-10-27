<?php
/**
 * two-factor-auth 2.28.0 — the actions, through the real plugin class, with
 * the core reduced to what the plugin touches.
 *
 * Run: php plugins/two-factor-auth/tests/ActionsTest.php (from the snappymail tree)
 */
declare(strict_types=1);

namespace RainLoop\Exceptions { class ClientException extends \Exception {
	public function __construct(int $iCode = 0, ?\Throwable $oPrevious = null, private string $sAdditional = '') { parent::__construct('', $iCode, $oPrevious); }
	public function getAdditionalMessage() : string { return $this->sAdditional; } } }
namespace RainLoop { class Notifications { const InvalidToken = 101; const AuthError = 102; const ConnectionError = 104; const DomainNotAllowed = 109;
		const AccountNotAllowed = 110; const MailServerError = 901; const ClientViewError = 902; const UnknownError = 999; }
	// The tranche of the core's Actions the plugin touches. The session is
	// resolved once per request, as in UserAuth::getMainAccountFromToken():
	// asked without exceptions and absent, it stays null — and a later strict
	// call then returns null instead of throwing "Account undefined".
	class Actions {
		private $oMainAuthAccount = false;
		public ?\RainLoop\Model\MainAccount $session = null;
		public int $resolved = 0;
		public $p = null;
		public function getMainAccountFromToken(bool $bThrow = true) {
			if (false === $this->oMainAuthAccount) {
				++$this->resolved;
				$this->oMainAuthAccount = $this->session;
				if (!$this->session && $bThrow) { throw new \RainLoop\Exceptions\ClientException(Notifications::InvalidToken, null, 'Account undefined'); }
			}
			return $this->oMainAuthAccount;
		}
		public function state() { return $this->oMainAuthAccount; }
		public function HasActionParam($k) { return false; }
		// 2.31.0: the core's resolution of a typed address (default domain), reached by Closure::bind.
		protected function resolveLoginCredentials(string $sEmail, $oPassword) : array {
			if ('boom' === $sEmail) { throw new \RuntimeException('resolution'); }
			return array('email' => \str_contains($sEmail, '@') ? $sEmail : $sEmail . '@smail.tn');
		}
		public function SetAdditionalAuthToken($a) { $this->p && ++$this->p->additionalCleared; }
	}
	class ActionsAdmin extends Actions {}
	// The services of the core, by name only.
	class ServiceActions { public function ServiceJson() {} public function ServiceRaw() {} public function ServiceAppData() {} public function ServicePlugins() {}
		public function ServiceCss() {} public function ServiceLang() {} public function ServiceUpload() {} public function ServiceUploadContacts() {}
		public function ServiceUploadBackground() {} public function ServiceProxyExternal() {} public function ServiceMailto() {} }
	class Api { public static function Config() { return new class { public function Get($a, $b, $c = null) { return 'smail.tn'; } }; } } }
namespace RainLoop\Model { abstract class Account { public function __construct(private string $e) {} public function Email() : string { return $this->e; } }
	class MainAccount extends Account {} class AdditionalAccount extends Account {} }
namespace RainLoop\Providers\Storage\Enumerations { class StorageType { const CONFIG = 1; const SIGN_ME = 3; } }
namespace RainLoop\Enumerations { class PluginPropertyType { const BOOL = 1; const STRING = 2; const STRING_TEXT = 3; } }
namespace RainLoop\Plugins {
	class Property { public static function NewInstance($n) { return new self; } public function __call($m, $a) { return $this; } }
	abstract class AbstractPlugin
	{
		public array $params = array();
		public array $config = array();
		public function UseLangs($b) : void {}
		public function addJs($f) : void {}
		public function addHook($a, $b) : void {}
		public array $jsonHooks = array();
		public function addJsonHook($a, $b) : void { $this->jsonHooks[$a] = $b; }
		public function addPartHook($a, $b) : void {}
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
	require __DIR__ . '/authenticator.php';

	// Like the core's: an address string is its own account's storage; a
	// directory per account and type on disk, for the lock and the sign-me tokens.
	final class Storage
	{
		public array $data = array();
		public bool $broken = false;
		public string $root;
		public function __construct() { $this->root = \sys_get_temp_dir() . '/tfa-test-' . \getmypid() . '-' . \bin2hex(\random_bytes(4)); }
		private static function id($a) : string { return \is_string($a) ? $a : $a->Email(); }
		public function Get($a, $t, $k) { if ($this->broken) { throw new \RuntimeException('storage down'); } return $this->data[self::id($a)] ?? ''; }
		public function Put($a, $t, $k, $v) : bool { $this->data[self::id($a)] = $v; return true; }
		public function Clear($a, $t, $k) : bool { unset($this->data[self::id($a)]); return true; }
		public function GenerateFilePath($a, $t, $b = false) : string {
			$d = $this->root . '/' . self::id($a) . '/' . (3 === $t ? '.sign_me/' : '');
			\is_dir($d) || \mkdir($d, 0700, true);
			return $d;
		}
	}
	// The real class declares typed accessors; the double swaps them through a subclass hook.
	final class P extends TwoFactorAuthPlugin
	{
		public Storage $oStore;
		public \RainLoop\Model\MainAccount $oAccount;
		public array $log = array();
		public int $authFailures = 0;
		public int $additionalCleared = 0;
		public \RainLoop\Actions $actions;
		public function __construct() { $this->oStore = new Storage(); $this->oAccount = new \RainLoop\Model\MainAccount('rym@smail.tn'); $this->request(); }
		/** A new request: the core resolves the session again. */
		public function request(?string $sSession = 'same', bool $bAdmin = false) : \RainLoop\Actions {
			$this->actions = $bAdmin ? new \RainLoop\ActionsAdmin() : new \RainLoop\Actions();
			$this->actions->p = $this;
			$this->actions->session = 'same' === $sSession ? $this->oAccount : (null === $sSession ? null : new \RainLoop\Model\MainAccount($sSession));
			return $this->actions;
		}
		public function check(string $sCode, array $aStale) : string { return $this->checkCode($this->oAccount, $aStale, $sCode); }
		public function stored() : array { return $this->loadRecord($this->oAccount); }
		public function lockFile() : string { return $this->lockPath($this->oAccount); }
		public function shortWait() : void { $this->fLockWait = 0.2; }
		/** The browser: its connection token, at the login screen and in the session. */
		public string $binding = 'browser-1';
		protected function loginBinding() : string { return $this->binding; }
		protected function sessionBinding() : string { return $this->binding; }
		/** The stored JSON, as a file on disk would be read and written by someone else. */
		public function raw() : array { return \json_decode($this->oStore->data[$this->oAccount->Email()], true); }
		public function setRaw(array $a) : void { $this->oStore->data[$this->oAccount->Email()] = \json_encode($a); }
		protected function Logger() : \MailSo\Log\Logger { return new \MailSo\Log\Logger($this); }
		protected function getMainAccountFromToken() : \RainLoop\Model\MainAccount { return $this->oAccount; }
		protected function StorageProvider() : \RainLoop\Providers\Storage { return new \RainLoop\Providers\Storage($this->oStore); }
		protected function logAuthFailure(\RainLoop\Model\MainAccount $o, string $s) : void { ++$this->authFailures; }
		/** 2.30.0: the wait of a refusal before the password, counted instead of slept. */
		public int $delays = 0;
		public bool $realDelay = false;
		protected function delayLikeAWrongPassword() : void { ++$this->delays; $this->realDelay && parent::delayLikeAWrongPassword(); }
		/** A new request: the plugin object is new for each one in the core. */
		public function fresh() : void { \Closure::bind(function () { $this->bLoggingIn = false; $this->sVerifiedBeforePassword = ''; }, $this, TwoFactorAuthPlugin::class)(); }
		public function Manager() { $p = $this; return new class ($p) {
			// Private, as in Plugins\Manager: the parts other plugins registered (caldav, files).
			private array $aAdditionalParts = array('caldavexport' => array(), 'files' => array(), 'twofactorsetuprequired' => array());
			public function __construct(private $p) {} public function Actions() { return $this->p->actions; } }; }
	}
}
namespace MailSo\Base { class Http { public static function StatusHeader(int $i) : void {} }
	class Utils { public static function Trim(string $s) : string { return \trim($s); } } }
namespace SnappyMail { class SensitiveString { public function __construct(private string $s) {} } }
namespace MailSo\Log { class Logger { public function __construct(private $p) {} public function Write($m) { $this->p->log[] = $m; } } }
namespace RainLoop\Providers { class Storage { public function __construct(private $s) {}
	public function Get($a, $t, $k) { return $this->s->Get($a, $t, $k); }
	public function Put($a, $t, $k, $v) { return $this->s->Put($a, $t, $k, $v); }
	public function Clear($a, $t, $k) { return $this->s->Clear($a, $t, $k); }
	public function GenerateFilePath($a, $t, $b = false) { return $this->s->GenerateFilePath($a, $t, $b); } } }

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
	$aInfo = $p->DoGetTwoFactorInfo()['Result'];
	$check('the info screen never sees secret, codes or QR', \array_keys($aInfo), array('User', 'IsSet', 'Enable', 'Tested', 'On', 'Enrolled', 'OnlyKey', 'Pending', 'PendingAsk', 'PendingKey', 'BackupLeft', 'WebAuthn', 'MaxPasskeys', 'Passkeys'));
	$check('… nor anything secret-shaped in its values', \preg_match('/' . \preg_quote($sSecret, '/') . '|BackupHashes|SecretBox/', \json_encode($aInfo)), 0);

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

	$p->params = array();
	try { $p->DoLogin($p->oAccount); $check('no code: refused', false, true); }
	catch (\RainLoop\Exceptions\ClientException $e) { $check('no code: refused and named, so the screen asks for it', $e->getAdditionalMessage(), 'TwoFactorCodeRequired'); }
	$p->params = array('totp_code' => '000000');
	try { $p->DoLogin($p->oAccount); } catch (\RainLoop\Exceptions\ClientException $e) { $check('a wrong code is not called a missing one', $e->getAdditionalMessage(), ''); }
	$p->params = array('totp_code' => $current($sSecret));
	$p->DoLogin($p->oAccount);
	$check('login with the current code', \end($p->log), 'TFA: Code verified for rym@smail.tn');
	try { $p->DoLogin($p->oAccount); $check('the same code again is refused', false, true); }
	catch (\RainLoop\Exceptions\ClientException $e) { $check('the same code again is refused', \in_array('TFA: replay for rym@smail.tn', $p->log, true), true); }
	$check('and reaches the auth log fail2ban reads (the wrong code above, then the replay)', $p->authFailures, 2);

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

	/* ---- S-49: the record is read again under the lock ---- */
	// A parallel attempt is a request that read the record before another
	// one wrote it: replaying its stale copy is that race, made deterministic.
	$r = new P();
	$cR = $r->DoCreateTwoFactorSecret()['Result'];
	$r->params = array('Code' => $previous($cR['Secret'])); $r->DoVerifyTwoFactorCode();
	$r->params = array('Enable' => '1'); $r->DoEnableTwoFactor();
	$aStale = $r->stored();
	$sBackup = \explode(' ', $cR['BackupCodes'])[0];
	$check('S-49: a backup code is spent once', $r->check($sBackup, $aStale), 'ok');
	$check('S-49: a second attempt that read the record before is refused, not spent again', $r->check($sBackup, $aStale), 'wrong');
	for ($i = 0; $i < 5; ++$i) { $r->check('99999' . $i, $aStale); }
	$check('S-49: five parallel wrong codes from the same stale copy still lock the account', $r->check(\explode(' ', $cR['BackupCodes'])[1], $aStale), 'locked');
	$r->shortWait();
	$rHeld = \fopen($r->lockFile(), 'c'); \flock($rHeld, LOCK_EX);
	$check('S-49: while another check holds the lock, the answer is "busy", never "ok"', $r->check($current($cR['Secret']), $aStale), 'busy');
	\flock($rHeld, LOCK_UN); \fclose($rHeld);

	/* ---- S-21: turning the second factor on forgets the remembered devices ---- */
	$t = new P();
	$sSignMe = $t->oStore->GenerateFilePath('rym@smail.tn', 3);
	\file_put_contents($sSignMe . '2b6f-remembered-before', 'token');
	$cT = $t->DoCreateTwoFactorSecret()['Result'];
	$t->params = array('Code' => $previous($cT['Secret'])); $t->DoVerifyTwoFactorCode();
	$check('S-21: a device remembered before is still there while the second factor is off', \count(\glob($sSignMe . '*')), 1);
	$t->params = array('Enable' => '1'); $t->DoEnableTwoFactor();
	$check('S-21: switching on removes every remember-me token of the account', \glob($sSignMe . '*'), array());

	/* ---- S-22: a protected account is refused as an additional account ---- */
	$a = new P();
	$a->oAccount = new \RainLoop\Model\MainAccount('sana@smail.tn');
	$cA = $a->DoCreateTwoFactorSecret()['Result'];
	$a->params = array('Code' => $previous($cA['Secret'])); $a->DoVerifyTwoFactorCode();
	$a->params = array('Enable' => '1'); $a->DoEnableTwoFactor();
	$a->oAccount = new \RainLoop\Model\MainAccount('rym@smail.tn');
	try { $a->FilterAccount(new \RainLoop\Model\AdditionalAccount('sana@smail.tn')); $check('S-22: a protected mailbox added with its password alone is refused', 'accepted', 'refused'); }
	catch (\RainLoop\Exceptions\ClientException $e) { $check('S-22: a protected mailbox added with its password alone is refused, and named', $e->getAdditionalMessage(), 'TwoFactorNotAdditional'); }
	$check('S-22: and the session is sent back to its main account', $a->additionalCleared, 1);
	$a->FilterAccount(new \RainLoop\Model\AdditionalAccount('nour@smail.tn'));
	$check('S-22: an unprotected mailbox is still added', $a->additionalCleared, 1);
	$a->FilterAccount(new \RainLoop\Model\MainAccount('sana@smail.tn'));
	$check('S-22: the main account is not this hook\'s business (login.success asks for its code)', $a->additionalCleared, 1);

	/* ---- S-09: no app-password promise without the store ---- */
	$n = new P();
	$aData = array('Auth' => true);
	$n->FilterAppData(false, $aData);
	$check('S-09: without the app-password store, the screen does not promise app passwords', $aData['TwoFactorAppPasswords'] ?? null, false);
	$sTpl = (string) \file_get_contents(__DIR__ . '/../templates/TwoFactorAuthSettings.html');
	$check('S-09: the note is bound to that flag, not shown unconditionally',
		(bool) \preg_match('/<p[^>]*data-bind="visible: appPasswordsNote"[^>]*data-i18n="PLUGIN_2FA\/APP_PASSWORDS_NOTE"/', $sTpl), true);

	/* ---- 2.26.0: enforced per tenant (domain list), never by default ---- */
	$check('the list is read as domains, the rest dropped',
		TwoFactorAuthPlugin::parseDomains("Smail.tn, @convergent.tn\nnot a domain;x..tn  societe.com.tn"), array('smail.tn', 'convergent.tn', 'societe.com.tn'));
	$f = new P();
	$aData = array('Auth' => true);
	$f->FilterAppData(false, $aData);
	$check('by default nobody is required to set it up', array($aData['RequireTwoFactor'], $aData['SetupTwoFactor']), array(false, false));
	$f->config = array('force_two_factor_domains' => "convergent.tn\nsmail.tn");
	$aData = array('Auth' => true);
	$f->FilterAppData(false, $aData);
	$check('an account of a listed domain must set it up', array($aData['RequireTwoFactor'], $aData['SetupTwoFactor']), array(true, true));
	$f->oAccount = new \RainLoop\Model\MainAccount('rym@smail.tn.ailleurs.com');
	$aData = array('Auth' => true);
	$f->FilterAppData(false, $aData);
	$check('a look-alike domain is not listed', $aData['RequireTwoFactor'], false);
	$aData = array('Auth' => false);
	$f->oAccount = new \RainLoop\Model\MainAccount('rym@smail.tn');
	$f->FilterAppData(false, $aData);
	$check('before login nothing is said about any domain', $aData['RequireTwoFactor'], false);

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
	$aData = array('Auth' => true);
	$q->FilterAppData(false, $aData);
	$check('S-09: with the store, for a served domain, the screen says so', $aData['TwoFactorAppPasswords'], true);
	$o = new P();
	$o->config = $q->config;
	$o->oAccount = new \RainLoop\Model\MainAccount('rym@ailleurs.tn');
	$aData = array('Auth' => true);
	$o->FilterAppData(false, $aData);
	$check('S-09: but not for a domain the store does not serve', $aData['TwoFactorAppPasswords'], false);

	// The store applies but cannot be written: enabling is refused, not left on.
	\file_put_contents("$sRoot-ro.conf", '<?php return ' . \var_export(array('racine' => '/proc/no-such-store', 'domaines' => array('smail.tn')), true) . ';');
	$w = new P();
	$w->config = array('app_passwords_conf' => "$sRoot-ro.conf");
	$cW = $w->DoCreateTwoFactorSecret()['Result'];
	$w->params = array('Code' => TwoFactorAuthTotpSlice::code($cW['Secret'], \intdiv(\time(), 30) - 1)); $w->DoVerifyTwoFactorCode();
	$w->params = array('Enable' => '1');
	$check('S-09: when app passwords cannot be required, switching on is refused', $w->DoEnableTwoFactor()['Result'], false);
	$check('S-09: and the second factor stays off, not on with the main password still opening IMAP', $w->DoGetTwoFactorInfo()['Result']['Enable'], false);
	@\unlink("$sRoot-ro.conf");
	@\unlink("$sRoot/smail.tn/rym.json"); @\rmdir("$sRoot/smail.tn"); @\rmdir($sRoot); @\unlink("$sRoot.conf");

	/* ---- 2.27.0: "enforce" held by the server (CDU-10 / S-76) ---- */
	// What the core does: SetActionParams() runs filter.action-params with the
	// method name before the action; Service::Handle() runs filter.http-paths.
	$verdict = function (P $x, string $sMethod) : string {
		try { $x->FilterActionParams($sMethod, array()); return 'passe'; }
		catch (\RainLoop\Exceptions\ClientException $e) { return $e->getAdditionalMessage() . '/' . $e->getCode(); }
	};
	$chemin = function (P $x, array $aPaths) : array { $x->FilterHttpPaths($aPaths); return $aPaths; };
	$enroler = function (P $x) use ($previous) {
		$c = $x->DoCreateTwoFactorSecret()['Result'];
		$x->params = array('Code' => $previous($c['Secret'])); $x->DoVerifyTwoFactorCode();
		$x->params = array('Enable' => '1'); return $x->DoEnableTwoFactor()['Result'];
	};
	$REFUS = 'TwoFactorSetupRequired/' . \RainLoop\Notifications::ClientViewError;

	$g = new P();
	$g->config = array('force_two_factor_domains' => 'smail.tn');
	foreach (array('DoMessageList', 'DoMessage', 'DoSendMessage', 'RawDownload', 'RawView', 'DoAccountsAndIdentities', 'DoContacts', 'DoPluginEpingleListe') as $m) {
		$g->request();
		$check("required, not set up: $m is refused, and named", $verdict($g, $m), $REFUS);
	}
	$check('the refusal does not count toward the client\'s logout-after-7-errors (code ' . \RainLoop\Notifications::ClientViewError . ')',
		\in_array(\RainLoop\Notifications::ClientViewError, array(\RainLoop\Notifications::AuthError, \RainLoop\Notifications::ConnectionError,
			\RainLoop\Notifications::DomainNotAllowed, \RainLoop\Notifications::AccountNotAllowed, \RainLoop\Notifications::MailServerError,
			\RainLoop\Notifications::UnknownError, \RainLoop\Notifications::InvalidToken), true), false);
	foreach (\preg_split('/\s+/', TwoFactorAuthPlugin::SETUP_ALLOWED_ACTIONS) as $m) {
		$g->request();
		$check("required, not set up: $m (measured allow-list) passes", $verdict($g, $m), 'passe');
	}
	$check('the allow-list is case-insensitive, as PHP method names (dologout runs DoLogout)', $verdict($g, 'dologout'), 'passe');
	$check('the allow-list holds no mail action', \preg_match('/Message|Send|Raw|Contacts|Identit/i', TwoFactorAuthPlugin::SETUP_ALLOWED_ACTIONS), 0);

	// The GET the core skips: three segments, no SetActionParams, no token.
	$check('GET ?/Json/…/AccountsAndIdentities with three segments: a fourth is added, so the hook runs',
		$chemin($g, array('Json', '0', 'AccountsAndIdentities')), array('Json', '0', 'AccountsAndIdentities', ''));
	$check('… also written json@x, which the core reads as Json',
		\count($chemin($g, array('json@x', '0', 'Contacts'))), 4);
	$check('… but not for an allowed action (Folders)', $chemin($g, array('Json', '0', 'Folders')), array('Json', '0', 'Folders'));
	$check('… nor for a POST (no action in the path)', $chemin($g, array('Json', '0', '')), array('Json', '0', ''));
	foreach (array(array('Upload', '0'), array('UploadContacts', '0'), array('UploadBackground'), array('ProxyExternal', 'aHR0cA'),
		array('CalDavExport', 'x'), array('Files', 'x'), array('Mailto')) as $aP) {
		$check("required, not set up: service {$aP[0]} is refused whole", $chemin($g, $aP), array('TwoFactorSetupRequired'));
	}
	$check('a first segment nothing answers (?lang=fr) still gets the page, as before', $chemin($g, array('lang=fr')), array('lang=fr'));
	$check('… nor a name no service nor part bears', $chemin($g, array('Nimporte', 'x')), array('Nimporte', 'x'));
	foreach (array(array('AppData', '0', '1'), array('Plugins', '0', 'User', 'h'), array('Raw', '0', 'Download', 'k'), array('Css', '0'), array('Lang', '0', 'App', 'fr'), array(''), array('index')) as $aP) {
		$check("required, not set up: service " . ($aP[0] ?: '(index)') . ' is left to the action filter', $chemin($g, $aP), $aP);
	}
	\ob_start(); $bServi = $g->ServiceSetupRequired(); $sCorps = (string) \ob_get_clean();
	$aCorps = \json_decode($sCorps, true);
	$check('the refused service answers like a refused action, named', array($bServi, $aCorps['Result'], $aCorps['messageAdditional']), array(true, false, 'TwoFactorSetupRequired'));

	// Fail closed: a record that cannot be read is "not set up".
	$g->oStore->broken = true; $g->request();
	$check('the record cannot be read: refused (fail closed)', $verdict($g, 'DoMessageList'), $REFUS);
	$g->oStore->broken = false;

	// Enrolled in this very request: nothing is cached, the next action passes.
	$g->request();
	$check('enrolled through the allowed actions', $enroler($g), true);
	foreach (array('DoMessageList', 'DoMessage', 'DoSendMessage', 'RawDownload') as $m) {
		$check("enrolled: $m passes", $verdict($g, $m), 'passe');
	}
	$check('enrolled: Upload is left alone', $chemin($g, array('Upload', '0')), array('Upload', '0'));
	$check('enrolled: the GET is left alone', $chemin($g, array('Json', '0', 'AccountsAndIdentities')), array('Json', '0', 'AccountsAndIdentities'));
	$g->params = array('Code' => $current($g->stored() ? TwoFactorRecord::unseal((string) $g->stored()['SecretBox'], TwoFactorRecord::key(APP_SALT)) : ''));
	$g->DoClearTwoFactorInfo();
	$check('cleared again in the same session: refused again', $verdict($g, 'DoMessageList'), $REFUS);

	// Not required: nothing refused, and the session is not even looked at.
	$h = new P();
	foreach (array('DoMessageList', 'DoSendMessage', 'RawDownload') as $m) {
		$check("nobody required: $m passes", $verdict($h, $m), 'passe');
	}
	$check('nobody required: Upload is left alone', $chemin($h, array('Upload', '0')), array('Upload', '0'));
	$check('nobody required: the session was never resolved by the plugin', $h->actions->resolved, 0);
	$h->config = array('force_two_factor_domains' => 'smail.tn');
	$h->request('rym@ailleurs.tn');
	$check('a domain not listed: MessageList passes', $verdict($h, 'DoMessageList'), 'passe');
	$check('a domain not listed: Upload is left alone', $chemin($h, array('Upload', '0')), array('Upload', '0'));
	$h->config = array('force_two_factor_auth' => true);
	$h->request('rym@ailleurs.tn');
	$check('the global switch: any domain is refused', $verdict($h, 'DoMessageList'), $REFUS);

	// The admin panel: ActionsAdmin, never filtered.
	$h->request('same', true);
	$check('admin panel: AdminSettingsGet passes', $verdict($h, 'DoAdminSettingsGet'), 'passe');
	$check('admin panel: MessageList is not this plugin\'s business either', $verdict($h, 'DoMessageList'), 'passe');
	$check('admin panel: its paths are left alone', $chemin($h, array('Upload', '0')), array('Upload', '0'));
	$check('admin panel: the user session is not even resolved', $h->actions->resolved, 0);

	// Before login: nothing to refuse, and the core is left as found, so the
	// action still meets its own "Account undefined" — which sends the browser to the login screen.
	$oSans = $h->request(null);
	$check('before login: Login passes', $verdict($h, 'DoLogin'), 'passe');
	$check('before login: MessageList is left to the core', $verdict($h, 'DoMessageList'), 'passe');
	$check('before login: the core\'s session state is put back (false, not null)', $oSans->state(), false);
	try { $oSans->getMainAccountFromToken(true); $check('before login: the action still throws InvalidToken', 'no exception', 'InvalidToken'); }
	catch (\RainLoop\Exceptions\ClientException $e) { $check('before login: the action still throws InvalidToken', $e->getCode(), \RainLoop\Notifications::InvalidToken); }

	// Configurable: the lists are the administrator's, the measured ones the default.
	$k = new P();
	$k->config = array('force_two_factor_domains' => 'smail.tn', 'setup_allowed_actions' => "DoLogout\nDoPluginGetTwoFactorInfo", 'setup_allowed_services' => 'AppData, Plugins, Json');
	$check('configured actions: DoLogout passes', $verdict($k, 'DoLogout'), 'passe');
	$check('configured actions: DoFolders, not listed, is refused', $verdict($k, 'DoFolders'), $REFUS);
	$check('configured services: Raw, not listed, is refused whole', $chemin($k, array('Raw', '0', 'Download', 'k')), array('TwoFactorSetupRequired'));
	$k->config['setup_allowed_actions'] = '  ';
	$check('an empty list is the measured default (DoFolders passes)', $verdict($k, 'DoFolders'), 'passe');

	/* ---- 2.28.0: security keys and passkeys (WebAuthn) as a second factor ---- */
	$WA = array('webauthn_enabled' => true, 'webauthn_origins' => 'https://webmail.smail.tn', 'webauthn_rp_id' => 'smail.tn');
	$inscrire = function (P $x, SoftAuthenticator $k, array $aProof = array(), array $o = array()) {
		$x->params = array();
		$aOpt = $x->DoWebAuthnCreateOptions()['Result'];
		if (!$aOpt) { return 'no options'; }
		$x->params = $aProof + array('Name' => $o['name'] ?? 'YubiKey', 'Credential' => \json_encode($k->create($aOpt['challenge'], $o)));
		$aR = $x->DoWebAuthnRegister()['Result'];
		// 2.32.0: a first key waits for the proof that the backup codes are kept.
		// The helper gives it, as a careful person would, unless asked not to.
		if (\is_array($aR) && !empty($aR['Pending']) && !empty($aR['PendingKey']) && empty($o['sans_preuve'])) {
			$aCodes = \explode(' ', $aR['BackupCodes']);
			$x->params = array('Code' => $aCodes[$aR['PendingAsk'] - 1]);
			$aC = $x->DoConfirmBackupCodes()['Result'];
			return \is_array($aC) ? $aC + array('BackupCodes' => $aR['BackupCodes']) : $aC;
		}
		return $aR;
	};
	$connexion = function (P $x, array $aParams) : string {
		$x->params = $aParams;
		try { $x->DoLogin($x->oAccount); return 'ok'; }
		catch (\RainLoop\Exceptions\ClientException $e) { return 'refused:' . \explode(':', $e->getAdditionalMessage())[0]; }
	};
	$optionsConnexion = function (P $x) : ?array {
		$x->params = array();
		try { $x->DoLogin($x->oAccount); return null; }
		catch (\RainLoop\Exceptions\ClientException $e) {
			$m = $e->getAdditionalMessage();
			return \str_starts_with($m, 'TwoFactorCodeRequired:') ? \json_decode(TwoFactorWebAuthn::unb64u(\substr($m, 22)), true) : null;
		}
	};
	$cle = fn (P $x, SoftAuthenticator $k, array $o = array()) => array('webauthn_assertion' => \json_encode($k->get($optionsConnexion($x)['challenge'] ?? 'none', $o)));
	$preuve = function (P $x, SoftAuthenticator $k, array $o = array()) {
		$x->params = array();
		$aOpt = $x->DoWebAuthnAssertOptions()['Result'];
		return array('Assertion' => \json_encode($k->get($aOpt ? $aOpt['challenge'] : 'none', $o)));
	};
	$dernier = fn (P $x, string $s) => (bool) \array_filter($x->log, fn ($l) => \str_contains($l, $s));
	// Each refusal above counts toward the lockout (five in fifteen minutes): cleared between groups.
	$deverrouiller = function (P $x) { $a = $x->raw(); $a['Failures'] = array(); $a['LockedUntil'] = 0; $x->setRaw($a); };

	// Off by default, and off without an origin.
	$d = new P();
	$check('security keys: off by default, no options are issued', $d->DoWebAuthnCreateOptions()['Result'], false);
	$check('security keys: the settings screen is told so', $d->DoGetTwoFactorInfo()['Result']['WebAuthn'], false);
	$d->config = array('webauthn_enabled' => true);
	$check('security keys: switched on without an origin, still off (the Host header is never used)', $d->DoWebAuthnCreateOptions()['Result'], false);

	$check('config: origins as browsers serialise them (default port dropped, case), rpId from the first',
		TwoFactorAuthPlugin::parseWebAuthnConf("https://Webmail.smail.tn:443/\nhttp://10.0.0.1", ''), array('origins' => array('https://webmail.smail.tn'), 'rpId' => 'webmail.smail.tn'));
	$check('config: a parent domain as rpId keeps its subdomains, drops the others',
		TwoFactorAuthPlugin::parseWebAuthnConf('https://webmail.smail.tn, https://mail.smail.tn:8443 https://smail.tn.evil.com', 'smail.tn'),
		array('origins' => array('https://webmail.smail.tn', 'https://mail.smail.tn:8443'), 'rpId' => 'smail.tn'));
	$check('config: an IP address cannot be an rpId (WebAuthn forbids it)', TwoFactorAuthPlugin::parseWebAuthnConf('http://10.89.10.1:8932', ''), null);
	$check('config: an rpId the origins are not under', TwoFactorAuthPlugin::parseWebAuthnConf('https://smail.tn', 'mail.smail.tn'), null);
	$check('config: no origin, no keys', TwoFactorAuthPlugin::parseWebAuthnConf('', 'smail.tn'), null);
	$check('a key\'s name: control and bidi-override characters removed, 64 at most',
		array(TwoFactorAuthPlugin::passkeyName("Yubi\u{202E}yeK\x07 \n bureau"), \mb_strlen(TwoFactorAuthPlugin::passkeyName(\str_repeat('é', 100)))), array('YubiyeK bureau', 64));

	// The first factor of an account: a key.
	$w = new P();
	$w->config = $WA;
	$kW = new SoftAuthenticator(-7);
	$w->params = array();
	$aOpt = $w->DoWebAuthnCreateOptions()['Result'];
	$check('creation options: the relying party, attestation "none", no key stored on the authenticator',
		array($aOpt['rp']['id'], $aOpt['attestation'], $aOpt['authenticatorSelection']['residentKey'], $aOpt['excludeCredentials']), array('smail.tn', 'none', 'discouraged', array()));
	$check('creation options: ES256, EdDSA and RS256 offered', \array_column($aOpt['pubKeyCredParams'], 'alg'), array(-7, -8, -257));
	$check('creation options: the user handle is random, never the address', array($aOpt['user']['name'], \str_contains(TwoFactorWebAuthn::unb64u($aOpt['user']['id']), 'rym')), array('rym@smail.tn', false));
	$w->params = array('Name' => 'YubiKey bleue', 'Credential' => \json_encode($kW->create($aOpt['challenge'])));
	$aR0 = $w->DoWebAuthnRegister()['Result'];
	$check('2.32.0: a first key is put aside, not active: backup codes shown once, a rank to retype',
		array($aR0['On'], $aR0['Enrolled'], $aR0['Pending'], $aR0['PendingKey'], \count($aR0['Passkeys']), \count(\explode(' ', $aR0['BackupCodes'])), $aR0['PendingAsk'] >= 1 && $aR0['PendingAsk'] <= 8),
		array(false, false, true, true, 0, 8, true));
	$check('2.32.0: … and the login still ignores it (the password alone, nothing is locked)', $connexion($w, array()), 'ok');
	$w->params = array('Code' => '000000000');
	$check('2.32.0: a wrong proof is refused', $w->DoConfirmBackupCodes()['Result'], false);
	$w->params = array('Code' => \explode(' ', $aR0['BackupCodes'])[$aR0['PendingAsk'] % 8]);
	$check('2.32.0: another code of the list than the one asked is refused too', $w->DoConfirmBackupCodes()['Result'], false);
	$w->params = array('Code' => \explode(' ', $aR0['BackupCodes'])[$aR0['PendingAsk'] - 1]);
	$aR = $w->DoConfirmBackupCodes()['Result'];
	$aR['BackupCodes'] = $aR0['BackupCodes'];
	$check('registered: the second factor is on, with this key', array($aR['On'], $aR['Enrolled'], \count($aR['Passkeys']), $aR['Passkeys'][0]['Name']), array(true, true, 1, 'YubiKey bleue'));
	$check('registered first: eight backup codes, shown this once', \count(\explode(' ', $aR['BackupCodes'] ?? '')), 8);
	$aBackupW = \explode(' ', $aR['BackupCodes']);
	$check('the settings screen gets a reference, never the credential id nor the key', \array_keys($aR['Passkeys'][0]), array('Ref', 'Name', 'Created', 'LastUsed'));
	$sRaw = $w->oStore->data['rym@smail.tn'];
	$check('stored sealed: neither the credential id nor the name appear in the record', array(\str_contains($sRaw, SoftAuthenticator::b64u($kW->credentialId)), \str_contains($sRaw, 'YubiKey')), array(false, false));
	$w->params = array('Name' => 'again', 'Credential' => \json_encode($kW->create($aOpt['challenge'])));
	$check('the registration challenge is spent: the same answer again is refused', $w->DoWebAuthnRegister()['Result'], false);
	$w->params = array();
	$check('the next options exclude the key already registered', \count($w->DoWebAuthnCreateOptions()['Result']['excludeCredentials']), 1);

	// Login.
	$check('login without a factor: refused, named', $connexion($w, array()), 'refused:TwoFactorCodeRequired');
	$aLogin = $optionsConnexion($w);
	$check('… and the request options follow the name, for this account\'s key', array($aLogin['rpId'], \array_column($aLogin['allowCredentials'], 'id')), array('smail.tn', array(SoftAuthenticator::b64u($kW->credentialId))));
	$aAssertion = $kW->get($aLogin['challenge']);
	$check('login with the key: accepted', $connexion($w, array('webauthn_assertion' => \json_encode($aAssertion))), 'ok');
	$check('… and its last use is recorded', $w->DoGetTwoFactorInfo()['Result']['Passkeys'][0]['LastUsed'] > 0, true);
	$check('the same assertion replayed: refused (challenge spent)', $connexion($w, array('webauthn_assertion' => \json_encode($aAssertion))), 'refused:');
	$check('… logged as such', $dernier($w, 'webauthn-challenge'), true);
	$check('wrong origin: refused', $connexion($w, $cle($w, $kW, array('origin' => 'https://webmail-smail.tn'))), 'refused:');
	$check('… logged as such', $dernier($w, 'webauthn-origin'), true);
	$check('wrong rpId: refused', $connexion($w, $cle($w, $kW, array('rpId' => 'evil.tn'))), 'refused:');
	$aLogin = $optionsConnexion($w);
	$sBad = \json_encode($kW->get($aLogin['challenge'], array('origin' => 'https://evil.tn')));
	$connexion($w, array('webauthn_assertion' => $sBad));
	$check('a failed attempt spends the challenge: a good answer to it is refused afterwards',
		$connexion($w, array('webauthn_assertion' => \json_encode($kW->get($aLogin['challenge'])))), 'refused:');
	$aLogin = $optionsConnexion($w);
	$w->binding = 'browser-2';
	$check('a challenge issued to one browser, answered from another: refused', $connexion($w, array('webauthn_assertion' => \json_encode($kW->get($aLogin['challenge'])))), 'refused:');
	$w->binding = 'browser-1';
	$aLogin = $optionsConnexion($w);
	$aRaw = $w->raw(); foreach ($aRaw['Challenges'] as &$c) { $c['e'] = \time() - 1; } unset($c); $w->setRaw($aRaw);
	$check('an expired challenge: refused', $connexion($w, array('webauthn_assertion' => \json_encode($kW->get($aLogin['challenge'])))), 'refused:');
	$check('a challenge issued at login cannot confirm a removal',
		(function () use ($w, $kW, $optionsConnexion) { $a = $optionsConnexion($w); $w->params = array('Ref' => $w->DoGetTwoFactorInfo()['Result']['Passkeys'][0]['Ref'], 'Assertion' => \json_encode($kW->get($a['challenge']))); return $w->DoWebAuthnRemove()['Result']; })(), false);
	$check('the refusals above count: the second factor is now locked', $dernier($w, 'TFA: locked for rym@smail.tn'), true);
	$deverrouiller($w);
	$check('a six-digit code is no factor for an account without TOTP', $connexion($w, array('totp_code' => '123456')), 'refused:');
	$check('a backup code logs in', $connexion($w, array('totp_code' => $aBackupW[0])), 'ok');
	$check('the key of another account is refused for this one',
		(function () use ($inscrire, $WA, $w, $connexion, $optionsConnexion) {
			$b = new P(); $b->oStore = $w->oStore; $b->config = $WA; $b->oAccount = new \RainLoop\Model\MainAccount('sana@smail.tn');
			$kB = new SoftAuthenticator(-7); $inscrire($b, $kB);
			return $connexion($w, array('webauthn_assertion' => \json_encode($kB->get($optionsConnexion($w)['challenge']))));
		})(), 'refused:');
	$check('… logged as an unknown credential', $dernier($w, 'webauthn-unknown-credential'), true);
	$check('S-22: an additional account with a key is refused', (function () use ($w) {
		try { $w->FilterAccount(new \RainLoop\Model\AdditionalAccount('sana@smail.tn')); return 'accepted'; }
		catch (\RainLoop\Exceptions\ClientException $e) { return $e->getAdditionalMessage(); } })(), 'TwoFactorNotAdditional');

	// The signature counter.
	$deverrouiller($w);
	$check('a counter that goes back: refused', $connexion($w, $cle($w, $kW, array('counter' => 1))), 'refused:');
	$check('… logged as such', $dernier($w, 'webauthn-counter'), true);
	$w->config['webauthn_counter_regression'] = 'warn';
	$check('with the setting on "warn": accepted', $connexion($w, $cle($w, $kW, array('counter' => 1))), 'ok');
	$check('… and logged', $dernier($w, 'signature counter went back'), true);
	unset($w->config['webauthn_counter_regression']);
	$kW->counter = 100;

	// Failures count toward the same lockout as wrong codes.
	$deverrouiller($w);
	$w->log = array();
	for ($i = 0; $i < 5; ++$i) { $connexion($w, $cle($w, $kW, array('signature' => 'not a signature'))); }
	$check('five bad assertions lock the second factor: then even a good one is refused', $connexion($w, $cle($w, $kW)), 'refused:');
	$check('… as locked', $dernier($w, 'TFA: locked for rym@smail.tn'), true);
	$deverrouiller($w);

	// Settings: rename, add another, remove — the last two with a current factor.
	$sRef = $w->DoGetTwoFactorInfo()['Result']['Passkeys'][0]['Ref'];
	$w->params = array('Ref' => $sRef, 'Name' => "Clé du bureau \u{202E}");
	$check('rename: the session is enough', $w->DoWebAuthnRename()['Result']['Passkeys'][0]['Name'], 'Clé du bureau');
	$w->params = array('Ref' => 'nope', 'Name' => 'x');
	$check('rename: an unknown reference changes nothing', $w->DoWebAuthnRename()['Result'], false);
	$kW2 = new SoftAuthenticator(-8);
	$check('a second key without a current factor: refused (a stolen session must not add its own)', $inscrire($w, $kW2), false);
	$aR = $inscrire($w, $kW2, $preuve($w, $kW), array('name' => 'Téléphone'));
	$check('a second key, confirmed with the first: registered, and no new backup codes', array(\count($aR['Passkeys']), isset($aR['BackupCodes'])), array(2, false));
	$check('the same authenticator twice: refused', $inscrire($w, $kW2, $preuve($w, $kW)), false);
	$w->config['webauthn_max_passkeys'] = 2;
	$w->params = array();
	$check('at the maximum per account: no more options', $w->DoWebAuthnCreateOptions()['Result'], false);
	unset($w->config['webauthn_max_passkeys']);
	$check('the second key (EdDSA) logs in', $connexion($w, $cle($w, $kW2)), 'ok');
	$sRef2 = $w->DoGetTwoFactorInfo()['Result']['Passkeys'][1]['Ref'];
	$w->params = array('Ref' => $sRef2);
	$check('removing a key without a factor: refused', $w->DoWebAuthnRemove()['Result'], false);
	$w->params = array('Ref' => $sRef2, 'Code' => '000000000');
	$check('removing a key with a wrong code: refused', $w->DoWebAuthnRemove()['Result'], false);
	$w->params = array('Ref' => $sRef2) + $preuve($w, $kW2);
	$check('removing a key with its own assertion: removed', \count($w->DoWebAuthnRemove()['Result']['Passkeys']), 1);

	// A TOTP next to a key: added only with a current factor, and a code only once tested.
	$w->params = array();
	$check('a TOTP next to a key, without a current factor: refused', $w->DoCreateTwoFactorSecret()['Result'], false);
	$w->params = $preuve($w, $kW);
	$cW = $w->DoCreateTwoFactorSecret()['Result'];
	$check('… with the key: created, and the key kept', array(\strlen($cW['Secret']) >= 16, \count($w->DoGetTwoFactorInfo()['Result']['Passkeys'])), array(true, 1));
	$check('an untested TOTP is not yet a factor at login', $connexion($w, array('totp_code' => $current($cW['Secret']))), 'refused:');
	$w->params = array('Code' => $previous($cW['Secret'])); $w->DoVerifyTwoFactorCode();
	$w->params = array('Enable' => '1');
	$check('tested, it switches on', $w->DoEnableTwoFactor()['Result'], true);
	\sleep(0);
	$check('the key still logs in next to it', $connexion($w, $cle($w, $kW)), 'ok');
	$w->params = array('Enable' => '0') + $preuve($w, $kW);
	$check('switching the TOTP off with the key: off, and the account stays protected by the key',
		array($w->DoEnableTwoFactor()['Result'], $w->DoGetTwoFactorInfo()['Result']['On']), array(true, true));
	$w->params = $preuve($w, $kW);
	$aC = $w->DoClearTwoFactorInfo()['Result'];
	$check('clearing everything with the key: nothing left', array($aC['On'], $aC['Passkeys']), array(false, array()));
	$check('… and the login asks for nothing more', $connexion($w, array()), 'ok');

	// Enforcement (2.27.0): a key is enrolment, through the allowed actions.
	$e = new P();
	$e->config = $WA + array('force_two_factor_domains' => 'smail.tn');
	$check('required, not set up: MessageList refused', $verdict($e, 'DoMessageList'), $REFUS);
	foreach (array('DoPluginWebAuthnCreateOptions', 'DoPluginWebAuthnRegister') as $m) {
		$check("required, not set up: $m is in the allow-list", $verdict($e, $m), 'passe');
	}
	foreach (array('DoPluginWebAuthnRename', 'DoPluginWebAuthnRemove', 'DoPluginWebAuthnAssertOptions') as $m) {
		$check("required, not set up: $m is not (nothing to rename or remove yet)", $verdict($e, $m), $REFUS);
	}
	$kE = new SoftAuthenticator(-257);
	$inscrire($e, $kE);
	$e->request();
	$check('enrolled with a key (RS256): MessageList passes', $verdict($e, 'DoMessageList'), 'passe');
	$aData = array('Auth' => true);
	$e->FilterAppData(false, $aData);
	$check('… and the screen no longer forces (SetupTwoFactor false)', $aData['SetupTwoFactor'], false);
	$aRaw = $e->raw(); $aRaw['PasskeysBox'] = \base64_encode(\random_bytes(64)); $e->setRaw($aRaw);
	$e->request();
	$check('a key box tampered with (cannot be opened): counted as not set up', $verdict($e, 'DoMessageList'), $REFUS);
	$check('… and the login is not let through on the password alone (fail closed)', $connexion($e, array()), 'refused:TwoFactorCodeRequired');
	$aRaw['PasskeysBox'] = TwoFactorRecord::seal('[{"Id":"' . SoftAuthenticator::b64u(\random_bytes(32)) . '","Alg":-7,"Key":"x","SignCount":0}]', TwoFactorRecord::key('another install'));
	$e->setRaw($aRaw);
	$check('a key sealed under another installation\'s salt is not accepted as one', $connexion($e, array()), 'refused:TwoFactorCodeRequired');

	// App passwords (S-09): required with the first factor, released with the last.
	\file_put_contents("$sRoot.conf", '<?php return ' . \var_export(array('racine' => $sRoot, 'domaines' => array('smail.tn')), true) . ';');
	$ap = new P();
	$ap->config = $WA + array('app_passwords_conf' => "$sRoot.conf");
	$kA = new SoftAuthenticator(-7);
	$inscrire($ap, $kA);
	$check('a first key requires app passwords for IMAP', \Convergent\Appli\Appli::lire("$sRoot/smail.tn/rym.json")['exige'], true);
	$ap->params = array('Ref' => $ap->DoGetTwoFactorInfo()['Result']['Passkeys'][0]['Ref']) + $preuve($ap, $kA);
	$ap->DoWebAuthnRemove();
	$check('removing the last one releases them', \Convergent\Appli\Appli::lire("$sRoot/smail.tn/rym.json")['exige'], false);
	@\unlink("$sRoot/smail.tn/rym.json"); @\rmdir("$sRoot/smail.tn"); @\rmdir($sRoot); @\unlink("$sRoot.conf");
	\file_put_contents("$sRoot-ro.conf", '<?php return ' . \var_export(array('racine' => '/proc/no-such-store', 'domaines' => array('smail.tn')), true) . ';');
	$ar = new P();
	$ar->config = $WA + array('app_passwords_conf' => "$sRoot-ro.conf");
	$check('S-09: when app passwords cannot be required, the first key is refused', $inscrire($ar, new SoftAuthenticator(-7)), false);
	$check('… and nothing is on', $ar->DoGetTwoFactorInfo()['Result']['On'], false);
	@\unlink("$sRoot-ro.conf");

	// S-21: a first key forgets the remembered devices, as the TOTP does.
	$sm = new P();
	$sm->config = $WA;
	$sSignMe2 = $sm->oStore->GenerateFilePath('rym@smail.tn', 3);
	\file_put_contents($sSignMe2 . 'remembered-before', 'token');
	$inscrire($sm, new SoftAuthenticator(-7));
	$check('S-21: a first key removes every remember-me token of the account', \glob($sSignMe2 . '*'), array());

	// Keys switched off afterwards: the account is still protected, by its backup codes.
	$off = new P();
	$off->config = $WA;
	$kO = new SoftAuthenticator(-7);
	$aO = $inscrire($off, $kO);
	$off->config = array();
	$check('keys switched off by the administrator: the login still asks for a factor', $connexion($off, array()), 'refused:TwoFactorCodeRequired');
	$check('… an assertion is refused ("unavailable")', $connexion($off, array('webauthn_assertion' => '{}')), 'refused:');
	$check('… and a backup code still opens it', $connexion($off, array('totp_code' => \explode(' ', $aO['BackupCodes'])[0])), 'ok');

	/* ---- 2.30.0: the code is judged before the password reaches the directory ---- */
	// One login as the core runs it: login.credentials, filter.account, then —
	// only if nothing refused — IMAP (the directory), then login.success.
	$login = function (P $x, array $aParams) : string {
		$x->fresh();
		$x->request();
		$x->params = $aParams;
		$x->NoteLogin();
		try { $x->FilterAccount($x->oAccount); }
		catch (\RainLoop\Exceptions\ClientException $e) { return 'refused:' . $e->getCode() . ':' . $e->getAdditionalMessage(); }
		try { $x->DoLogin($x->oAccount); return 'directory+ok'; }
		catch (\RainLoop\Exceptions\ClientException $e) { return 'directory+refused:' . \explode(':', $e->getAdditionalMessage())[0]; }
	};
	$AUTH = 'refused:102:';
	$b = new P();
	$b->oAccount = new \RainLoop\Model\MainAccount('salma@smail.tn');
	$cB = $b->DoCreateTwoFactorSecret()['Result'];
	$b->params = array('Code' => $previous($cB['Secret'])); $b->DoVerifyTwoFactorCode();
	$b->params = array('Enable' => '1'); $b->DoEnableTwoFactor();
	$aBefore = $b->raw();

	$check('before the password: no code, the password never reaches the directory', $login($b, array()), $AUTH);
	$check('… refused as a wrong password is: AuthError, no name (nothing says the account has a second factor)', $login($b, array('totp_code' => '')), $AUTH);
	$check('… and it waited like a wrong password', $b->delays, 2);
	$check('a wrong code: refused before the directory', $login($b, array('totp_code' => '000000')), $AUTH);
	for ($i = 0; $i < 20; ++$i) { $login($b, array('totp_code' => \sprintf('%06d', 100000 + $i))); }
	$check('twenty wrong codes write nothing: the record is byte for byte the same', $b->raw(), $aBefore);
	$check('… so no lockout anyone could trigger: the owner\'s right code still passes, then the password', $login($b, array('totp_code' => $current($cB['Secret']))), 'directory+ok');
	$check('… judged once, before the password — login.success does not call it a replay', $dernier($b, 'replay'), false);
	$check('the same code again: refused before the directory (time step spent)', $login($b, array('totp_code' => $current($cB['Secret']))), $AUTH);
	$check('… named a replay in the plugin log only', $dernier($b, 'TFA: replay for salma@smail.tn, refused before the password'), true);
	$sBackup = \explode(' ', $cB['BackupCodes'])[0];
	$check('a backup code passes before the password', $login($b, array('totp_code' => $sBackup)), 'directory+ok');
	$check('… once', $login($b, array('totp_code' => $sBackup)), $AUTH);
	$check('an assertion on an account without a key does not carry a password past the check', $login($b, array('webauthn_assertion' => '{"junk":1}')), $AUTH);
	$check('… nor with a wrong code beside it', $login($b, array('webauthn_assertion' => 'x', 'totp_code' => '000000')), $AUTH);

	// The flag is spent by the first account filtered: a session rebuilt from
	// its cookie (no login.credentials) is never asked for a code.
	$b->fresh(); $b->params = array();
	try { $b->FilterAccount($b->oAccount); $check('a session rebuilt from its cookie is not a login', 'passe', 'passe'); }
	catch (\Throwable $e) { $check('a session rebuilt from its cookie is not a login', 'refused', 'passe'); }
	$b->fresh(); $b->NoteLogin();
	$b->FilterAccount(new \RainLoop\Model\AdditionalAccount('nour@smail.tn'));
	try { $b->FilterAccount($b->oAccount); $check('an additional account\'s setup spends the flag', 'passe', 'passe'); }
	catch (\Throwable $e) { $check('an additional account\'s setup spends the flag', 'refused', 'passe'); }
	$b->fresh(); $b->request(null, true); $b->params = array(); $b->NoteLogin();
	try { $b->FilterAccount($b->oAccount); $check('the admin panel resolving a login is not one', 'passe', 'passe'); }
	catch (\Throwable $e) { $check('the admin panel resolving a login is not one', 'refused', 'passe'); }

	// A wrong code never takes the owner's lock; a right one under a held lock fails closed.
	$b->shortWait();
	$rHeld = \fopen($b->lockFile(), 'c'); \flock($rHeld, LOCK_EX);
	$fT = \microtime(true);
	$check('a wrong code while the record is locked by another request: refused at once', array($login($b, array('totp_code' => '000000')), \microtime(true) - $fT < 0.15), array($AUTH, true));
	$check('a right code while the lock is held: refused ("busy" is not "ok")', $login($b, array('totp_code' => \explode(' ', $cB['BackupCodes'])[2])), $AUTH);
	$check('… named busy, and the code is not spent', array($dernier($b, 'TFA: busy for salma@smail.tn'), \count($b->raw()['BackupHashes'])), array(true, 7));
	\flock($rHeld, LOCK_UN); \fclose($rHeld);

	// A record locked by failures after a right password stays locked here too.
	$aL = $b->raw(); $aL['LockedUntil'] = \time() + 600; $b->setRaw($aL);
	$check('a record locked after a right password: refused before the directory as well', $login($b, array('totp_code' => \explode(' ', $cB['BackupCodes'])[1])), $AUTH);
	$check('… and the backup code is not spent by a locked refusal', \count($b->raw()['BackupHashes']), 7);

	// Accounts without a second factor: nothing changes.
	$u = new P();
	$u->oAccount = new \RainLoop\Model\MainAccount('nour@smail.tn');
	$check('no second factor: no code, the password decides as before', $login($u, array()), 'directory+ok');
	$check('no second factor: a code typed anyway is ignored', $login($u, array('totp_code' => '123456')), 'directory+ok');
	$check('… and nothing waited', $u->delays, 0);

	// Security keys: their challenge follows a right password, so a key account keeps that order without a code.
	$kb = new P();
	$kb->config = $WA;
	$kK = new SoftAuthenticator(-7);
	$aK = $inscrire($kb, $kK);
	// 2.31.0: no longer the exception — no factor, no directory.
	$check('a key account, no code: refused before the directory too (2.31.0)', $login($kb, array()), $AUTH);
	$check('… a junk assertion no longer carries the password past the check', $login($kb, array('webauthn_assertion' => '{}')), $AUTH);
	$deverrouiller($kb);
	$check('… but a code typed on a key account is judged before the password', $login($kb, array('totp_code' => '000000')), $AUTH);
	$check('… and its backup code passes', $login($kb, array('totp_code' => \explode(' ', $aK['BackupCodes'])[0])), 'directory+ok');

	/* ---- 2.31.0: the key's challenge before any password ---- */
	$opts = function (P $x, string $sEmail) {
		$x->fresh(); $x->request(null); $x->params = array('Email' => $sEmail);
		return $x->DoWebAuthnLoginOptions()['Result'];
	};
	$aRawKeys = TwoFactorRecord::passkeys($kb->raw(), TwoFactorRecord::key(APP_SALT));
	$oK = $opts($kb, 'rym');
	$check('login options for a typed address, resolved as the core does (default domain)', array(\is_array($oK), \array_column($oK['allowCredentials'] ?? array(), 'id')), array(true, \array_column($aRawKeys, 'Id')));
	$check('… a stateless challenge of 48 characters', \strlen($oK['challenge']), 48);
	$aRawBefore = $kb->raw();
	for ($i = 0; $i < 30; ++$i) { $opts($kb, 'rym@smail.tn'); }
	$check('… thirty requests for it write nothing: no flood can push the owner\'s challenges out', $kb->raw(), $aRawBefore);
	$oD1 = $opts($kb, 'nour@smail.tn'); $oD2 = $opts($kb, 'nour@smail.tn');
	$check('an address without a key gets options of the same shape', \array_keys($oD1), \array_keys($oK));
	$check('… with decoy ids, the same at each request, as a real account\'s are', array(\array_column($oD1['allowCredentials'], 'id') === \array_column($oD2['allowCredentials'], 'id'), \in_array(\count($oD1['allowCredentials']), array(1, 2), true)), array(true, true));
	$check('… of a security key\'s length (64 bytes)', \strlen(TwoFactorWebAuthn::unb64u($oD1['allowCredentials'][0]['id'])), 64);
	$check('… and a fresh challenge each time', $oD1['challenge'] !== $oD2['challenge'], true);
	$check('an address the core cannot resolve: no options', $opts($kb, 'boom'), false);

	$signe = fn (SoftAuthenticator $k, array $o) => \json_encode($k->get($o['challenge']));
	$sA = $signe($kK, $opts($kb, 'rym@smail.tn'));
	$aBeforeKey = $kb->raw();
	$check('the key before the password: the assertion is judged, then the password goes', $login($kb, array('webauthn_assertion' => $sA)), 'directory+ok');
	$check('… judged once (login.success does not judge it again)', $dernier($kb, 'security key, login'), false);
	$aAfterKey = $kb->raw();
	$check('… the key\'s last use is stored, and its challenge marked spent', array(TwoFactorRecord::passkeys($aAfterKey, TwoFactorRecord::key(APP_SALT))[0]['LastUsed'] > 0, \count($aAfterKey['Spent'] ?? array())), array(true, 1));
	$check('the same assertion again: refused before the directory', $login($kb, array('webauthn_assertion' => $sA)), $AUTH);
	$check('… named in the plugin log', $dernier($kb, 'TFA: webauthn-challenge for rym@smail.tn, refused before the password'), true);
	$sOther = $signe($kK, $opts($kb, 'nour@smail.tn'));
	$check('a challenge asked for another address does not open this one', $login($kb, array('webauthn_assertion' => $sOther)), $AUTH);
	$o3 = $opts($kb, 'rym@smail.tn'); $kb->binding = 'browser-2';
	$check('a challenge asked by another browser does not either', $login($kb, array('webauthn_assertion' => $signe($kK, $o3))), $AUTH);
	$kb->binding = 'browser-1';
	$sExpired = TwoFactorAuthPlugin::loginChallenge('rym@smail.tn', 'browser-1', \time() - 1, TwoFactorRecord::key(APP_SALT));
	$check('an expired challenge, though signed by the key: refused', $login($kb, array('webauthn_assertion' => \json_encode($kK->get($sExpired)))), $AUTH);
	$sForged = TwoFactorAuthPlugin::loginChallenge('rym@smail.tn', 'browser-1', \time() + 300, TwoFactorRecord::key('another install'));
	$check('a challenge made with another key (forged): refused', $login($kb, array('webauthn_assertion' => \json_encode($kK->get($sForged)))), $AUTH);
	$check('a challenge that would last too long: refused', TwoFactorAuthPlugin::loginChallengeValid(TwoFactorAuthPlugin::loginChallenge('rym@smail.tn', 'b', \time() + 4000, 'k'), 'rym@smail.tn', 'b', \time(), 'k'), false);
	$check('… and a well-formed one is valid (the check above is not always false)', TwoFactorAuthPlugin::loginChallengeValid(TwoFactorAuthPlugin::loginChallenge('rym@smail.tn', 'b', \time() + 60, 'k'), 'rym@smail.tn', 'b', \time(), 'k'), true);
	$kOther = new SoftAuthenticator(-7);
	$check('another key, never registered: refused', $login($kb, array('webauthn_assertion' => $signe($kOther, $opts($kb, 'rym@smail.tn')))), $AUTH);
	$aNow = $kb->raw();
	$check('… and none of these failures wrote anything', $aNow, $aAfterKey);
	$kb->shortWait();
	$sHeld = $signe($kK, $opts($kb, 'rym@smail.tn'));
	$rH = \fopen($kb->lockFile(), 'c'); \flock($rH, LOCK_EX);
	$check('a right assertion while the lock is held: refused ("busy" is not "ok")', $login($kb, array('webauthn_assertion' => $sHeld)), $AUTH);
	\flock($rH, LOCK_UN); \fclose($rH);
	$check('… and, the lock free, the same assertion then passes (it was not spent)', $login($kb, array('webauthn_assertion' => $sHeld)), 'directory+ok');
	$aData = array('Auth' => false); $kb->FilterAppData(false, $aData);
	$check('the login screen is told keys are on, before any login', $aData['TwoFactorKeyLogin'], true);
	// A passkey without a counter (most of them): only the spent mark stops a replay.
	$kz = new P();
	$kz->config = $WA;
	$kZ = new SoftAuthenticator(-7);
	$inscrire($kz, $kZ);
	$sZ = \json_encode($kZ->get($opts($kz, 'rym@smail.tn')['challenge'], array('counter' => 0)));
	$check('a passkey without a counter logs in before the password', $login($kz, array('webauthn_assertion' => $sZ)), 'directory+ok');
	$check('… and the same assertion replayed is refused: the challenge was marked spent', $login($kz, array('webauthn_assertion' => $sZ)), $AUTH);
	\is_dir($kz->oStore->root) && \exec('rm -rf ' . \escapeshellarg($kz->oStore->root));

	$kb->config = array();
	$aData = array('Auth' => false); $kb->FilterAppData(false, $aData);
	$check('keys switched off: the login screen is told', $aData['TwoFactorKeyLogin'], false);
	$check('… no login options', $opts($kb, 'rym@smail.tn'), false);
	$check('keys switched off by the administrator: a key account without a code no longer goes past', $login($kb, array()), $AUTH);
	$check('… nor with an assertion', $login($kb, array('webauthn_assertion' => $sA)), $AUTH);

	// The real wait: until the request has lasted precheck_delay seconds (and up to 0.5 s more).
	$tw = new P();
	$tw->realDelay = true;
	$tw->config = array('precheck_delay' => 1);
	$_SERVER['REQUEST_TIME_FLOAT'] = \microtime(true);
	$tw->request(); $tw->params = array(); $tw->NoteLogin();
	$cT = $tw->DoCreateTwoFactorSecret()['Result'];
	$tw->params = array('Code' => $previous($cT['Secret'])); $tw->DoVerifyTwoFactorCode();
	$tw->params = array('Enable' => '1'); $tw->DoEnableTwoFactor();
	$_SERVER['REQUEST_TIME_FLOAT'] = \microtime(true);
	$fT = \microtime(true);
	$login($tw, array('totp_code' => '000000'));
	$fW = \microtime(true) - $fT;
	$check('the refusal waits precheck_delay (1 s here), at most half a second more', $fW >= 0.99 && $fW < 1.6, true);
	$tw->config = array('precheck_delay' => 99);
	$_SERVER['REQUEST_TIME_FLOAT'] = \microtime(true) - 20;
	$fT = \microtime(true);
	$login($tw, array('totp_code' => '000000'));
	$check('… bounded to 10 s, counted from the start of the request', \microtime(true) - $fT < 0.1, true);


	// A Do* method nobody registered is dead code for the browser: every action is hooked, under its own name.
	$hk = new P(); $hk->Init();
	$aDo = \array_values(\array_filter(\array_map(fn ($m) => $m->name, (new \ReflectionClass(TwoFactorAuthPlugin::class))->getMethods(\ReflectionMethod::IS_PUBLIC)),
		fn ($n) => \str_starts_with($n, 'Do') && !\in_array($n, array('DoLogin'), true)));
	$check('every public action of the plugin is registered as a JSON hook', \array_values(\array_diff($aDo, $hk->jsonHooks)), array());
	$check('the three actions of 2.32.0 are hooked under the names the screen calls',
		array($hk->jsonHooks['ConfirmBackupCodes'] ?? '', $hk->jsonHooks['CancelPendingCodes'] ?? '', $hk->jsonHooks['RegenerateBackupCodes'] ?? ''),
		array('DoConfirmBackupCodes', 'DoCancelPendingCodes', 'DoRegenerateBackupCodes'));

	/* ---- 2.32.0: a key as the only second factor is not active until its backup codes are proven kept ---- */
	$registre = function (P $x, SoftAuthenticator $k, array $o = array()) use ($inscrire) { return $inscrire($x, $k, array(), $o + array('sans_preuve' => true)); };
	$confirmer = function (P $x, string $sCode) { $x->params = array('Code' => $sCode); return $x->DoConfirmBackupCodes()['Result']; };

	$v = new P();
	$v->config = $WA;
	$kV = new SoftAuthenticator(-7);
	$aV = $registre($v, $kV);
	$aVCodes = \explode(' ', $aV['BackupCodes']);
	$iAsk = $aV['PendingAsk'] - 1;
	$check('2.32.0: the info says what waits, never the codes', array(\array_key_exists('BackupCodes', $v->DoGetTwoFactorInfo()['Result']), $v->DoGetTwoFactorInfo()['Result']['Pending'], $v->DoGetTwoFactorInfo()['Result']['PendingAsk']), array(false, true, $aV['PendingAsk']));
	$sRawV = $v->oStore->data['rym@smail.tn'];
	$check('2.32.0: stored as hashes and a sealed key: no code, no credential id in the record', \array_sum(\array_map(fn ($c) => (int) \str_contains($sRawV, $c), $aVCodes)) + (int) \str_contains($sRawV, SoftAuthenticator::b64u($kV->credentialId)), 0);
	$check('2.32.0: pending, the account is not enrolled: a forced tenant is still forced', $v->DoGetTwoFactorInfo()['Result']['Enrolled'], false);
	$check('2.32.0: pending, the key is not asked at login (nothing is on yet)', $connexion($v, array()), 'ok');

	// Hostile proofs.
	foreach (array('', '   ', '12345', '1234567890', 'abcdefghi', "12345678\0", '１２３４５６７８９', '000000000') as $sBad) {
		$check('2.32.0: hostile proof ' . \json_encode($sBad) . ' refused', $confirmer($v, $sBad), false);
	}
	$v->params = array('Code' => array($aVCodes[$iAsk]));
	$check('2.32.0: a proof sent as an array is refused', $v->DoConfirmBackupCodes()['Result'], false);
	$check('2.32.0: five wrong proofs discard the codes (and the pending key)', array($v->DoGetTwoFactorInfo()['Result']['Pending'], $v->DoGetTwoFactorInfo()['Result']['Passkeys']), array(false, array()));
	$check('2.32.0: … and the right one no longer works', $confirmer($v, $aVCodes[$iAsk]), false);
	$check('2.32.0: … the account is exactly as before (no factor)', $v->DoGetTwoFactorInfo()['Result']['On'], false);

	// Another browser, an expiry, a cancel.
	$aV = $registre($v, $kV);
	$aVCodes = \explode(' ', $aV['BackupCodes']); $iAsk = $aV['PendingAsk'] - 1;
	$v->binding = 'browser-2';
	$check('2.32.0: another browser of the same account cannot confirm what it never saw', $confirmer($v, $aVCodes[$iAsk]), false);
	$v->binding = 'browser-1';
	$aRaw = $v->raw(); $aRaw['Pending']['e'] = \time() - 1; $v->setRaw($aRaw);
	$check('2.32.0: expired codes are no proof', array($confirmer($v, $aVCodes[$iAsk]), $v->DoGetTwoFactorInfo()['Result']['Pending']), array(false, false));
	$aV = $registre($v, $kV);
	$v->params = array();
	$check('2.32.0: cancel drops the pending codes and key', array($v->DoCancelPendingCodes()['Result']['Pending'], $v->DoGetTwoFactorInfo()['Result']['Passkeys']), array(false, array()));
	$check('2.32.0: nothing pending: a proof is refused', $confirmer($v, '123456789'), false);

	// The right proof.
	$aV = $registre($v, $kV);
	$aVCodes = \explode(' ', $aV['BackupCodes']); $iAsk = $aV['PendingAsk'] - 1;
	$aRaw = $v->raw(); $aRaw['Failures'] = array(\time(), \time()); $aRaw['LockedUntil'] = 0; $v->setRaw($aRaw);
	$aOk = $confirmer($v, $aVCodes[$iAsk]);
	$check('2.32.0: the right code: the key is active, the second factor on, the key alone', array($aOk['On'], $aOk['Enrolled'], $aOk['OnlyKey'], $aOk['Pending'], \count($aOk['Passkeys']), $aOk['BackupLeft']), array(true, true, true, false, 1, 8));
	$check('2.32.0: the lockout counter is not wiped by a confirmation', \count($v->raw()['Failures']), 2);
	$check('2.32.0: … and a backup code now opens the login (spent: 7 left)', $connexion($v, array('totp_code' => $aVCodes[0])), 'ok');
	$check('2.32.0: … the retyped code is one of the codes in force, not spent', $v->DoGetTwoFactorInfo()['Result']['BackupLeft'], 7);
	$check('2.32.0: login now needs the second factor', $connexion($v, array()), 'refused:TwoFactorCodeRequired');
	$check('2.32.0: no backup code is kept in clear in the record', \array_sum(\array_map(fn ($c) => (int) \str_contains($v->oStore->data['rym@smail.tn'], $c), $aVCodes)), 0);

	// A key sitting next to a half-made authenticator enrolment: the enrolment is given up, not left with dead codes.
	$h2 = new P(); $h2->config = $WA;
	$c2 = $h2->DoCreateTwoFactorSecret()['Result'];
	$a2 = $registre($h2, new SoftAuthenticator(-7));
	$confirmer($h2, \explode(' ', $a2['BackupCodes'])[$a2['PendingAsk'] - 1]);
	$check('2.32.0: a half-made authenticator enrolment next to the key is abandoned (its codes were replaced)', array($h2->DoGetTwoFactorInfo()['Result']['IsSet'], isset($h2->raw()['SecretBox'])), array(false, false));
	$check('2.32.0: … its old codes are dead', $connexion($h2, array('totp_code' => \explode(' ', $c2['BackupCodes'])[0])), 'refused:');

	// Regenerating the codes.
	$v->params = array();
	$check('2.32.0: regenerate without a current factor is refused', $v->DoRegenerateBackupCodes()['Result'], false);
	$v->params = array('Code' => '123456');
	$check('2.32.0: … with a wrong code too', $v->DoRegenerateBackupCodes()['Result'], false);
	$deverrouiller($v);
	$aRg = $v->DoRegenerateBackupCodes() ; $v->params = $preuve($v, $kV);
	$aRg = $v->DoRegenerateBackupCodes()['Result'];
	$aNew = \explode(' ', $aRg['BackupCodes']);
	$check('2.32.0: with the key: eight new codes, pending, no key waiting', array(\count($aNew), $aRg['Pending'], $aRg['PendingKey'], $aRg['BackupLeft']), array(8, true, false, 7));
	$check('2.32.0: until confirmed, the old codes hold', $connexion($v, array('totp_code' => $aVCodes[1])), 'ok');
	$check('2.32.0: … and the new ones do not yet', $connexion($v, array('totp_code' => $aNew[0])), 'refused:');
	$deverrouiller($v);
	$check('2.32.0: a wrong proof leaves the old ones', $confirmer($v, $aNew[($aRg['PendingAsk']) % 8]), false);
	$aC = $confirmer($v, $aNew[$aRg['PendingAsk'] - 1]);
	$check('2.32.0: confirmed: eight codes, the key untouched', array($aC['BackupLeft'], \count($aC['Passkeys']), $aC['Pending']), array(8, 1, false));
	$check('2.32.0: the old codes are dead, the new ones work', array($connexion($v, array('totp_code' => $aVCodes[2])), $connexion($v, array('totp_code' => $aNew[0]))), array('refused:', 'ok'));
	$z = new P(); $z->config = $WA;
	$check('2.32.0: no second factor: nothing to regenerate', $z->DoRegenerateBackupCodes()['Result'], false);

	// With a second key / with the authenticator on: no waiting.
	$check('2.32.0: a second key is active at once (the codes already exist)', \count($inscrire($v, new SoftAuthenticator(-8), $preuve($v, $kV))['Passkeys']), 2);
	$t2 = new P(); $t2->config = $WA;
	$cT2 = $t2->DoCreateTwoFactorSecret()['Result'];
	$t2->params = array('Code' => $previous($cT2['Secret'])); $t2->DoVerifyTwoFactorCode();
	$t2->params = array('Enable' => '1'); $t2->DoEnableTwoFactor();
	$aT2 = $inscrire($t2, new SoftAuthenticator(-7), array('Code' => $current($cT2['Secret'])));
	$check('2.32.0: with the authenticator on, a key is active at once and the warning stays off', array(\count($aT2['Passkeys']), $aT2['OnlyKey'], $aT2['Pending']), array(1, false, false));

	// The warning: a key alone says so, and not once an authenticator joins.
	$check('2.32.0: the info of a key-only account carries the warning flag', $v->DoGetTwoFactorInfo()['Result']['OnlyKey'], true);
	$check('2.32.0: the actions of the proof are open to an account still setting up', array(\str_contains(TwoFactorAuthPlugin::SETUP_ALLOWED_ACTIONS, 'DoPluginConfirmBackupCodes'), \str_contains(TwoFactorAuthPlugin::SETUP_ALLOWED_ACTIONS, 'DoPluginCancelPendingCodes'), \str_contains(TwoFactorAuthPlugin::SETUP_ALLOWED_ACTIONS, 'Regenerate')), array(true, true, false));

	foreach (array($v, $h2, $z, $t2) as $x) { \is_dir($x->oStore->root) && \exec('rm -rf ' . \escapeshellarg($x->oStore->root)); }

	foreach (array($b, $u, $kb, $tw) as $x) { \is_dir($x->oStore->root) && \exec('rm -rf ' . \escapeshellarg($x->oStore->root)); }

	foreach (array($d, $w, $e, $ap, $ar, $sm, $off) as $x) { \is_dir($x->oStore->root) && \exec('rm -rf ' . \escapeshellarg($x->oStore->root)); }

	// The temporary storage of every double.
	foreach (array($p, $r, $t, $a, $n, $q, $o, $w, $f, $g, $h, $k) as $x) { \is_dir($x->oStore->root) && \exec('rm -rf ' . \escapeshellarg($x->oStore->root)); }

	echo "\n", $iFail ? "$iFail failed\n" : "0 failed\n";
	exit($iFail ? 1 : 0);
}
