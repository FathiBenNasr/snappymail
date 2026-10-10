<?php
/**
 * two-factor-auth 2.27.0 — the actions, through the real plugin class, with
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
		public function addJsonHook($a, $b) : void {}
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
		protected function Logger() : \MailSo\Log\Logger { return new \MailSo\Log\Logger($this); }
		protected function getMainAccountFromToken() : \RainLoop\Model\MainAccount { return $this->oAccount; }
		protected function StorageProvider() : \RainLoop\Providers\Storage { return new \RainLoop\Providers\Storage($this->oStore); }
		protected function logAuthFailure(\RainLoop\Model\MainAccount $o, string $s) : void { ++$this->authFailures; }
		public function Manager() { $p = $this; return new class ($p) {
			// Private, as in Plugins\Manager: the parts other plugins registered (caldav, files).
			private array $aAdditionalParts = array('caldavexport' => array(), 'files' => array(), 'twofactorsetuprequired' => array());
			public function __construct(private $p) {} public function Actions() { return $this->p->actions; } }; }
	}
}
namespace MailSo\Base { class Http { public static function StatusHeader(int $i) : void {} } }
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

	// The temporary storage of every double.
	foreach (array($p, $r, $t, $a, $n, $q, $o, $w, $f, $g, $h, $k) as $x) { \is_dir($x->oStore->root) && \exec('rm -rf ' . \escapeshellarg($x->oStore->root)); }

	echo "\n", $iFail ? "$iFail failed\n" : "0 failed\n";
	exit($iFail ? 1 : 0);
}
