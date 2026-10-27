<?php

require_once __DIR__ . '/providers/record.php';
require_once __DIR__ . '/providers/webauthn.php';

use \RainLoop\Exceptions\ClientException;
use \RainLoop\Model\Account;
use \RainLoop\Model\MainAccount;

class TwoFactorAuthPlugin extends \RainLoop\Plugins\AbstractPlugin
{
	const
		NAME     = 'Two Factor Authentication',
		VERSION  = '2.32.0',
		RELEASE  = '2026-10-26',
		REQUIRED = '2.36.0',
		CATEGORY = 'Login',
		DESCRIPTION = 'Provides support for TOTP 2FA and security keys / passkeys (WebAuthn) as a second factor',
		// The additional message of the refusal when the code is missing.
		CODE_REQUIRED = 'TwoFactorCodeRequired',
		// The additional message when a protected account is refused as an additional one.
		NOT_ADDITIONAL = 'TwoFactorNotAdditional',
		// The additional message of every request refused while an account
		// that must set up the second factor has not (2.27.0).
		SETUP_REQUIRED = 'TwoFactorSetupRequired',
		/**
		 * What an account that must enrol may still call, measured on
		 * banc-smail on 10 October 2026 (tests/browser/forcer.js, MESURE=1):
		 * the boot of the application, the settings screen, creating the
		 * secret, testing the code, enabling, logging out.
		 *  - DoFolders: the boot calls it, and on a refusal the application
		 *    logs out and says "Folders error" — the screen that enrols would
		 *    never be reached. It gives folder names and counters, no message.
		 *  - DoPluginShowTwoFactorSecret and DoPluginClearTwoFactorInfo: two
		 *    links of the same screen ("show the secret", "clear"), for whoever
		 *    lost the QR code before testing it.
		 * Everything else the boot calls (AccountsAndIdentities, SettingsUpdate,
		 * other plugins) is refused, and the screen still enrols.
		 *  - DoPluginWebAuthnCreateOptions and DoPluginWebAuthnRegister (2.28.0):
		 *    a security key is a second factor too, and registering one is how
		 *    such an account may enrol instead of the TOTP. Measured on
		 *    banc-smail (tests/browser/cle.js).
		 */
		SETUP_ALLOWED_ACTIONS = 'DoFolders DoLogout DoPluginGetTwoFactorInfo DoPluginCreateTwoFactorSecret'
			. ' DoPluginShowTwoFactorSecret DoPluginVerifyTwoFactorCode DoPluginEnableTwoFactor DoPluginClearTwoFactorInfo'
			. ' DoPluginWebAuthnCreateOptions DoPluginWebAuthnRegister DoPluginConfirmBackupCodes DoPluginCancelPendingCodes',
		/**
		 * The services (first segment of ?/<Service>/...) such an account may
		 * reach. Measured: AppData, Plugins, Json. Css and Lang serve code,
		 * not data, and the settings screens that stay reachable switch theme
		 * and language through them; Raw and Json are then filtered action by
		 * action. Everything else — Upload, ProxyExternal, the parts of other
		 * plugins (calendar export, files) — never reaches filter.action-params,
		 * so it is refused here, whole.
		 */
		SETUP_ALLOWED_SERVICES = 'AppData Plugins Json Raw Css Lang Ping';

	public function Init() : void
	{
		$this->UseLangs(true);

		$this->addJs('js/TwoFactorWebAuthn.js');
		$this->addJs('js/TwoFactorAuthLogin.js');
		$this->addJs('js/TwoFactorAuthSettings.js');

		$this->addHook('login.success', 'DoLogin');
		// 2.30.0: the code is judged BEFORE the password reaches the directory.
		// login.credentials runs only inside a login; the filter.account that
		// follows it carries the account the login is about.
		$this->addHook('login.credentials', 'NoteLogin');
		// login.success runs for the main account only: an additional account
		// goes through filter.account alone, at setup and on every request.
		$this->addHook('filter.account', 'FilterAccount');
		$this->addHook('filter.app-data', 'FilterAppData');
		// 2.27.0: "enforce" held by the server, not only by the redirect of
		// TwoFactorAuthLogin.js — a session could call the API directly.
		$this->addHook('filter.action-params', 'FilterActionParams');
		$this->addHook('filter.http-paths', 'FilterHttpPaths');
		$this->addPartHook(self::SETUP_REQUIRED, 'ServiceSetupRequired');

		$this->addJsonHook('GetTwoFactorInfo', 'DoGetTwoFactorInfo');
		$this->addJsonHook('CreateTwoFactorSecret', 'DoCreateTwoFactorSecret');
		$this->addJsonHook('ShowTwoFactorSecret', 'DoShowTwoFactorSecret');
		$this->addJsonHook('EnableTwoFactor', 'DoEnableTwoFactor');
		$this->addJsonHook('VerifyTwoFactorCode', 'DoVerifyTwoFactorCode');
		$this->addJsonHook('ClearTwoFactorInfo', 'DoClearTwoFactorInfo');
		// 2.28.0: security keys and passkeys (WebAuthn) as a second factor.
		$this->addJsonHook('WebAuthnCreateOptions', 'DoWebAuthnCreateOptions');
		$this->addJsonHook('WebAuthnRegister', 'DoWebAuthnRegister');
		$this->addJsonHook('WebAuthnAssertOptions', 'DoWebAuthnAssertOptions');
		// 2.31.0: a key's challenge for the login screen, before any password.
		$this->addJsonHook('WebAuthnLoginOptions', 'DoWebAuthnLoginOptions');
		$this->addJsonHook('WebAuthnRename', 'DoWebAuthnRename');
		$this->addJsonHook('WebAuthnRemove', 'DoWebAuthnRemove');
		// 2.32.0: the proof that the backup codes are kept, and new codes.
		$this->addJsonHook('ConfirmBackupCodes', 'DoConfirmBackupCodes');
		$this->addJsonHook('CancelPendingCodes', 'DoCancelPendingCodes');
		$this->addJsonHook('RegenerateBackupCodes', 'DoRegenerateBackupCodes');

		$this->addTemplate('templates/TwoFactorAuthSettings.html');
		$this->addTemplate('templates/PopupsTwoFactorAuthTest.html');
	}

	public function configMapping() : array
	{
		return [
			\RainLoop\Plugins\Property::NewInstance("force_two_factor_auth")
//				->SetLabel('PLUGIN_TWO_FACTOR/LABEL_FORCE')
				->SetLabel('Enforce 2-Step Verification')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::BOOL),
			\RainLoop\Plugins\Property::NewInstance("force_two_factor_domains")
				->SetLabel('Enforce 2-Step Verification for these domains')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::STRING_TEXT)
				->SetDescription('One domain per line (or separated by commas or spaces). Accounts of these domains must set up 2-Step Verification, as with the switch above, which applies to everyone. Empty: nobody but what the switch above says.')
				->SetDefaultValue(''),
			\RainLoop\Plugins\Property::NewInstance("setup_allowed_actions")
				->SetLabel('Allowed until 2-Step Verification is set up: actions')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::STRING_TEXT)
				->SetDescription('While an account that must set up 2-Step Verification has not, the server refuses every action not listed here (method names: DoX for ?/Json, DoPluginX for a plugin action, RawX for ?/Raw). Empty: the measured default, ' . self::SETUP_ALLOWED_ACTIONS . '.')
				->SetDefaultValue(''),
			\RainLoop\Plugins\Property::NewInstance("setup_allowed_services")
				->SetLabel('Allowed until 2-Step Verification is set up: services')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::STRING_TEXT)
				->SetDescription('The same, for the first segment of the address (?/Service/...). Json and Raw are then filtered action by action. Empty: ' . self::SETUP_ALLOWED_SERVICES . '.')
				->SetDefaultValue(''),
			\RainLoop\Plugins\Property::NewInstance("precheck_delay")
				->SetLabel('Seconds a wrong code waits before it is refused')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::INT)
				->SetDescription('The code is checked before the password. Its refusal must take as long as a wrong password, or the wait tells who has 2-Step Verification: Cyrus pauses failedloginpause (3 s by default) after a failed login. Between 0 and 10.')
				->SetDefaultValue(3),
			\RainLoop\Plugins\Property::NewInstance("otp_issuer")
				->SetLabel('Service name shown in the authenticator')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::STRING)
				->SetDescription('Names this service next to the account in the authenticator app. Empty: the webmail title.')
				->SetDefaultValue(''),
			\RainLoop\Plugins\Property::NewInstance("otp_image_url")
				->SetLabel('Authenticator icon URL')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::STRING)
				->SetDescription('Optional https:// address of a square PNG (256x256 works well) that FreeOTP, FreeOTP+ and 2FAS draw next to the account. The phone fetches it, not the browser, so it must be reachable from the internet. Google Authenticator, Microsoft Authenticator and Aegis ignore it.')
				->SetDefaultValue(''),
			// 2.28.0: security keys and passkeys (WebAuthn), as a second factor only.
			\RainLoop\Plugins\Property::NewInstance("webauthn_enabled")
				->SetLabel('Security keys and passkeys (WebAuthn) as a second factor')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::BOOL)
				->SetDescription('A second factor next to the TOTP code, never instead of the password: the password still opens the mailbox. Needs the origin below.')
				->SetDefaultValue(false),
			\RainLoop\Plugins\Property::NewInstance("webauthn_origins")
				->SetLabel('Security keys: webmail origins')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::STRING_TEXT)
				->SetDescription('The addresses this webmail is served at, one per line, e.g. https://webmail.example.com (scheme, host, and port when not the default). The browser reports the origin; the Host header of the request is never trusted. Empty: security keys stay off.')
				->SetDefaultValue(''),
			\RainLoop\Plugins\Property::NewInstance("webauthn_rp_id")
				->SetLabel('Security keys: relying party ID')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::STRING)
				->SetDescription('The domain the keys are bound to: the host of the origins or a parent domain of it. Empty: the host of the first origin. Changing it later makes every registered key unusable.')
				->SetDefaultValue(''),
			\RainLoop\Plugins\Property::NewInstance("webauthn_require_uv")
				->SetLabel('Security keys: require user verification (PIN or biometrics)')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::BOOL)
				->SetDescription('Off: a touch of the key is enough (it is a second factor, the password came first). On: keys without a PIN or biometrics are refused.')
				->SetDefaultValue(false),
			\RainLoop\Plugins\Property::NewInstance("webauthn_max_passkeys")
				->SetLabel('Security keys: at most this many per account')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::INT)
				->SetDefaultValue(10),
			\RainLoop\Plugins\Property::NewInstance("webauthn_challenge_ttl")
				->SetLabel('Security keys: seconds a challenge stays valid')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::INT)
				->SetDescription('Between 30 and 3600. Each challenge is used once.')
				->SetDefaultValue(300),
			\RainLoop\Plugins\Property::NewInstance("webauthn_counter_regression")
				->SetLabel('Security keys: a signature counter that goes back')
				->SetType(\RainLoop\Enumerations\PluginPropertyType::SELECTION)
				->SetDescription('refuse: the sign-in is refused (a counter that does not grow may mean a cloned key). warn: accepted and logged.')
				->SetDefaultValue(array('refuse', 'warn')),
		];
	}

	public function FilterAppData($bAdmin, &$aResult)
	{
		if (!$bAdmin && \is_array($aResult)/* && isset($aResult['Auth']) && !$aResult['Auth']*/) {
			$aResult['RequireTwoFactor'] = (bool) $this->Config()->Get('plugin', 'force_two_factor_auth', false);

			$aResult['SetupTwoFactor'] = false;
			// 2.31.0: the login screen offers a security key whenever keys are on
			// for this webmail — for every visitor, so it says nothing of anyone.
			$aResult['TwoFactorKeyLogin'] = null !== $this->webAuthnConf();
			if (!empty($aResult['Auth'])) {
				$oAccount = $this->getMainAccountFromToken();
				// Per tenant (2.26.0): a domain in the list is held to the
				// same rule as the global switch, and only its accounts.
				$aResult['RequireTwoFactor'] = $aResult['RequireTwoFactor'] || $this->forcedFor($oAccount->Email());
				if ($aResult['RequireTwoFactor']) {
					$aData = $this->getTwoFactorInfo($oAccount);
					// A security key counts as much as the TOTP (2.28.0).
					$aResult['SetupTwoFactor'] = empty($aData['Enrolled']);
				}
			}

			// The settings screen states that mail apps need app passwords only
			// where that is actually enforced for this account (S-09): a promise
			// the server does not keep is worse than no promise.
			$aResult['TwoFactorAppPasswords'] = false;
			if (!empty($aResult['Auth'])) {
				try {
					$aResult['TwoFactorAppPasswords'] = null !== $this->appPasswordsConf($this->getMainAccountFromToken());
				} catch (\Throwable $oError) {
					// No account, no promise.
				}
			}
		}
	}

	/**
	 * The domains whose accounts must set up the second factor.
	 *
	 * @return string[] lower-case domain names; anything that is not one is dropped
	 */
	public static function parseDomains(string $sList) : array
	{
		$aResult = array();
		foreach (\preg_split('/[\s,;]+/', \strtolower($sList), -1, PREG_SPLIT_NO_EMPTY) as $sDomain) {
			$sDomain = \ltrim($sDomain, '@');
			if (\preg_match('/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/', $sDomain)) {
				$aResult[$sDomain] = $sDomain;
			}
		}
		return \array_values($aResult);
	}

	/** Whether the account's domain is one the administrator listed. */
	protected function forcedFor(string $sEmail) : bool
	{
		$iAt = \strrpos($sEmail, '@');
		if (false === $iAt) {
			return false;
		}
		$sDomain = \strtolower(\substr($sEmail, $iAt + 1));
		return \in_array($sDomain,
			static::parseDomains((string) $this->Config()->Get('plugin', 'force_two_factor_domains', '')), true);
	}

	/**
	 * Every action of an account that must set up the second factor and has
	 * not is refused, except the allowed ones (2.27.0, CDU-10 / S-76).
	 *
	 * Until 2.26.0 the rule was a redirect in the browser: the session of such
	 * an account read mail through ?/Json and ?/Raw like any other. The core
	 * runs this hook for every ?/Json action — FilterHttpPaths below closes
	 * the one GET form it skips — and every ?/Raw one, before the action.
	 * Fail closed: an action not in the list is refused, and a record that
	 * cannot be read counts as "not set up".
	 */
	public function FilterActionParams($sMethodName, $aParams = null) : void
	{
		$sMethodName = (string) $sMethodName;
		if ($this->setupAllows('setup_allowed_actions', self::SETUP_ALLOWED_ACTIONS, $sMethodName)
		 || !$this->setupRequired()) {
			return;
		}
		$this->Logger()->Write("TFA: {$sMethodName} refused, 2-Step Verification must be set up first");
		throw new ClientException(\RainLoop\Notifications::ClientViewError, null, self::SETUP_REQUIRED);
	}

	/**
	 * The two paths filter.action-params does not see (2.27.0).
	 *
	 * 1. A GET ?/Json/&q[]=/0/<Action> with nothing after the action: the
	 *    core takes the action from the path but calls SetActionParams only
	 *    when a fourth segment exists — so Folders, Contacts... answered
	 *    without the hook, and without a token (no CSRF check on GET). An
	 *    empty fourth segment makes the core call it; the action reads no
	 *    parameter from it (RawKey '' is "none").
	 * 2. Any other service: Upload*, ProxyExternal, the parts of other
	 *    plugins. Not allowed: sent to ServiceSetupRequired, which refuses.
	 *
	 * Nothing changes for an account that is not required to enrol, nor for
	 * the admin panel, nor before login.
	 */
	public function FilterHttpPaths(&$aPaths) : void
	{
		if (!\is_array($aPaths) || empty($aPaths[0])) {
			return;
		}
		$sService = \strtolower(\preg_replace('/@.*$/', '', (string) $aPaths[0]));
		if ('' === $sService || 'index' === $sService || \strtolower(self::SETUP_REQUIRED) === $sService) {
			return;
		}
		if ($this->setupAllows('setup_allowed_services', self::SETUP_ALLOWED_SERVICES, $sService)) {
			if ('json' === $sService && 3 === \count($aPaths) && '' !== (string) $aPaths[2]
			 && !$this->setupAllows('setup_allowed_actions', self::SETUP_ALLOWED_ACTIONS, 'Do' . $aPaths[2])
			 && $this->setupRequired()) {
				$aPaths[] = '';
			}
			return;
		}
		if ($this->servesSomething($sService) && $this->setupRequired()) {
			$this->Logger()->Write("TFA: service {$aPaths[0]} refused, 2-Step Verification must be set up first");
			$aPaths = array(self::SETUP_REQUIRED);
		}
	}

	/**
	 * Whether the core would answer this first segment with something other
	 * than the application page: a ServiceActions method or a plugin part.
	 * Anything else (?lang=fr, a typo) gets the page, as before 2.27.0. The
	 * parts are a private list of the plugin manager: when it cannot be read,
	 * the answer is yes — refused rather than served.
	 */
	protected function servesSomething(string $sService) : bool
	{
		if (\method_exists(\RainLoop\ServiceActions::class, 'Service' . $sService)) {
			return true;
		}
		try {
			$oManager = $this->Manager();
			return (bool) \Closure::bind(fn () => isset($this->aAdditionalParts[$sService]),
				$oManager, \get_class($oManager))();
		} catch (\Throwable $oError) {
			return true;
		}
	}

	/** The answer of a refused service: the shape of a refused ?/Json action. */
	public function ServiceSetupRequired() : bool
	{
		if (!\headers_sent()) {
			\MailSo\Base\Http::StatusHeader(403);
			\header('Content-Type: application/json; charset=utf-8');
		}
		echo \json_encode(array(
			'Action' => self::SETUP_REQUIRED,
			'Result' => false,
			'code' => \RainLoop\Notifications::ClientViewError,
			'message' => '',
			'messageAdditional' => self::SETUP_REQUIRED
		));
		return true;
	}

	/** Whether $sName is in the configured list, or in the default when it is empty. Case-insensitive, as PHP method names. */
	protected function setupAllows(string $sKey, string $sDefault, string $sName) : bool
	{
		$sList = \trim((string) $this->Config()->Get('plugin', $sKey, ''));
		$aList = \preg_split('/[\s,;]+/', \strtolower('' === $sList ? $sDefault : $sList), -1, PREG_SPLIT_NO_EMPTY);
		return '' !== $sName && \in_array(\strtolower($sName), $aList, true);
	}

	/**
	 * Logged in (not the admin panel), required to enrol — global switch or a
	 * listed domain — and without a second factor switched on. Not cached: the
	 * same request can be the one that enables it.
	 */
	protected function setupRequired() : bool
	{
		$oActions = $this->Manager()->Actions();
		if ($oActions instanceof \RainLoop\ActionsAdmin) {
			return false;
		}
		$bGlobal = (bool) $this->Config()->Get('plugin', 'force_two_factor_auth', false);
		if (!$bGlobal && !static::parseDomains((string) $this->Config()->Get('plugin', 'force_two_factor_domains', ''))) {
			// Nobody is required: the session is not even looked at.
			return false;
		}
		$oAccount = $this->currentMainAccount();
		if (!$oAccount || (!$bGlobal && !$this->forcedFor($oAccount->Email()))) {
			return false;
		}
		try {
			$aRecord = $this->loadRecord($oAccount);
		} catch (\Throwable $oError) {
			$this->Logger()->Write("TFA: record of {$oAccount->Email()} unreadable, counted as not set up");
			return true;
		}
		return !$aRecord || !TwoFactorRecord::hasFactor($aRecord, $this->recordKey());
	}

	/**
	 * The main account of the session, or null before login.
	 *
	 * Asked without exceptions; but the core then keeps "no account" for the
	 * rest of the request, and the action that follows would no longer throw
	 * its own InvalidToken ("session gone") — which is what sends the browser
	 * back to the login screen. The core is left as it was found.
	 */
	protected function currentMainAccount() : ?MainAccount
	{
		$oActions = $this->Manager()->Actions();
		try {
			$oAccount = $oActions->getMainAccountFromToken(false);
		} catch (\Throwable $oError) {
			$oAccount = null;
		}
		if (!$oAccount) {
			try {
				// Bound to the class that declares the property (UserAuth, a trait of Actions).
				\Closure::bind(function () {
					\property_exists($this, 'oMainAuthAccount') && $this->oMainAuthAccount = false;
				}, $oActions, \RainLoop\Actions::class)();
			} catch (\Throwable $oError) {
			}
		}
		return $oAccount instanceof MainAccount ? $oAccount : null;
	}

	/**
	 * An additional account whose own second factor is on is refused (S-22).
	 *
	 * Adding an account (DoAccountSetup) calls LoginProcess(..., false), which
	 * never runs login.success — so DoLogin, and the code, were skipped: the
	 * password of a protected mailbox was enough to read it through someone
	 * else's session. There is no field for a code in the additional-account
	 * dialog, so the only safe answer is no. The hook also runs each time an
	 * additional account is rebuilt from its cookie, which closes accounts
	 * that were added before this check existed, or before their owner turned
	 * the second factor on.
	 */
	public function FilterAccount($oAccount)
	{
		// Spent by the first account filtered after login.credentials, whichever
		// it is: an additional account's setup must not leave it for the next.
		$bLoggingIn = $this->bLoggingIn;
		$this->bLoggingIn = false;
		if ($oAccount instanceof MainAccount) {
			$bLoggingIn && $this->CheckBeforePassword($oAccount);
			return;
		}
		if (!($oAccount instanceof \RainLoop\Model\AdditionalAccount)) {
			return;
		}
		// By address: the storage of an AdditionalAccount object resolves to
		// the directory of the main account that holds it, not to its own.
		$aRecord = $this->loadRecordFor($oAccount->Email());
		if (!$aRecord || !TwoFactorRecord::isOn($aRecord, $this->recordKey())) {
			return;
		}
		$this->Logger()->Write("TFA: {$oAccount->Email()} refused as an additional account, its second factor is on");
		try {
			// Back to the main account, so the session is not left on a refused one.
			$this->Manager()->Actions()->SetAdditionalAuthToken(null);
		} catch (\Throwable $oError) {
		}
		throw new ClientException(\RainLoop\Notifications::AuthError, null, self::NOT_ADDITIONAL);
	}

	/** Set by login.credentials, spent by the filter.account of the same login. */
	private bool $bLoggingIn = false;
	/** The address whose code CheckBeforePassword() accepted in this request. */
	private string $sVerifiedBeforePassword = '';

	public function NoteLogin(&$sEmail = '', &$sImapUser = '', &$sPassword = '', &$sSmtpUser = '') : void
	{
		$this->bLoggingIn = !($this->Manager()->Actions() instanceof \RainLoop\ActionsAdmin);
	}

	/**
	 * The code, judged before the password is sent to IMAP — hence to the
	 * directory (2.30.0, TODO §72 of the suite).
	 *
	 * Why: every wrong password sent to IMAP is a failure counted by the
	 * directory's password policy, which slows and then locks the account.
	 * Whoever knows only an address could lock its owner out. For an account
	 * whose authenticator is on, a login without its right code now stops
	 * here: nothing reaches the directory, nothing is counted, and the
	 * password can no longer be guessed through the webmail.
	 *
	 * What this opens, and how it is closed:
	 *  - Whether an account has a second factor must not show. The refusal is
	 *    the core's own for a wrong password: AuthError, no additional message,
	 *    the core's auth-log line (fail2ban), and the same duration
	 *    (precheck_delay, Cyrus' failedloginpause).
	 *  - A wrong code here is NOT counted toward the record's lockout: anyone
	 *    may send one, and a lockout anyone can trigger is the weapon this
	 *    removes. The limit is per IP (fail2ban). Each right code then lets
	 *    one password through, once (the time step is spent): guessing the
	 *    password now costs some 330 000 guessed codes per try.
	 *  - A wrong code is judged without the lock and without writing: an
	 *    attacker's attempts never hold the owner's record.
	 *  - Security keys (2.31.0): the challenge is asked for by the login
	 *    screen before any password (DoWebAuthnLoginOptions) and judged here.
	 *    Until 2.30.0 it was issued after a right password, so an account
	 *    with a key let its password through to the directory.
	 *  - IMAP and SMTP clients are not covered: they reach the directory
	 *    directly (app passwords and the slowdown of the policy guard them).
	 */
	public function CheckBeforePassword(MainAccount $oAccount) : void
	{
		$aRecord = $this->loadRecord($oAccount);
		if (!$aRecord || !TwoFactorRecord::isOn($aRecord, $this->recordKey())) {
			return;
		}
		$sAssertion = \trim((string) $this->jsonParam('webauthn_assertion', ''));
		$sCode = \trim((string) $this->jsonParam('totp_code', ''));
		if ('' !== $sAssertion) {
			// 2.31.0: a key is judged here too, against the challenge the login
			// screen asked for (DoWebAuthnLoginOptions) — so an account with
			// a key is no longer the exception: no factor, no directory.
			$sOutcome = $this->checkAssertionBeforePassword($oAccount, $sAssertion);
		} else if ('' === $sCode) {
			$sOutcome = 'missing';
		} else {
			$sOutcome = $this->checkCodeBeforePassword($oAccount, $sCode);
		}
		if ('ok' === $sOutcome) {
			$this->sVerifiedBeforePassword = $oAccount->Email();
			$this->Logger()->Write("TFA: Code verified for {$oAccount->Email()}, before the password");
			return;
		}
		$this->Logger()->Write("TFA: {$sOutcome} for {$oAccount->Email()}, refused before the password");
		$this->delayLikeAWrongPassword();
		// The core's refusal of a wrong password, exactly: same code, no name.
		throw new ClientException(\RainLoop\Notifications::AuthError);
	}

	/**
	 * One code before the password: 'ok', or why not. A wrong one is judged on
	 * the record as read, and nothing is written; a right one is judged again
	 * under the lock and spent (time step or backup code) — the record read
	 * once the lock is held decides, as in checkCode().
	 */
	protected function checkCodeBeforePassword(MainAccount $oAccount, string $sCode) : string
	{
		$fJudge = function (array $aRecord) use ($oAccount, $sCode) : array {
			$oProvider = $this->TwoFactorAuthProvider($oAccount);
			$bTotp = !empty($aRecord['Enable']);
			return TwoFactorRecord::check($aRecord, $sCode, $this->recordKey(), \time(),
				fn (string $sSecret, string $s) => $bTotp ? $oProvider->MatchingSlice($sSecret, $s) : null);
		};
		$aRecord = $this->loadRecord($oAccount);
		if (!$aRecord) {
			return 'wrong';
		}
		[$sOutcome] = $fJudge($aRecord);
		if ('ok' !== $sOutcome) {
			return $sOutcome;
		}
		return $this->underLock($oAccount, function () use ($oAccount, $fJudge) {
			$aRecord = $this->loadRecord($oAccount);
			if (!$aRecord) {
				return 'wrong';
			}
			[$sOutcome, $aNew] = $fJudge($aRecord);
			if ('ok' !== $sOutcome) {
				// Spent by a parallel login meanwhile: a replay, not counted either.
				return $sOutcome;
			}
			return $this->saveRecord($oAccount, $aNew) ? 'ok' : 'busy';
		}) ?? 'busy';
	}

	/**
	 * Waits until the request has lasted as long as a wrong password would:
	 * precheck_delay seconds, and up to half a second more, at random.
	 */
	protected function delayLikeAWrongPassword() : void
	{
		$fDelay = \max(0, \min(10, (int) $this->Config()->Get('plugin', 'precheck_delay', 3)))
			+ \random_int(0, 500) / 1000;
		$fStart = (float) ($_SERVER['REQUEST_TIME_FLOAT'] ?? \microtime(true));
		$fLeft = $fDelay - (\microtime(true) - $fStart);
		0 < $fLeft && \usleep((int) ($fLeft * 1000000));
	}

	/* ---- 2.31.0: a security key before the password ---- */

	/** How long a login challenge lasts, and the size of its parts. */
	const LOGIN_CHALLENGE_TTL = 300;

	/**
	 * The request options of a login with a key, before any password.
	 *
	 * Anyone may ask, for any address: so the answer must not tell which
	 * accounts have a key, and must not write anything.
	 *  - The challenge is stateless: random bytes, an expiry and a MAC (key
	 *    derived from APP_SALT) over them, the address and the browser's
	 *    connection token. Nothing is stored until a key signs it, so a flood
	 *    of requests cannot push the owner's challenges out of the record.
	 *  - An address without a key gets one or two credential ids derived from
	 *    it (always the same ones for the same address, as a real account's
	 *    are), of the length of a security key's. A real account's list keeps
	 *    its own ids and number. Only an authenticator that holds the key can
	 *    tell them apart.
	 */
	public function DoWebAuthnLoginOptions() : array
	{
		$aConf = $this->webAuthnConf();
		$sBinding = $this->loginBinding();
		$sEmail = $this->loginEmail((string) $this->jsonParam('Email', ''));
		if (!$aConf || '' === $sBinding || '' === $sEmail) {
			return $this->jsonResponse(__FUNCTION__, false);
		}
		$aKeys = null;
		try {
			$aRecord = $this->loadRecordFor($sEmail);
			$aKeys = $aRecord && TwoFactorRecord::isOn($aRecord, $this->recordKey())
				? TwoFactorRecord::passkeys($aRecord, $this->recordKey()) : null;
		} catch (\Throwable $oError) {
		}
		if (!$aKeys) {
			$aKeys = static::decoyKeys($sEmail, $this->recordKey());
		}
		$sChallenge = static::loginChallenge($sEmail, $sBinding, \time() + \min($aConf['ttl'], self::LOGIN_CHALLENGE_TTL), $this->recordKey());
		return $this->jsonResponse(__FUNCTION__, static::requestOptions($aKeys, $sChallenge, $aConf));
	}

	/**
	 * The address a login with $sEmail will be about: the core's own
	 * resolution (default domain, the login.credentials of other plugins),
	 * with a password that is never used. Empty when it cannot be had.
	 */
	protected function loginEmail(string $sEmail) : string
	{
		$sEmail = \MailSo\Base\Utils::Trim($sEmail);
		if ('' === $sEmail || \strlen($sEmail) > 320) {
			return '';
		}
		try {
			$oActions = $this->Manager()->Actions();
			$a = \Closure::bind(fn () => $this->resolveLoginCredentials($sEmail, new \SnappyMail\SensitiveString('********')),
				$oActions, \RainLoop\Actions::class)();
			$sEmail = (string) ($a['email'] ?? '');
		} catch (\Throwable $oError) {
			$sEmail = '';
		}
		// Our own login.credentials hook ran too: this was no login.
		$this->bLoggingIn = false;
		return \str_contains($sEmail, '@') ? $sEmail : '';
	}

	/** Decoy credential ids for an address without a key: 1 or 2, 64 bytes, stable. */
	public static function decoyKeys(string $sEmail, string $sKey) : array
	{
		$sSeed = \hash_hmac('sha512', 'decoy|' . \strtolower($sEmail), $sKey, true);
		$aKeys = array();
		for ($i = 0, $n = 1 + (\ord($sSeed[0]) & 1); $i < $n; ++$i) {
			$aKeys[] = array('Id' => TwoFactorWebAuthn::b64u(\hash_hmac('sha512', "decoy|{$i}|" . \strtolower($sEmail), $sKey, true)));
		}
		return $aKeys;
	}

	/** A stateless login challenge: random (16) . expiry (4) . MAC (16), base64url. */
	public static function loginChallenge(string $sEmail, string $sBinding, int $iExpiry, string $sKey) : string
	{
		$sBody = \random_bytes(16) . \pack('N', $iExpiry);
		return TwoFactorWebAuthn::b64u($sBody . static::loginMac($sBody, $sEmail, $sBinding, $sKey));
	}

	protected static function loginMac(string $sBody, string $sEmail, string $sBinding, string $sKey) : string
	{
		return \substr(\hash_hmac('sha256', "login-key|{$sBody}|" . \strtolower($sEmail) . '|' . $sBinding, $sKey, true), 0, 16);
	}

	/** Whether $sChallenge is one of ours, for this address and this browser, and not expired. */
	public static function loginChallengeValid(?string $sChallenge, string $sEmail, string $sBinding, int $iNow, string $sKey) : bool
	{
		if (null === $sChallenge || '' === $sBinding || !\preg_match('/^[A-Za-z0-9_-]{48}$/', $sChallenge)) {
			return false;
		}
		$s = TwoFactorWebAuthn::unb64u($sChallenge);
		if (36 !== \strlen($s)) {
			return false;
		}
		$sBody = \substr($s, 0, 20);
		$iExpiry = \unpack('N', \substr($s, 16, 4))[1];
		return \hash_equals(static::loginMac($sBody, $sEmail, $sBinding, $sKey), \substr($s, 20))
			&& $iExpiry > $iNow && $iExpiry <= $iNow + self::LOGIN_CHALLENGE_TTL + 60;
	}

	/**
	 * A key's assertion before the password: 'ok', or why not. As for a code,
	 * a failure writes nothing and counts nothing; a success is judged again
	 * under the lock, on the record read there, and stored: the key's counter,
	 * its last use, and the challenge spent (kept until it expires).
	 */
	protected function checkAssertionBeforePassword(MainAccount $oAccount, string $sJson) : string
	{
		$aConf = $this->webAuthnConf();
		$sBinding = $this->loginBinding();
		if (!$aConf || '' === $sBinding) {
			return 'unavailable';
		}
		$sKey = $this->recordKey();
		$sEmail = $oAccount->Email();
		$fJudge = function (array $aRecord) use ($sJson, $sEmail, $sBinding, $aConf, $sKey) : array {
			$iNow = \time();
			if (TwoFactorRecord::isLocked($aRecord, $iNow)) {
				return array('locked', null, null);
			}
			try {
				$aCredential = TwoFactorWebAuthn::decodeCredential($sJson);
				$sPresented = TwoFactorWebAuthn::presentedChallenge($aCredential);
				$bOurs = static::loginChallengeValid($sPresented, $sEmail, $sBinding, $iNow, $sKey)
					&& !TwoFactorRecord::challengeSpent($aRecord, (string) $sPresented, $iNow);
				$aKeys = TwoFactorRecord::passkeys($aRecord, $sKey) ?? array();
				$aResult = TwoFactorWebAuthn::assert($aCredential, array(
					'challenge' => $bOurs ? $sPresented : null,
					'userHandle' => (string) ($aRecord['UserHandle'] ?? '')
				) + $aConf, $aKeys);
			} catch (TwoFactorWebAuthnError $oError) {
				return array('webauthn-' . $oError->getMessage(), null, null);
			}
			$aKeys[$aResult['index']]['SignCount'] = $aResult['signCount'];
			$aKeys[$aResult['index']]['LastUsed'] = $iNow;
			$aRecord = TwoFactorRecord::spendChallenge(TwoFactorRecord::withPasskeys($aRecord, $aKeys, $sKey),
				(string) $sPresented, $iNow + self::LOGIN_CHALLENGE_TTL + 60, $iNow);
			return array('ok', TwoFactorRecord::recordSuccess($aRecord, null), $aResult);
		};
		$aRecord = $this->loadRecord($oAccount);
		if (!$aRecord) {
			return 'webauthn-unknown-credential';
		}
		[$sOutcome] = $fJudge($aRecord);
		if ('ok' !== $sOutcome) {
			return $sOutcome;
		}
		return $this->underLock($oAccount, function () use ($oAccount, $fJudge) {
			$aRecord = $this->loadRecord($oAccount);
			if (!$aRecord) {
				return 'webauthn-unknown-credential';
			}
			[$sOutcome, $aNew, $aResult] = $fJudge($aRecord);
			if ('ok' !== $sOutcome) {
				return $sOutcome;
			}
			$aResult['regression'] && $this->Logger()->Write("TFA: signature counter went back for {$oAccount->Email()}, accepted (webauthn_counter_regression = warn)");
			return $this->saveRecord($oAccount, $aNew) ? 'ok' : 'busy';
		}) ?? 'busy';
	}

	/**
	 * The second factor of a login: a code (TOTP or backup), or — 2.28.0 — a
	 * security key's assertion.
	 *
	 * Why a key is a SECOND factor here and never a passwordless login: the
	 * webmail opens the mailbox over IMAP with the person's password. A key
	 * proves who is at the keyboard, it does not give us that password; a
	 * passwordless login would need the server to keep every password (or a
	 * master credential able to open any mailbox), which the owner's rules
	 * refuse (moindre privilège). So the password comes first, then the key.
	 */
	public function DoLogin(MainAccount $oAccount)
	{
		if ('' !== $this->sVerifiedBeforePassword && $this->sVerifiedBeforePassword === $oAccount->Email()) {
			// Already judged, and spent, before the password (2.30.0): judging
			// it again here would call it a replay.
			return;
		}
		$aRecord = $this->loadRecord($oAccount);
		if (!$aRecord || !TwoFactorRecord::isOn($aRecord, $this->recordKey())) {
			return;
		}
		$sAssertion = \trim((string) $this->jsonParam('webauthn_assertion', ''));
		$sCode = \trim((string) $this->jsonParam('totp_code', ''));
		if ('' === $sAssertion && empty($sCode)) {
			$this->Logger()->Write("TFA: Code required for {$oAccount->Email()}");
			// Named, so the login screen asks for the code instead of saying
			// "authentication failed": the password was right, and a person
			// told otherwise resets a good password.
			// Saying so after a correct password is what every 2FA login does.
			// With a security key, the request options follow the name: the
			// challenge is only ever issued once the password was right.
			throw new ClientException(\RainLoop\Notifications::AuthError, null, self::CODE_REQUIRED . $this->loginKeyOptions($oAccount));
		}
		$sOutcome = '' !== $sAssertion
			? $this->checkAssertion($oAccount, $sAssertion, 'login', $this->loginBinding())
			: $this->checkCode($oAccount, $aRecord, $sCode);
		if ('ok' !== $sOutcome) {
			// The failure goes to the auth log as well, which fail2ban reads.
			$this->logAuthFailure($oAccount, $sOutcome);
			throw new ClientException(\RainLoop\Notifications::AuthError);
		}
		$this->Logger()->Write("TFA: Code verified for {$oAccount->Email()}");
	}

	public function DoGetTwoFactorInfo() : array
	{
		$oAccount = $this->getMainAccountFromToken();

		if (!$this->TwoFactorAuthProvider($oAccount)) {
			return $this->jsonResponse(__FUNCTION__, false);
		}

		return $this->jsonResponse(__FUNCTION__, $this->getTwoFactorInfo($oAccount, true));
	}

	public function DoCreateTwoFactorSecret() : array
	{
		$oAccount = $this->getMainAccountFromToken();

		if (!$this->TwoFactorAuthProvider($oAccount)) {
			return $this->jsonResponse(__FUNCTION__, false);
		}
		// Re-enrolling over an active second factor would remove it without a
		// code: clearing it (which asks for one) has to come first.
		$aExisting = $this->loadRecord($oAccount);
		if ($aExisting && !empty($aExisting['Enable'])) {
			return $this->jsonResponse(__FUNCTION__, false);
		}
		// A security key is already on (2.28.0): adding a TOTP is adding a
		// second factor, and a stolen session must not be able to.
		if ($aExisting && TwoFactorRecord::isOn($aExisting, $this->recordKey())) {
			if ('ok' !== $this->proveSecondFactor($oAccount)) {
				return $this->jsonResponse(__FUNCTION__, false);
			}
			$aExisting = $this->loadRecord($oAccount) ?? $aExisting;
		}

		$sSecret = $this->TwoFactorAuthProvider($oAccount)->CreateSecret();
		$aCodes = TwoFactorRecord::newBackupCodes();
		$aNew = TwoFactorRecord::create($oAccount->Email(), $sSecret, $aCodes, $this->recordKey());
		// What the TOTP does not own stays: the keys, their user handle, the
		// pending challenges, and the lockout — a new secret is no way out of it.
		foreach (array('PasskeysBox', 'UserHandle', 'Challenges', 'Spent', 'Failures', 'LockedUntil') as $sKey) {
			$aExisting && isset($aExisting[$sKey]) && $aNew[$sKey] = $aExisting[$sKey];
		}
		$this->saveRecord($oAccount, $aNew);

		// The only time the backup codes are ever shown: only their hashes are kept.
		return $this->jsonResponse(__FUNCTION__, array(
			'User' => $oAccount->Email(),
			'IsSet' => true,
			'Enable' => false,
			'Tested' => false,
			'Secret' => $sSecret,
			'QRCode' => $this->getQRCode($oAccount, $sSecret),
			'BackupCodes' => \implode(' ', $aCodes)
		));
	}

	private function getQRCode(MainAccount $oAccount, string $secret) : string
	{
		$issuer = \trim((string) $this->Config()->Get('plugin', 'otp_issuer', ''))
			?: \trim((string) \RainLoop\Api::Config()->Get('webmail', 'title', ''));
		$uri = TwoFactorRecord::uri($oAccount->Email(), $secret, $issuer, $this->otpImageUrl());
		$QR = \SnappyMail\QRCode::getMinimumQRCode(
			$uri,
			\SnappyMail\QRCode::ERROR_CORRECT_LEVEL_M
		);
		return TwoFactorRecord::svg($QR->getModuleCount(), fn (int $r, int $c) => $QR->isDark($r, $c));
	}

	/**
	 * The icon an authenticator shows next to the account, or '' when unset.
	 *
	 * `image` is in no standard. FreeOTP, FreeOTP+ and 2FAS fetch it at
	 * enrollment time and draw the logo; Google Authenticator, Microsoft
	 * Authenticator and Aegis ignore it and show a letter. It is therefore
	 * optional end to end, and an empty setting leaves the URI byte for byte
	 * as it was.
	 *
	 * Only https:// is accepted, and not out of pedantry: the phone — not the
	 * browser — fetches this URL, over whatever network it happens to be on.
	 * In the clear, anyone on that path learns that an enrollment is taking
	 * place and for which service. The secret does not leak; the event does.
	 *
	 * A configured address that is refused is written to the log rather than
	 * dropped in silence: a missing icon is otherwise indistinguishable from
	 * an authenticator that cannot show one, and the fault would be looked for
	 * on the wrong side.
	 */
	private function otpImageUrl() : string
	{
		$image = \trim((string) $this->Config()->Get('plugin', 'otp_image_url', ''));
		if ('' === $image) {
			return '';
		}
		if (!\str_starts_with($image, 'https://') || !\parse_url($image, PHP_URL_HOST)) {
			$this->logWrite('otp_image_url must be an https:// address, ignored: ' . $image,
				\LOG_WARNING);
			return '';
		}
		return $image;
	}

	/**
	 * The secret, again — only while enrolling. Once the second factor is on,
	 * showing it would hand it to whoever holds the session: a stolen session
	 * must not become a stolen second factor.
	 */
	public function DoShowTwoFactorSecret() : array
	{
		$oAccount = $this->getMainAccountFromToken();
		$aRecord = $this->loadRecord($oAccount);
		if (!$this->TwoFactorAuthProvider($oAccount) || !$aRecord || !empty($aRecord['Enable']) || empty($aRecord['SecretBox'])) {
			return $this->jsonResponse(__FUNCTION__, false);
		}
		$sSecret = (string) TwoFactorRecord::unseal((string) $aRecord['SecretBox'], $this->recordKey());
		return $this->jsonResponse(__FUNCTION__, array(
			'User' => $oAccount->Email(),
			'Secret' => $sSecret,
			'QRCode' => '' === $sSecret ? '' : $this->getQRCode($oAccount, $sSecret)
		));
	}

	/**
	 * On: only once a code from the phone has been accepted (`Tested`) —
	 * otherwise a mistyped enrolment locks the person out at the next login.
	 * Off: a current code is required. Without it, a stolen session would
	 * switch the second factor off and keep the account.
	 */
	public function DoEnableTwoFactor() : array
	{
		$oAccount = $this->getMainAccountFromToken();
		$aRecord = $this->loadRecord($oAccount);
		if (!$this->TwoFactorAuthProvider($oAccount) || !$aRecord || empty($aRecord['SecretBox'])) {
			return $this->jsonResponse(__FUNCTION__, false);
		}

		$bEnable = '1' === \trim($this->jsonParam('Enable', '0'));
		if ($bEnable && empty($aRecord['Tested'])) {
			return $this->jsonResponse(__FUNCTION__, false);
		}
		// A code, or a security key (2.28.0).
		if (!$bEnable && !empty($aRecord['Enable'])
			&& 'ok' !== $this->proveSecondFactor($oAccount)) {
			return $this->jsonResponse(__FUNCTION__, false);
		}

		// checkCode() may have written the record (time step, failures): build on that one.
		$aRecord = $this->loadRecord($oAccount) ?? $aRecord;
		// On or off for the whole account: a security key may keep it on (2.28.0).
		$bWasOn = TwoFactorRecord::isOn($aRecord, $this->recordKey());
		$aNext = $aRecord;
		$aNext['Enable'] = $bEnable;
		$bNowOn = TwoFactorRecord::isOn($aNext, $this->recordKey());

		$oActions = $this->Manager()->Actions();
		if ($oActions->HasActionParam('EnableTwoFactor')) {
			$sValue = $oActions->GetActionParam('EnableTwoFactor', '');
			$oActions->SettingsProvider()->Load($oAccount)->SetConf('EnableTwoFactor', !empty($sValue));
		}

		// Required before the second factor is on, not after (S-09): when the
		// store is there and cannot be written, enabling is refused rather than
		// left on while the main password still opens IMAP and SMTP.
		$bTurnsOn = !$bWasOn && $bNowOn;
		if ($bTurnsOn && !$this->appPasswordsRequired($oAccount, true)) {
			return $this->jsonResponse(__FUNCTION__, false);
		}

		$bSaved = $this->saveRecord($oAccount, $aNext);
		if (!$bSaved) {
			$bTurnsOn && $this->appPasswordsRequired($oAccount, false);
		} else if ($bTurnsOn) {
			$this->forgetRememberedDevices($oAccount);
		} else if ($bWasOn && !$bNowOn) {
			$this->appPasswordsRequired($oAccount, false);
		}
		return $this->jsonResponse(__FUNCTION__, $bSaved);
	}

	/** The test of the phone: counted, rate-limited and replay-guarded like a login. */
	public function DoVerifyTwoFactorCode() : array
	{
		$oAccount = $this->getMainAccountFromToken();
		$aRecord = $this->loadRecord($oAccount);
		if (!$this->TwoFactorAuthProvider($oAccount) || !$aRecord || empty($aRecord['SecretBox'])) {
			return $this->jsonResponse(__FUNCTION__, false);
		}
		$bOk = 'ok' === $this->checkCode($oAccount, $aRecord, (string) $this->jsonParam('Code', ''), true);
		return $this->jsonResponse(__FUNCTION__, $bOk);
	}

	/** Removing the second factor — TOTP and security keys — asks for a current one, once it is on. */
	public function DoClearTwoFactorInfo() : array
	{
		$oAccount = $this->getMainAccountFromToken();
		$aRecord = $this->loadRecord($oAccount);
		if (!$this->TwoFactorAuthProvider($oAccount)) {
			return $this->jsonResponse(__FUNCTION__, false);
		}
		if ($aRecord && TwoFactorRecord::isOn($aRecord, $this->recordKey())
			&& 'ok' !== $this->proveSecondFactor($oAccount)) {
			return $this->jsonResponse(__FUNCTION__, false);
		}

		$this->StorageProvider()->Clear($oAccount,
			\RainLoop\Providers\Storage\Enumerations\StorageType::CONFIG,
			'two_factor'
		);
		$this->Logger()->Write("TFA: Second factor removed for {$oAccount->Email()}");
		$this->appPasswordsRequired($oAccount, false);

		return $this->jsonResponse(__FUNCTION__, $this->getTwoFactorInfo($oAccount, true));
	}

	/**
	 * One line in the auth log, in the format of the core's own failures.
	 *
	 * ⚠️ 2.20.0 called `Actions::LoggerAuthHelper()`, which is **protected**:
	 * every wrong code at login ended in a PHP error instead of a refusal, and
	 * nothing ever reached the file fail2ban reads. The line is written here,
	 * where the core writes its own — `[logs] path` and
	 * `auth_logging_filename` — and only when `auth_logging` is on.
	 */
	protected function logAuthFailure(MainAccount $oAccount, string $sOutcome) : void
	{
		try {
			$oConfig = \RainLoop\Api::Config();
			if (!$oConfig->Get('logs', 'auth_logging', false)) {
				return;
			}
			$oNow = new \DateTime('now', new \DateTimeZone((string) $oConfig->Get('logs', 'time_zone', 'UTC') ?: 'UTC'));
			$sName = (string) \preg_replace_callback('/\{date:([^}]+)\}/', fn ($m) => $oNow->format($m[1]),
				\trim((string) $oConfig->Get('logs', 'auth_logging_filename', '')));
			$sName = (string) \preg_replace('/[^a-zA-Z0-9@_+=\-\.\/!()\[\]]/', '', \str_replace('..', '.', $sName));
			if ('' === $sName) {
				return;
			}
			$sPath = (\trim((string) $oConfig->Get('logs', 'path', '')) ?: \APP_PRIVATE_DATA . 'logs') . '/' . $sName;
			\is_dir(\dirname($sPath)) || \mkdir(\dirname($sPath), 0755, true);
			$sIp = $this->Manager()->Actions()->Http()->GetClientIp((bool) $oConfig->Get('labs', 'http_client_ip_check_proxy', false));
			$sUser = (string) \preg_replace('/[^\w@.+-]/', '', $oAccount->Email());
			\file_put_contents($sPath, '[' . $oNow->format('Y-m-d H:i:s') . "] Auth failed: ip={$sIp} user={$sUser} 2fa={$sOutcome}\n",
				FILE_APPEND | LOCK_EX);
		} catch (\Throwable $oError) {
			// A log that cannot be written must not turn a refusal into an error.
		}
	}

	/**
	 * The "remember me" tokens of the account, all of them (S-21, plugin side).
	 *
	 * The core rebuilds a remembered session from its cookie without running
	 * login.success, so a device remembered before the second factor existed
	 * — or by whoever had the password then — was never asked for a code, and
	 * the token renews itself for 30 days at each use. Turning the second
	 * factor on is the moment those devices stop being trusted. A device
	 * remembered afterwards went through DoLogin, code included.
	 */
	protected function forgetRememberedDevices(MainAccount $oAccount) : void
	{
		$iType = \RainLoop\Providers\Storage\Enumerations\StorageType::SIGN_ME;
		$sDir = (string) $this->StorageProvider()->GenerateFilePath($oAccount, $iType);
		if ('' === $sDir) {
			$this->Logger()->Write("TFA: remembered devices of {$oAccount->Email()} could not be listed");
			return;
		}
		$iGone = 0;
		foreach (\glob(\rtrim($sDir, '/') . '/*') ?: array() as $sFile) {
			\is_file($sFile) && !\is_link($sFile) && \unlink($sFile) && ++$iGone;
		}
		$this->Logger()->Write("TFA: {$iGone} remembered device(s) forgotten for {$oAccount->Email()}");
	}

	/**
	 * The SnappyMail-mots-de-passe-appli configuration when it applies to this
	 * account — store loaded, configuration readable, domain served — else null.
	 * Only then is "mail apps need an app password" true.
	 */
	protected function appPasswordsConf(MainAccount $oAccount) : ?array
	{
		if (!\class_exists('\\Convergent\\Appli\\Appli')) {
			return null;
		}
		$aConf = \Convergent\Appli\Appli::conf((string) $this->Config()->Get('plugin', 'app_passwords_conf', '/etc/sky-appli.conf'));
		return $aConf && null !== \Convergent\Appli\Appli::compte($oAccount->Email(), (array) $aConf['domaines'])
			? $aConf : null;
	}

	/**
	 * Mail apps (IMAP, SMTP, DAV) take app passwords only while the second
	 * factor is on — the SnappyMail-mots-de-passe-appli store, when it is
	 * installed (its plugin loads the shared code). Without it the second
	 * factor guards the webmail alone, and the settings screen no longer says
	 * otherwise (S-09).
	 *
	 * False only when the store applies and could not be written: the caller
	 * refuses to enable. True when it was written, or when it does not apply.
	 */
	protected function appPasswordsRequired(MainAccount $oAccount, bool $bRequired) : bool
	{
		$aConf = $this->appPasswordsConf($oAccount);
		if (null === $aConf) {
			return true;
		}
		if (\Convergent\Appli\Appli::poserExigence($aConf, $oAccount->Email(), $bRequired)) {
			return true;
		}
		$this->Logger()->Write('TFA: could not ' . ($bRequired ? 'require' : 'release') . " app passwords for {$oAccount->Email()}");
		return false;
	}

	/* ---- security keys and passkeys (WebAuthn, 2.28.0) ---- */

	/**
	 * The WebAuthn settings, or null when security keys are off — switched
	 * off, or with no usable origin. Nothing here comes from the request:
	 * the origins and the relying party are the administrator's.
	 */
	protected function webAuthnConf() : ?array
	{
		if (!$this->Config()->Get('plugin', 'webauthn_enabled', false)) {
			return null;
		}
		$aConf = static::parseWebAuthnConf((string) $this->Config()->Get('plugin', 'webauthn_origins', ''),
			(string) $this->Config()->Get('plugin', 'webauthn_rp_id', ''));
		if (!$aConf) {
			$this->logWrite('webauthn_enabled is on, but no origin matches the relying party ID: security keys stay off', \LOG_WARNING);
			return null;
		}
		$mCounter = $this->Config()->Get('plugin', 'webauthn_counter_regression', 'refuse');
		\is_array($mCounter) && $mCounter = \reset($mCounter);
		return $aConf + array(
			'name' => \trim((string) $this->Config()->Get('plugin', 'otp_issuer', ''))
				?: \trim((string) \RainLoop\Api::Config()->Get('webmail', 'title', '')) ?: $aConf['rpId'],
			'requireUV' => (bool) $this->Config()->Get('plugin', 'webauthn_require_uv', false),
			'max' => \max(1, \min(50, (int) $this->Config()->Get('plugin', 'webauthn_max_passkeys', 10))),
			'ttl' => \max(30, \min(3600, (int) $this->Config()->Get('plugin', 'webauthn_challenge_ttl', 300))),
			'counter' => 'warn' === $mCounter ? 'warn' : 'refuse'
		);
	}

	/**
	 * The origins (as browsers serialise them: scheme, host, port unless the
	 * default) and the relying party ID. The rpId must be a domain — WebAuthn
	 * forbids an IP address — and every origin kept must be that domain or
	 * one of its subdomains; the others are dropped. Null: nothing usable.
	 */
	public static function parseWebAuthnConf(string $sOrigins, string $sRpId) : ?array
	{
		$aOrigins = array();
		foreach (\preg_split('/[\s,;]+/', \strtolower($sOrigins), -1, PREG_SPLIT_NO_EMPTY) as $sOrigin) {
			if (!\preg_match('#^(https?)://([a-z0-9.-]+)(?::(\d{1,5}))?/?$#', $sOrigin, $m)) {
				continue;
			}
			$sPort = $m[3] ?? '';
			if (('https' === $m[1] && '443' === $sPort) || ('http' === $m[1] && '80' === $sPort)) {
				$sPort = '';
			}
			$aOrigins["{$m[1]}://{$m[2]}" . ('' === $sPort ? '' : ":{$sPort}")] = $m[2];
		}
		if (!$aOrigins) {
			return null;
		}
		$sRpId = \strtolower(\trim($sRpId)) ?: \reset($aOrigins);
		if (!\preg_match('/^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/', $sRpId)
		 || \preg_match('/^[0-9.]+$/', $sRpId)) {
			return null;
		}
		$aKept = array();
		foreach ($aOrigins as $sOrigin => $sHost) {
			if ($sHost === $sRpId || \str_ends_with($sHost, '.' . $sRpId)) {
				$aKept[] = $sOrigin;
			}
		}
		return $aKept ? array('origins' => $aKept, 'rpId' => $sRpId) : null;
	}

	/** A short stable reference to a key, for the settings screen: not its credential id. */
	public static function passkeyRef(string $sId) : string
	{
		return \substr(\hash('sha256', 'ref:' . $sId), 0, 16);
	}

	/** The browser at the login screen: its connection cookie (no session yet). */
	protected function loginBinding() : string
	{
		return (string) \SnappyMail\Cookies::get(\RainLoop\Utils::CONNECTION_TOKEN);
	}

	/** The browser of a logged-in session. */
	protected function sessionBinding() : string
	{
		return (string) \RainLoop\Utils::GetConnectionToken();
	}

	/** Runs $f under the account's lock; null when the lock could not be had. */
	protected function underLock(MainAccount $oAccount, callable $f)
	{
		$rLock = $this->lockRecord($oAccount);
		if (!$rLock) {
			$this->Logger()->Write("TFA: busy for {$oAccount->Email()}");
			return null;
		}
		try {
			return $f();
		} finally {
			\flock($rLock, LOCK_UN);
			\fclose($rLock);
		}
	}

	/**
	 * A new challenge for this account, stored under the lock: the record
	 * written, and the challenge — or null (no record and none to create,
	 * busy, or nothing to bind it to).
	 */
	protected function issueChallenge(MainAccount $oAccount, string $sPurpose, string $sBinding, array $aConf, bool $bCreate = false) : ?array
	{
		if ('' === $sBinding) {
			return null;
		}
		return $this->underLock($oAccount, function () use ($oAccount, $sPurpose, $sBinding, $aConf, $bCreate) {
			$aRecord = $this->loadRecord($oAccount) ?? ($bCreate ? TwoFactorRecord::blank($oAccount->Email()) : null);
			if (!$aRecord) {
				return null;
			}
			if (empty($aRecord['UserHandle'])) {
				// Random, never the address: the authenticator may show or keep it.
				$aRecord['UserHandle'] = TwoFactorWebAuthn::b64u(\random_bytes(16));
			}
			$sChallenge = TwoFactorWebAuthn::b64u(\random_bytes(32));
			$aRecord = TwoFactorRecord::addChallenge($aRecord, $sChallenge, $sPurpose, $sBinding, \time(), $aConf['ttl'], $this->recordKey());
			return $this->saveRecord($oAccount, $aRecord) ? array($aRecord, $sChallenge) : null;
		});
	}

	/** PublicKeyCredentialRequestOptions, as JSON-friendly values (base64url). */
	protected static function requestOptions(array $aKeys, string $sChallenge, array $aConf) : array
	{
		return array(
			'challenge' => $sChallenge,
			'rpId' => $aConf['rpId'],
			'timeout' => $aConf['ttl'] * 1000,
			'userVerification' => $aConf['requireUV'] ? 'required' : 'discouraged',
			'allowCredentials' => \array_map(fn ($k) => array('type' => 'public-key', 'id' => (string) $k['Id']), \array_values($aKeys))
		);
	}

	/**
	 * After a right password and no second factor: the request options of
	 * the account's keys, appended to the name of the refusal — or '' when
	 * the account has none, or keys are off.
	 */
	protected function loginKeyOptions(MainAccount $oAccount) : string
	{
		$aConf = $this->webAuthnConf();
		$aRecord = $this->loadRecord($oAccount);
		$aKeys = $aRecord ? TwoFactorRecord::passkeys($aRecord, $this->recordKey()) : null;
		if (!$aConf || !$aKeys) {
			return '';
		}
		$a = $this->issueChallenge($oAccount, 'login', $this->loginBinding(), $aConf);
		return $a ? ':' . TwoFactorWebAuthn::b64u(\json_encode(static::requestOptions($aKeys, $a[1], $aConf))) : '';
	}

	/**
	 * One assertion, checked and recorded like a code: under the lock, the
	 * challenge spent whatever the outcome, failures counted toward the same
	 * lockout, the key's counter and last use stored on success.
	 *
	 * @return string 'ok', 'locked', 'busy', 'unavailable' or 'webauthn-<reason>'
	 */
	protected function checkAssertion(MainAccount $oAccount, string $sJson, string $sPurpose, string $sBinding) : string
	{
		$aConf = $this->webAuthnConf();
		if (!$aConf || '' === $sBinding) {
			$this->Logger()->Write("TFA: security key unavailable for {$oAccount->Email()}");
			return 'unavailable';
		}
		$sOutcome = $this->underLock($oAccount, function () use ($oAccount, $sJson, $sPurpose, $sBinding, $aConf) {
			$aRecord = $this->loadRecord($oAccount);
			if (!$aRecord) {
				return 'webauthn-unknown-credential';
			}
			$iNow = \time();
			if (TwoFactorRecord::isLocked($aRecord, $iNow)) {
				return 'locked';
			}
			$sKey = $this->recordKey();
			try {
				$aCredential = TwoFactorWebAuthn::decodeCredential($sJson);
				$sPresented = TwoFactorWebAuthn::presentedChallenge($aCredential);
				[$bUsable, $aRecord] = TwoFactorRecord::takeChallenge($aRecord, $sPresented, $sPurpose, $sBinding, $iNow, $sKey);
				$aKeys = TwoFactorRecord::passkeys($aRecord, $sKey) ?? array();
				$aResult = TwoFactorWebAuthn::assert($aCredential, array(
					'challenge' => $bUsable ? $sPresented : null,
					'userHandle' => (string) ($aRecord['UserHandle'] ?? '')
				) + $aConf, $aKeys);
			} catch (TwoFactorWebAuthnError $oError) {
				$this->saveRecord($oAccount, TwoFactorRecord::recordFailure($aRecord, $iNow));
				return 'webauthn-' . $oError->getMessage();
			}
			if ($aResult['regression']) {
				$this->Logger()->Write("TFA: signature counter went back for {$oAccount->Email()}, accepted (webauthn_counter_regression = warn)");
			}
			$aKeys[$aResult['index']]['SignCount'] = $aResult['signCount'];
			$aKeys[$aResult['index']]['LastUsed'] = $iNow;
			$aRecord = TwoFactorRecord::recordSuccess(TwoFactorRecord::withPasskeys($aRecord, $aKeys, $sKey), null);
			return $this->saveRecord($oAccount, $aRecord) ? 'ok' : 'busy';
		}) ?? 'busy';
		$this->Logger()->Write("TFA: {$sOutcome} for {$oAccount->Email()} (security key, {$sPurpose})");
		return $sOutcome;
	}

	/**
	 * A current second factor, for what weakens it (switching off, removing,
	 * adding another): a security key's assertion when one is sent, else a
	 * code. Counted and locked like a login.
	 */
	protected function proveSecondFactor(MainAccount $oAccount) : string
	{
		$sAssertion = \trim((string) $this->jsonParam('Assertion', ''));
		return '' !== $sAssertion
			? $this->checkAssertion($oAccount, $sAssertion, 'reauth', $this->sessionBinding())
			: $this->checkCode($oAccount, array(), (string) $this->jsonParam('Code', ''));
	}

	/** A key's name as the person typed it: no control or bidi-override characters, 64 at most. */
	public static function passkeyName(string $sName) : string
	{
		$sName = (string) \preg_replace('/[\p{C}]+/u', '', \mb_convert_encoding($sName, 'UTF-8', 'UTF-8'));
		return \mb_substr(\trim((string) \preg_replace('/\s+/u', ' ', $sName)), 0, 64);
	}

	/** PublicKeyCredentialCreationOptions for a new key of this account. */
	public function DoWebAuthnCreateOptions() : array
	{
		$oAccount = $this->getMainAccountFromToken();
		$aConf = $this->webAuthnConf();
		if (!$aConf) {
			return $this->jsonResponse(__FUNCTION__, false);
		}
		$aRecord = $this->loadRecord($oAccount);
		$aKeys = $aRecord ? TwoFactorRecord::passkeys($aRecord, $this->recordKey()) : array();
		if (null === $aKeys || \count($aKeys) >= $aConf['max']) {
			return $this->jsonResponse(__FUNCTION__, false);
		}
		$a = $this->issueChallenge($oAccount, 'register', $this->sessionBinding(), $aConf, true);
		if (!$a) {
			return $this->jsonResponse(__FUNCTION__, false);
		}
		return $this->jsonResponse(__FUNCTION__, array(
			'rp' => array('id' => $aConf['rpId'], 'name' => $aConf['name']),
			'user' => array('id' => $a[0]['UserHandle'], 'name' => $oAccount->Email(), 'displayName' => $oAccount->Email()),
			'challenge' => $a[1],
			'pubKeyCredParams' => \array_map(fn ($i) => array('type' => 'public-key', 'alg' => $i), TwoFactorWebAuthn::algorithms()),
			'timeout' => $aConf['ttl'] * 1000,
			'excludeCredentials' => \array_map(fn ($k) => array('type' => 'public-key', 'id' => (string) $k['Id']), $aKeys),
			'authenticatorSelection' => array(
				'userVerification' => $aConf['requireUV'] ? 'required' : 'discouraged',
				// A second factor needs no key stored on the authenticator:
				// a security key's few resident slots are left alone.
				'residentKey' => 'discouraged',
				'requireResidentKey' => false
			),
			'attestation' => 'none'
		));
	}

	/**
	 * Registers a key. When a second factor is already on, a current one is
	 * required first (code or key): a stolen session must not add its own.
	 * The first factor of an account also gets backup codes, shown once.
	 */
	public function DoWebAuthnRegister() : array
	{
		$oAccount = $this->getMainAccountFromToken();
		$aConf = $this->webAuthnConf();
		$sBinding = $this->sessionBinding();
		$aRecord = $this->loadRecord($oAccount);
		if (!$aConf || '' === $sBinding || !$aRecord) {
			return $this->jsonResponse(__FUNCTION__, false);
		}
		$sKey = $this->recordKey();
		$bWasOn = TwoFactorRecord::isOn($aRecord, $sKey);
		if ($bWasOn && 'ok' !== $this->proveSecondFactor($oAccount)) {
			return $this->jsonResponse(__FUNCTION__, false);
		}
		$sName = static::passkeyName((string) $this->jsonParam('Name', ''));
		$aCodes = array();
		$sOutcome = $this->underLock($oAccount, function () use ($oAccount, $aConf, $sBinding, $sKey, $bWasOn, $sName, &$aCodes) {
			$aRecord = $this->loadRecord($oAccount);
			$aKeys = $aRecord ? TwoFactorRecord::passkeys($aRecord, $sKey) : null;
			if (null === $aKeys) {
				return 'unreadable';
			}
			$iNow = \time();
			try {
				$aCredential = TwoFactorWebAuthn::decodeCredential((string) $this->jsonParam('Credential', ''));
				$sPresented = TwoFactorWebAuthn::presentedChallenge($aCredential);
				[$bUsable, $aRecord] = TwoFactorRecord::takeChallenge($aRecord, $sPresented, 'register', $sBinding, $iNow, $sKey);
				$aNew = TwoFactorWebAuthn::register($aCredential, array('challenge' => $bUsable ? $sPresented : null) + $aConf);
			} catch (TwoFactorWebAuthnError $oError) {
				$this->saveRecord($oAccount, $aRecord);
				return 'webauthn-' . $oError->getMessage();
			}
			if (\count($aKeys) >= $aConf['max']) {
				$this->saveRecord($oAccount, $aRecord);
				return 'max';
			}
			foreach ($aKeys as $k) {
				if (\hash_equals((string) ($k['Id'] ?? ''), $aNew['Id'])) {
					$this->saveRecord($oAccount, $aRecord);
					return 'duplicate';
				}
			}
			$aKeys[] = $aNew + array(
				'Name' => '' === $sName ? 'Key ' . (\count($aKeys) + 1) : $sName,
				'Created' => $iNow,
				'LastUsed' => 0
			);
			if (!$bWasOn) {
				// 2.32.0: the first factor of an account is a key and nothing else.
				// It is put aside with fresh backup codes and becomes active only
				// when the person retypes one of them (DoConfirmBackupCodes): a key
				// that cannot be used on another device must not be the only way in
				// unless the way out has been kept. Until then nothing changes for
				// the login, and a person who stops here is not locked out.
				$aCodes = TwoFactorRecord::newBackupCodes();
				return $this->saveRecord($oAccount, TwoFactorRecord::startPending($aRecord, $aCodes, $aKeys[\count($aKeys) - 1],
					$sBinding, $iNow, $sKey)) ? 'pending' : 'busy';
			}
			// Required before the second factor is on (S-09), as for the TOTP.
			if (!$bWasOn && !$this->appPasswordsRequired($oAccount, true)) {
				$this->saveRecord($oAccount, $aRecord);
				return 'app-passwords';
			}
			$aNext = TwoFactorRecord::withPasskeys($aRecord, $aKeys, $sKey);
			if (empty($aNext['BackupHashes'])) {
				// Without them, a lost key is a lost mailbox.
				$aCodes = TwoFactorRecord::newBackupCodes();
				$aNext['BackupHashes'] = \array_map(fn ($s) => TwoFactorRecord::hashCode($s, $sKey), $aCodes);
			}
			if (!$this->saveRecord($oAccount, $aNext)) {
				$bWasOn || $this->appPasswordsRequired($oAccount, false);
				$aCodes = array();
				return 'busy';
			}
			return 'ok';
		}) ?? 'busy';
		$this->Logger()->Write("TFA: security key registration {$sOutcome} for {$oAccount->Email()}");
		if ('ok' !== $sOutcome && 'pending' !== $sOutcome) {
			return $this->jsonResponse(__FUNCTION__, false);
		}
		'ok' === $sOutcome && !$bWasOn && $this->forgetRememberedDevices($oAccount);
		$aInfo = $this->getTwoFactorInfo($oAccount, true);
		// The only time these backup codes are shown.
		$aCodes && $aInfo['BackupCodes'] = \implode(' ', $aCodes);
		return $this->jsonResponse(__FUNCTION__, $aInfo);
	}

	/**
	 * The proof that the backup codes are kept (2.32.0): one of them, retyped
	 * (the server says which, by rank). Right: the codes — and the key put
	 * aside with them, if any — take effect. The session is enough, because the
	 * pending state weakens nothing and the codes were shown to this browser
	 * only (bound to its connection token).
	 */
	public function DoConfirmBackupCodes() : array
	{
		$oAccount = $this->getMainAccountFromToken();
		$sBinding = $this->sessionBinding();
		$sKey = $this->recordKey();
		$bTurnsOn = false;
		$sOutcome = $this->underLock($oAccount, function () use ($oAccount, $sBinding, $sKey, &$bTurnsOn) {
			$aRecord = $this->loadRecord($oAccount);
			if (!$aRecord) {
				return 'none';
			}
			$mCode = $this->jsonParam('Code', '');
			// Anything but a string is a wrong answer, not a notice.
			[$sOutcome, $aNext] = TwoFactorRecord::confirmPending($aRecord, \is_string($mCode) ? $mCode : '', $sBinding, \time(), $sKey);
			if ('ok' === $sOutcome) {
				$bTurnsOn = !TwoFactorRecord::isOn($aRecord, $sKey) && TwoFactorRecord::isOn($aNext, $sKey);
				// Required before the second factor is on (S-09), as for the TOTP.
				if ($bTurnsOn && !$this->appPasswordsRequired($oAccount, true)) {
					return 'app-passwords';
				}
			}
			if ('binding' !== $sOutcome && !$this->saveRecord($oAccount, $aNext)) {
				$bTurnsOn && $this->appPasswordsRequired($oAccount, false);
				return 'busy';
			}
			return $sOutcome;
		}) ?? 'busy';
		$this->Logger()->Write("TFA: backup codes confirmation {$sOutcome} for {$oAccount->Email()}");
		if ('ok' !== $sOutcome) {
			return $this->jsonResponse(__FUNCTION__, false);
		}
		$bTurnsOn && $this->forgetRememberedDevices($oAccount);
		return $this->jsonResponse(__FUNCTION__, $this->getTwoFactorInfo($oAccount, true));
	}

	/** Drops the codes (and the key) put aside, to start again: nothing active is touched. */
	public function DoCancelPendingCodes() : array
	{
		$oAccount = $this->getMainAccountFromToken();
		$bDone = $this->underLock($oAccount, function () use ($oAccount) {
			$aRecord = $this->loadRecord($oAccount);
			return !$aRecord || !isset($aRecord['Pending']) || $this->saveRecord($oAccount, TwoFactorRecord::dropPending($aRecord));
		});
		return $this->jsonResponse(__FUNCTION__, $bDone ? $this->getTwoFactorInfo($oAccount, true) : false);
	}

	/**
	 * New backup codes (2.32.0). Asks for a current second factor, code or key,
	 * like everything that touches the second factor. The old codes stay valid
	 * until the new ones are confirmed by retyping one: shown and never kept,
	 * they would otherwise replace working codes with lost ones.
	 */
	public function DoRegenerateBackupCodes() : array
	{
		$oAccount = $this->getMainAccountFromToken();
		$sBinding = $this->sessionBinding();
		$aRecord = $this->loadRecord($oAccount);
		$sKey = $this->recordKey();
		if (!$aRecord || '' === $sBinding || !TwoFactorRecord::isOn($aRecord, $sKey)
			|| 'ok' !== $this->proveSecondFactor($oAccount)) {
			return $this->jsonResponse(__FUNCTION__, false);
		}
		$aCodes = TwoFactorRecord::newBackupCodes();
		$bSaved = $this->underLock($oAccount, function () use ($oAccount, $aCodes, $sBinding, $sKey) {
			$aRecord = $this->loadRecord($oAccount);
			return $aRecord && $this->saveRecord($oAccount, TwoFactorRecord::startPending($aRecord, $aCodes, null, $sBinding, \time(), $sKey));
		});
		$this->Logger()->Write('TFA: new backup codes ' . ($bSaved ? 'issued, to be confirmed' : 'not issued') . " for {$oAccount->Email()}");
		if (!$bSaved) {
			return $this->jsonResponse(__FUNCTION__, false);
		}
		$aInfo = $this->getTwoFactorInfo($oAccount, true);
		// The only time these are shown.
		$aInfo['BackupCodes'] = \implode(' ', $aCodes);
		return $this->jsonResponse(__FUNCTION__, $aInfo);
	}

	/** Request options to confirm, with a key, what weakens the second factor. */
	public function DoWebAuthnAssertOptions() : array
	{
		$oAccount = $this->getMainAccountFromToken();
		$aConf = $this->webAuthnConf();
		$aRecord = $this->loadRecord($oAccount);
		$aKeys = $aRecord ? TwoFactorRecord::passkeys($aRecord, $this->recordKey()) : null;
		$a = $aConf && $aKeys ? $this->issueChallenge($oAccount, 'reauth', $this->sessionBinding(), $aConf) : null;
		return $this->jsonResponse(__FUNCTION__, $a ? static::requestOptions($aKeys, $a[1], $aConf) : false);
	}

	/** Renames a key: the session is enough, nothing is weakened. */
	public function DoWebAuthnRename() : array
	{
		$oAccount = $this->getMainAccountFromToken();
		$sRef = (string) $this->jsonParam('Ref', '');
		$sName = static::passkeyName((string) $this->jsonParam('Name', ''));
		if ('' === $sName) {
			return $this->jsonResponse(__FUNCTION__, false);
		}
		$bDone = $this->underLock($oAccount, fn () => $this->editPasskeys($oAccount, $sRef, function (array $aKeys, int $i) use ($sName) {
			$aKeys[$i]['Name'] = $sName;
			return $aKeys;
		}));
		return $this->jsonResponse(__FUNCTION__, $bDone ? $this->getTwoFactorInfo($oAccount, true) : false);
	}

	/** Removes a key, with a current second factor — this one included. */
	public function DoWebAuthnRemove() : array
	{
		$oAccount = $this->getMainAccountFromToken();
		$sRef = (string) $this->jsonParam('Ref', '');
		$aRecord = $this->loadRecord($oAccount);
		if (!$aRecord || 'ok' !== $this->proveSecondFactor($oAccount)) {
			return $this->jsonResponse(__FUNCTION__, false);
		}
		$bDone = $this->underLock($oAccount, fn () => $this->editPasskeys($oAccount, $sRef, function (array $aKeys, int $i) {
			unset($aKeys[$i]);
			return \array_values($aKeys);
		}));
		if (!$bDone) {
			return $this->jsonResponse(__FUNCTION__, false);
		}
		$this->Logger()->Write("TFA: security key removed for {$oAccount->Email()}");
		$aRecord = $this->loadRecord($oAccount);
		if (!$aRecord || !TwoFactorRecord::isOn($aRecord, $this->recordKey())) {
			// The last factor gone: mail apps take the password again.
			$this->appPasswordsRequired($oAccount, false);
		}
		return $this->jsonResponse(__FUNCTION__, $this->getTwoFactorInfo($oAccount, true));
	}

	/** Applies $f to the key list at the key referenced by $sRef; to be called under the lock. */
	protected function editPasskeys(MainAccount $oAccount, string $sRef, callable $f) : bool
	{
		$aRecord = $this->loadRecord($oAccount);
		$aKeys = $aRecord ? TwoFactorRecord::passkeys($aRecord, $this->recordKey()) : null;
		if (!$aKeys || '' === $sRef) {
			return false;
		}
		foreach ($aKeys as $i => $k) {
			if (\hash_equals(static::passkeyRef((string) ($k['Id'] ?? '')), $sRef)) {
				return $this->saveRecord($oAccount, TwoFactorRecord::withPasskeys($aRecord, $f($aKeys, $i), $this->recordKey()));
			}
		}
		return false;
	}

	/* ---- the record ---- */

	protected function recordKey() : string
	{
		return TwoFactorRecord::key(\APP_SALT);
	}

	/** The stored record in its current shape, or null when there is none for this account. */
	protected function loadRecord(MainAccount $oAccount) : ?array
	{
		return $this->loadRecordFor($oAccount->Email());
	}

	/** The same, by address: the storage path of an address is its own account's. */
	protected function loadRecordFor(string $sEmail) : ?array
	{
		if ('' === $sEmail) {
			return null;
		}
		$sData = $this->StorageProvider()->Get($sEmail,
			\RainLoop\Providers\Storage\Enumerations\StorageType::CONFIG,
			'two_factor'
		);
		$mData = $sData ? static::DecodeKeyValues($sData) : array();
		if (empty($mData['User']) || $sEmail !== $mData['User']
			|| (empty($mData['Secret']) && empty($mData['SecretBox']) && empty($mData['PasskeysBox']) && empty($mData['UserHandle']))) {
			return null;
		}
		return TwoFactorRecord::normalise($mData, $this->recordKey());
	}

	protected function saveRecord(MainAccount $oAccount, array $aRecord) : bool
	{
		return $this->StorageProvider()->Put($oAccount,
			\RainLoop\Providers\Storage\Enumerations\StorageType::CONFIG,
			'two_factor',
			\json_encode($aRecord)
		);
	}

	/** How long a check waits for another one on the same account, in seconds. */
	protected float $fLockWait = 3.0;

	/**
	 * One code, checked and recorded: failures counted, spent backup codes and
	 * the last time step stored — whatever the outcome.
	 *
	 * Read, decide and write happen under an exclusive lock per account, and
	 * the record is read again once the lock is held (S-49): without it,
	 * parallel attempts all read the same Failures and the last write wins,
	 * so the lockout counted bursts rather than attempts, and one backup code
	 * or one time step could be spent twice. The record passed in only says
	 * that one existed; the one under the lock decides.
	 * A lock that cannot be taken refuses: "busy" is not "ok".
	 */
	protected function checkCode(MainAccount $oAccount, array $aRecord, string $sCode, bool $bMarkTested = false) : string
	{
		$rLock = $this->lockRecord($oAccount);
		if (!$rLock) {
			$this->Logger()->Write("TFA: busy for {$oAccount->Email()}");
			return 'busy';
		}
		try {
			$aRecord = $this->loadRecord($oAccount);
			if (!$aRecord) {
				return 'wrong';
			}
			$oProvider = $this->TwoFactorAuthProvider($oAccount);
			// A TOTP code counts once the TOTP is on, or while it is being
			// tested. A secret created next to a security key and never
			// tested is not a second factor yet (2.28.0); backup codes are.
			$bTotp = $bMarkTested || !empty($aRecord['Enable']);
			[$sOutcome, $aNew] = TwoFactorRecord::check($aRecord, $sCode, $this->recordKey(), \time(),
				fn (string $sSecret, string $s) => $bTotp ? $oProvider->MatchingSlice($sSecret, $s) : null);
			if ('ok' === $sOutcome && $bMarkTested) {
				$aNew['Tested'] = true;
			}
			$this->saveRecord($oAccount, $aNew);
		} finally {
			\flock($rLock, LOCK_UN);
			\fclose($rLock);
		}
		// "replay" and "locked" are not "wrong code": a log that merges them
		// loses the one line worth reading.
		$this->Logger()->Write("TFA: {$sOutcome} for {$oAccount->Email()}");
		return $sOutcome;
	}

	/** The lock file sits next to the record, in the account's own directory. */
	protected function lockPath(MainAccount $oAccount) : string
	{
		$sDir = (string) $this->StorageProvider()->GenerateFilePath($oAccount,
			\RainLoop\Providers\Storage\Enumerations\StorageType::CONFIG, true);
		return '' === $sDir ? '' : \rtrim($sDir, '/') . '/two_factor.lock';
	}

	/** @return resource|null the held lock, or null when it could not be had in time */
	protected function lockRecord(MainAccount $oAccount)
	{
		$sPath = $this->lockPath($oAccount);
		if ('' === $sPath || \is_link($sPath)) {
			return null;
		}
		$rLock = @\fopen($sPath, 'c');
		if (!$rLock) {
			return null;
		}
		$fUntil = \microtime(true) + $this->fLockWait;
		do {
			if (\flock($rLock, LOCK_EX | LOCK_NB)) {
				return $rLock;
			}
			\usleep(20000);
		} while (\microtime(true) < $fUntil);
		\fclose($rLock);
		return null;
	}

	protected function Logger() : \MailSo\Log\Logger
	{
		return $this->Manager()->Actions()->Logger();
	}
	protected function getMainAccountFromToken() : MainAccount
	{
		return $this->Manager()->Actions()->getMainAccountFromToken();
	}
	protected function StorageProvider() : \RainLoop\Providers\Storage
	{
		return $this->Manager()->Actions()->StorageProvider();
	}

	private $oTwoFactorAuthProvider = null;
	protected function TwoFactorAuthProvider(MainAccount $oAccount) : ?TwoFactorAuthInterface
	{
		if (!$this->oTwoFactorAuthProvider) {
			require_once __DIR__ . '/providers/interface.php';
			require_once __DIR__ . '/providers/totp.php';
			$this->oTwoFactorAuthProvider = new TwoFactorAuthTotp();
		}
		return $this->oTwoFactorAuthProvider;
	}

	/**
	 * What the settings screen may know: never the secret, the codes or the
	 * QR code, and of the security keys only their name and dates — not the
	 * public key, not the credential id.
	 */
	protected function getTwoFactorInfo(MainAccount $oAccount, bool $bRemoveSecret = false) : array
	{
		$aRecord = $this->loadRecord($oAccount);
		$aConf = $this->webAuthnConf();
		$aKeys = $aRecord ? (TwoFactorRecord::passkeys($aRecord, $this->recordKey()) ?? array()) : array();
		$aPending = $aRecord ? TwoFactorRecord::pending($aRecord, \time()) : null;
		return array(
			'User' => $oAccount->Email(),
			'IsSet' => $aRecord && !empty($aRecord['SecretBox']),
			'Enable' => $aRecord ? !empty($aRecord['Enable']) : false,
			'Tested' => $aRecord ? !empty($aRecord['Tested']) : false,
			// 2.28.0: the second factor of the account, whichever it is.
			'On' => $aRecord && TwoFactorRecord::isOn($aRecord, $this->recordKey()),
			'Enrolled' => $aRecord && TwoFactorRecord::hasFactor($aRecord, $this->recordKey()),
			// 2.32.0: a key is the only second factor — without an authenticator
			// app, only the backup codes open the account if the key is not at hand.
			'OnlyKey' => $aRecord && empty($aRecord['Enable']) && \count($aKeys) > 0,
			// Codes shown and waiting for their proof: which rank to retype, and
			// whether a first key waits with them. Never the codes.
			'Pending' => null !== $aPending,
			'PendingAsk' => $aPending ? ((int) ($aPending['ask'] ?? 0)) + 1 : 0,
			'PendingKey' => $aPending ? '' !== (string) ($aPending['kb'] ?? '') : false,
			'BackupLeft' => $aRecord ? \count((array) ($aRecord['BackupHashes'] ?? array())) : 0,
			'WebAuthn' => null !== $aConf,
			'MaxPasskeys' => $aConf ? $aConf['max'] : 0,
			'Passkeys' => \array_map(fn ($k) => array(
				// A reference, not the credential id: the screen has no use for it.
				'Ref' => static::passkeyRef((string) ($k['Id'] ?? '')),
				'Name' => (string) ($k['Name'] ?? ''),
				'Created' => (int) ($k['Created'] ?? 0),
				'LastUsed' => (int) ($k['LastUsed'] ?? 0)
			), $aKeys)
		);
	}

	private static function DecodeKeyValues(string $sData) : array
	{
		if (!\str_contains($sData, 'User')) {
			$sData = \MailSo\Base\Utils::UrlSafeBase64Decode($sData);
			if (!\strlen($sData)) {
				return array();
			}
			$sKey = \md5(APP_SALT);
			$sData = \is_callable('xxtea_decrypt')
				? \xxtea_decrypt($sData, $sKey)
				: \MailSo\Base\Xxtea::decrypt($sData, $sKey);
		}
		try {
			return \json_decode($sData, true, 512, JSON_THROW_ON_ERROR) ?: array();
		} catch (\Throwable $e) {
			// Never unserialize(): the stored string is data, and unserialize()
			// of data is object injection.
			return array();
		}
	}
}
