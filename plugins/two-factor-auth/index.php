<?php

require_once __DIR__ . '/providers/record.php';

use \RainLoop\Exceptions\ClientException;
use \RainLoop\Model\Account;
use \RainLoop\Model\MainAccount;

class TwoFactorAuthPlugin extends \RainLoop\Plugins\AbstractPlugin
{
	const
		NAME     = 'Two Factor Authentication',
		VERSION  = '2.26.0',
		RELEASE  = '2026-10-10',
		REQUIRED = '2.36.0',
		CATEGORY = 'Login',
		DESCRIPTION = 'Provides support for TOTP 2FA',
		// The additional message of the refusal when the code is missing.
		CODE_REQUIRED = 'TwoFactorCodeRequired',
		// The additional message when a protected account is refused as an additional one.
		NOT_ADDITIONAL = 'TwoFactorNotAdditional';

	public function Init() : void
	{
		$this->UseLangs(true);

		$this->addJs('js/TwoFactorAuthLogin.js');
		$this->addJs('js/TwoFactorAuthSettings.js');

		$this->addHook('login.success', 'DoLogin');
		// login.success runs for the main account only: an additional account
		// goes through filter.account alone, at setup and on every request.
		$this->addHook('filter.account', 'FilterAccount');
		$this->addHook('filter.app-data', 'FilterAppData');

		$this->addJsonHook('GetTwoFactorInfo', 'DoGetTwoFactorInfo');
		$this->addJsonHook('CreateTwoFactorSecret', 'DoCreateTwoFactorSecret');
		$this->addJsonHook('ShowTwoFactorSecret', 'DoShowTwoFactorSecret');
		$this->addJsonHook('EnableTwoFactor', 'DoEnableTwoFactor');
		$this->addJsonHook('VerifyTwoFactorCode', 'DoVerifyTwoFactorCode');
		$this->addJsonHook('ClearTwoFactorInfo', 'DoClearTwoFactorInfo');

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
		];
	}

	public function FilterAppData($bAdmin, &$aResult)
	{
		if (!$bAdmin && \is_array($aResult)/* && isset($aResult['Auth']) && !$aResult['Auth']*/) {
			$aResult['RequireTwoFactor'] = (bool) $this->Config()->Get('plugin', 'force_two_factor_auth', false);

			$aResult['SetupTwoFactor'] = false;
			if (!empty($aResult['Auth'])) {
				$oAccount = $this->getMainAccountFromToken();
				// Per tenant (2.26.0): a domain in the list is held to the
				// same rule as the global switch, and only its accounts.
				$aResult['RequireTwoFactor'] = $aResult['RequireTwoFactor'] || $this->forcedFor($oAccount->Email());
				if ($aResult['RequireTwoFactor']) {
					$aData = $this->getTwoFactorInfo($oAccount);
					$aResult['SetupTwoFactor'] = empty($aData['IsSet']) || empty($aData['Enable']);
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
		if (!($oAccount instanceof \RainLoop\Model\AdditionalAccount)) {
			return;
		}
		// By address: the storage of an AdditionalAccount object resolves to
		// the directory of the main account that holds it, not to its own.
		$aRecord = $this->loadRecordFor($oAccount->Email());
		if (!$aRecord || empty($aRecord['Enable'])) {
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

	public function DoLogin(MainAccount $oAccount)
	{
		$aRecord = $this->loadRecord($oAccount);
		if (!$aRecord || empty($aRecord['Enable'])) {
			return;
		}
		$sCode = \trim($this->jsonParam('totp_code', ''));
		if (empty($sCode)) {
			$this->Logger()->Write("TFA: Code required for {$oAccount->Email()}");
			// Named, so the login screen asks for the code instead of saying
			// "authentication failed": the password was right, and a person
			// told otherwise resets a good password.
			// Saying so after a correct password is what every 2FA login does.
			throw new ClientException(\RainLoop\Notifications::AuthError, null, self::CODE_REQUIRED);
		}
		$sOutcome = $this->checkCode($oAccount, $aRecord, $sCode);
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

		$sSecret = $this->TwoFactorAuthProvider($oAccount)->CreateSecret();
		$aCodes = TwoFactorRecord::newBackupCodes();
		$this->saveRecord($oAccount, TwoFactorRecord::create($oAccount->Email(), $sSecret, $aCodes, $this->recordKey()));

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
		if (!$this->TwoFactorAuthProvider($oAccount) || !$aRecord || !empty($aRecord['Enable'])) {
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
		if (!$this->TwoFactorAuthProvider($oAccount) || !$aRecord) {
			return $this->jsonResponse(__FUNCTION__, false);
		}

		$bEnable = '1' === \trim($this->jsonParam('Enable', '0'));
		if ($bEnable && empty($aRecord['Tested'])) {
			return $this->jsonResponse(__FUNCTION__, false);
		}
		if (!$bEnable && !empty($aRecord['Enable'])
			&& 'ok' !== $this->checkCode($oAccount, $aRecord, (string) $this->jsonParam('Code', ''))) {
			return $this->jsonResponse(__FUNCTION__, false);
		}

		// checkCode() may have written the record (time step, failures): build on that one.
		$aRecord = $this->loadRecord($oAccount) ?? $aRecord;

		$oActions = $this->Manager()->Actions();
		if ($oActions->HasActionParam('EnableTwoFactor')) {
			$sValue = $oActions->GetActionParam('EnableTwoFactor', '');
			$oActions->SettingsProvider()->Load($oAccount)->SetConf('EnableTwoFactor', !empty($sValue));
		}

		// Required before the second factor is on, not after (S-09): when the
		// store is there and cannot be written, enabling is refused rather than
		// left on while the main password still opens IMAP and SMTP.
		if ($bEnable && !$this->appPasswordsRequired($oAccount, true)) {
			return $this->jsonResponse(__FUNCTION__, false);
		}

		$aRecord['Enable'] = $bEnable;
		$bSaved = $this->saveRecord($oAccount, $aRecord);
		if (!$bSaved) {
			$bEnable && $this->appPasswordsRequired($oAccount, false);
		} else if ($bEnable) {
			$this->forgetRememberedDevices($oAccount);
		} else {
			$this->appPasswordsRequired($oAccount, false);
		}
		return $this->jsonResponse(__FUNCTION__, $bSaved);
	}

	/** The test of the phone: counted, rate-limited and replay-guarded like a login. */
	public function DoVerifyTwoFactorCode() : array
	{
		$oAccount = $this->getMainAccountFromToken();
		$aRecord = $this->loadRecord($oAccount);
		if (!$this->TwoFactorAuthProvider($oAccount) || !$aRecord) {
			return $this->jsonResponse(__FUNCTION__, false);
		}
		$bOk = 'ok' === $this->checkCode($oAccount, $aRecord, (string) $this->jsonParam('Code', ''), true);
		return $this->jsonResponse(__FUNCTION__, $bOk);
	}

	/** Removing the second factor asks for a current code, once it is on. */
	public function DoClearTwoFactorInfo() : array
	{
		$oAccount = $this->getMainAccountFromToken();
		$aRecord = $this->loadRecord($oAccount);
		if (!$this->TwoFactorAuthProvider($oAccount)) {
			return $this->jsonResponse(__FUNCTION__, false);
		}
		if ($aRecord && !empty($aRecord['Enable'])
			&& 'ok' !== $this->checkCode($oAccount, $aRecord, (string) $this->jsonParam('Code', ''))) {
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
			|| (empty($mData['Secret']) && empty($mData['SecretBox']))) {
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
			[$sOutcome, $aNew] = TwoFactorRecord::check($aRecord, $sCode, $this->recordKey(), \time(),
				fn (string $sSecret, string $s) => $oProvider->MatchingSlice($sSecret, $s));
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

	/** What the settings screen may know: never the secret, the codes or the QR code. */
	protected function getTwoFactorInfo(MainAccount $oAccount, bool $bRemoveSecret = false) : array
	{
		$aRecord = $this->loadRecord($oAccount);
		return array(
			'User' => $oAccount->Email(),
			'IsSet' => null !== $aRecord,
			'Enable' => $aRecord ? !empty($aRecord['Enable']) : false,
			'Tested' => $aRecord ? !empty($aRecord['Tested']) : false
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
