<?php

require_once __DIR__ . '/providers/record.php';

use \RainLoop\Exceptions\ClientException;
use \RainLoop\Model\Account;
use \RainLoop\Model\MainAccount;

class TwoFactorAuthPlugin extends \RainLoop\Plugins\AbstractPlugin
{
	const
		NAME     = 'Two Factor Authentication',
		VERSION  = '2.24.0',
		RELEASE  = '2026-10-07',
		REQUIRED = '2.36.0',
		CATEGORY = 'Login',
		DESCRIPTION = 'Provides support for TOTP 2FA',
		// The additional message of the refusal when the code is missing.
		CODE_REQUIRED = 'TwoFactorCodeRequired';

	public function Init() : void
	{
		$this->UseLangs(true);

		$this->addJs('js/TwoFactorAuthLogin.js');
		$this->addJs('js/TwoFactorAuthSettings.js');

		$this->addHook('login.success', 'DoLogin');
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
			if ($aResult['RequireTwoFactor'] && !empty($aResult['Auth'])) {
				$aData = $this->getTwoFactorInfo($this->getMainAccountFromToken());
				$aResult['SetupTwoFactor'] = empty($aData['IsSet']) || empty($aData['Enable']);
			}
		}
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

		$oActions = $this->Manager()->Actions();
		if ($oActions->HasActionParam('EnableTwoFactor')) {
			$sValue = $oActions->GetActionParam('EnableTwoFactor', '');
			$oActions->SettingsProvider()->Load($oAccount)->SetConf('EnableTwoFactor', !empty($sValue));
		}

		$aRecord['Enable'] = $bEnable;
		$bSaved = $this->saveRecord($oAccount, $aRecord);
		$bSaved && $this->appPasswordsRequired($oAccount, $bEnable);
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
	 * Mail apps (IMAP, SMTP, DAV) take app passwords only while the second
	 * factor is on — the SnappyMail-mots-de-passe-appli store, when it is
	 * installed (its plugin loads the shared code). Without it, nothing
	 * changes: the second factor then guards the webmail alone, as before.
	 */
	protected function appPasswordsRequired(MainAccount $oAccount, bool $bRequired) : void
	{
		if (!\class_exists('\\Convergent\\Appli\\Appli')) {
			return;
		}
		$aConf = \Convergent\Appli\Appli::conf((string) $this->Config()->Get('plugin', 'app_passwords_conf', '/etc/sky-appli.conf'));
		if ($aConf && null !== \Convergent\Appli\Appli::compte($oAccount->Email(), (array) $aConf['domaines'])
			&& !\Convergent\Appli\Appli::poserExigence($aConf, $oAccount->Email(), $bRequired)) {
			$this->Logger()->Write('TFA: could not ' . ($bRequired ? 'require' : 'release') . " app passwords for {$oAccount->Email()}");
		}
	}

	/* ---- the record ---- */

	protected function recordKey() : string
	{
		return TwoFactorRecord::key(\APP_SALT);
	}

	/** The stored record in its current shape, or null when there is none for this account. */
	protected function loadRecord(MainAccount $oAccount) : ?array
	{
		$sData = $this->StorageProvider()->Get($oAccount,
			\RainLoop\Providers\Storage\Enumerations\StorageType::CONFIG,
			'two_factor'
		);
		$mData = $sData ? static::DecodeKeyValues($sData) : array();
		if (empty($mData['User']) || $oAccount->Email() !== $mData['User']
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

	/**
	 * One code, checked and recorded: failures counted, spent backup codes and
	 * the last time step stored — whatever the outcome.
	 */
	protected function checkCode(MainAccount $oAccount, array $aRecord, string $sCode, bool $bMarkTested = false) : string
	{
		$oProvider = $this->TwoFactorAuthProvider($oAccount);
		[$sOutcome, $aNew] = TwoFactorRecord::check($aRecord, $sCode, $this->recordKey(), \time(),
			fn (string $sSecret, string $s) => $oProvider->MatchingSlice($sSecret, $s));
		if ('ok' === $sOutcome && $bMarkTested) {
			$aNew['Tested'] = true;
		}
		$this->saveRecord($oAccount, $aNew);
		// "replay" and "locked" are not "wrong code": a log that merges them
		// loses the one line worth reading.
		$this->Logger()->Write("TFA: {$sOutcome} for {$oAccount->Email()}");
		return $sOutcome;
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
