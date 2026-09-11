<?php

use \RainLoop\Exceptions\ClientException;
use \RainLoop\Model\Account;
use \RainLoop\Model\MainAccount;

class TwoFactorAuthPlugin extends \RainLoop\Plugins\AbstractPlugin
{
	const
		NAME     = 'Two Factor Authentication',
		VERSION  = '2.20.0',
		RELEASE  = '2026-09-11',
		REQUIRED = '2.36.0',
		CATEGORY = 'Login',
		DESCRIPTION = 'Provides support for TOTP 2FA';

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
				$aResult['SetupTwoFactor'] = empty($aData['IsSet']) || empty($aData['Enable']) || empty($aData['Secret']);
			}
		}
	}

	public function DoLogin(MainAccount $oAccount)
	{
		if ($this->TwoFactorAuthProvider($oAccount)) {
			$aData = $this->getTwoFactorInfo($oAccount);
			if (isset($aData['IsSet'], $aData['Enable']) && !empty($aData['Secret']) && $aData['IsSet'] && $aData['Enable']) {
				$sCode = \trim($this->jsonParam('totp_code', ''));
				if (empty($sCode)) {
					$this->Logger()->Write("TFA: Code required for {$oAccount->Email()}");
					throw new ClientException(\RainLoop\Notifications::AuthError);
				}

				$bUseBackupCode = false;
				if (6 < \strlen($sCode) && !empty($aData['BackupCodes'])) {
					$aBackupCodes = \explode(' ', \trim(\preg_replace('/[^\d]+/', ' ', $aData['BackupCodes'])));
					$bUseBackupCode = \in_array($sCode, $aBackupCodes);
					if ($bUseBackupCode) {
						$this->removeBackupCodeFromTwoFactorInfo($oAccount, $sCode);
					}
				}

				if (!$bUseBackupCode && !$this->TwoFactorAuthProvider($oAccount)->VerifyCode($aData['Secret'], $sCode)) {
					$this->Manager()->Actions()->LoggerAuthHelper($oAccount);
					$this->Logger()->Write("TFA: Code failed for {$oAccount->Email()}");
					throw new ClientException(\RainLoop\Notifications::AuthError);
				}
				$this->Logger()->Write("TFA: Code verified for {$oAccount->Email()}");
			}
		}
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

		$sEmail = $oAccount->Email();

		$sSecret = $this->TwoFactorAuthProvider($oAccount)->CreateSecret();

		$aCodes = \array_map(function(){return \rand(100000000, 900000000);}, \array_fill(0, 8, null));

		$this->StorageProvider()->Put($oAccount,
			\RainLoop\Providers\Storage\Enumerations\StorageType::CONFIG,
			'two_factor',
			\json_encode(array(
				'User' => $sEmail,
				'Enable' => false,
				'Secret' => $sSecret,
				'QRCode' => $this->getQRCode($oAccount, $sSecret),
				'BackupCodes' => \implode(' ', $aCodes)
			))
		);

		return $this->jsonResponse(__FUNCTION__, $this->getTwoFactorInfo($oAccount));
	}

	private function getQRCode(MainAccount $oAccount, string $secret) : string
	{
		$email = \rawurlencode($oAccount->Email());
//		$issuer = \rawurlencode(\RainLoop\API::Config()->Get('webmail', 'title', 'SnappyMail'));
		$uri = "otpauth://totp/{$email}?secret={$secret}";
		$image = $this->otpImageUrl();
		if ($image) {
			$uri .= '&image=' . \rawurlencode($image);
		}
		$QR = \SnappyMail\QRCode::getMinimumQRCode(
//			"otpauth://totp/{$issuer}:{$email}?secret={$secret}&issuer={$issuer}",
			$uri,
			\SnappyMail\QRCode::ERROR_CORRECT_LEVEL_M
		);
		return $QR->__toString();
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

	public function DoShowTwoFactorSecret() : array
	{
		$oAccount = $this->getMainAccountFromToken();

		if (!$this->TwoFactorAuthProvider($oAccount)) {
			return $this->jsonResponse(__FUNCTION__, false);
		}

		$aResult = $this->getTwoFactorInfo($oAccount);
		unset($aResult['BackupCodes']);

		$aResult['QRCode'] = $this->getQRCode($oAccount, $aResult['Secret']);

		return $this->jsonResponse(__FUNCTION__, $aResult);
	}

	public function DoEnableTwoFactor() : array
	{
		$oAccount = $this->getMainAccountFromToken();

		if (!$this->TwoFactorAuthProvider($oAccount)) {
			return $this->jsonResponse(__FUNCTION__, false);
		}

		$oActions = $this->Manager()->Actions();
		if ($oActions->HasActionParam('EnableTwoFactor')) {
			$sValue = $oActions->GetActionParam('EnableTwoFactor', '');
			$oActions->SettingsProvider()->Load($oAccount)->SetConf('EnableTwoFactor', !empty($sValue));
		}

		$sEmail = $oAccount->Email();

		$bResult = false;
		$mData = $this->getTwoFactorInfo($oAccount);
		if (isset($mData['Secret'], $mData['BackupCodes'])) {
			$bResult = $this->StorageProvider()->Put($oAccount,
				\RainLoop\Providers\Storage\Enumerations\StorageType::CONFIG,
				'two_factor',
				\json_encode(array(
					'User' => $sEmail,
					'Enable' => '1' === \trim($this->jsonParam('Enable', '0')),
					'Secret' => $mData['Secret'],
					'BackupCodes' => $mData['BackupCodes']
				))
			);
		}

		return $this->jsonResponse(__FUNCTION__, $bResult);
	}

	public function DoVerifyTwoFactorCode() : array
	{
		$oAccount = $this->getMainAccountFromToken();

		if (!$this->TwoFactorAuthProvider($oAccount)) {
			return $this->jsonResponse(__FUNCTION__, false);
		}

		$sCode = \trim($this->jsonParam('Code', ''));

		$aData = $this->getTwoFactorInfo($oAccount);
		$sSecret = !empty($aData['Secret']) ? $aData['Secret'] : '';

		return $this->jsonResponse(__FUNCTION__,
			$this->TwoFactorAuthProvider($oAccount)->VerifyCode($sSecret, $sCode));
	}

	public function DoClearTwoFactorInfo() : array
	{
		$oAccount = $this->getMainAccountFromToken();

		if (!$this->TwoFactorAuthProvider($oAccount)) {
			return $this->jsonResponse(__FUNCTION__, false);
		}

		$this->StorageProvider()->Clear($oAccount,
			\RainLoop\Providers\Storage\Enumerations\StorageType::CONFIG,
			'two_factor'
		);

		return $this->jsonResponse(__FUNCTION__, $this->getTwoFactorInfo($oAccount, true));
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
			require __DIR__ . '/providers/interface.php';
			require __DIR__ . '/providers/totp.php';
			$this->oTwoFactorAuthProvider = new TwoFactorAuthTotp();
		}
		return $this->oTwoFactorAuthProvider;
	}

	protected function getTwoFactorInfo(MainAccount $oAccount, bool $bRemoveSecret = false) : array
	{
		$sEmail = $oAccount->Email();

		$mData = null;

		$aResult = array(
			'User' => '',
			'IsSet' => false,
			'Enable' => false,
			'Secret' => '',
			'BackupCodes' => ''
		);

		if (!empty($sEmail)) {
			$aResult['User'] = $sEmail;

			$sData = $this->StorageProvider()->Get($oAccount,
				\RainLoop\Providers\Storage\Enumerations\StorageType::CONFIG,
				'two_factor'
			);

			if ($sData) {
				$mData = static::DecodeKeyValues($sData);
			}
		}

		if (!empty($aResult['User']) &&
			!empty($mData['User']) && !empty($mData['Secret']) &&
			!empty($mData['BackupCodes']) && $sEmail === $mData['User'])
		{
			$aResult['IsSet'] = true;
			$aResult['Enable'] = isset($mData['Enable']) ? !!$mData['Enable'] : false;
			$aResult['Secret'] = $mData['Secret'];
			$aResult['BackupCodes'] = $mData['BackupCodes'];
			$aResult['QRCode'] = $this->getQRCode($oAccount, $mData['Secret']);
		}

		if ($bRemoveSecret) {
			if (isset($aResult['Secret'])) {
				unset($aResult['Secret']);
			}

			if (isset($aResult['BackupCodes'])) {
				unset($aResult['BackupCodes']);
			}
		}

		return $aResult;
	}

	protected function removeBackupCodeFromTwoFactorInfo(MainAccount $oAccount, string $sCode) : bool
	{
		if (!$oAccount || empty($sCode)) {
			return false;
		}

		$sData = $this->StorageProvider()->Get($oAccount,
			\RainLoop\Providers\Storage\Enumerations\StorageType::CONFIG,
			'two_factor'
		);

		if ($sData) {
			$mData = static::DecodeKeyValues($sData);

			if (!empty($mData['BackupCodes'])) {
				$sBackupCodes = \preg_replace('/[^\d]+/', ' ', ' '.$mData['BackupCodes'].' ');
				$sBackupCodes = \str_replace(' '.$sCode.' ', '', $sBackupCodes);

				$mData['BackupCodes'] = \trim(\preg_replace('/[^\d]+/', ' ', $sBackupCodes));

				return $this->StorageProvider()->Put($oAccount,
					\RainLoop\Providers\Storage\Enumerations\StorageType::CONFIG,
					'two_factor',
					\json_encode($mData)
				);
			}
		}

		return false;
	}

	private static function DecodeKeyValues(string $sData) : array
	{
		if (!\str_contains($sData, 'User')) {
			$sData = \MailSo\Base\Utils::UrlSafeBase64Decode($sData);
			if (!\strlen($sData)) {
				return '';
			}
			$sKey = \md5(APP_SALT);
			$sData = \is_callable('xxtea_decrypt')
				? \xxtea_decrypt($sData, $sKey)
				: \MailSo\Base\Xxtea::decrypt($sData, $sKey);
		}
		try {
			return \json_decode($sData, true, 512, JSON_THROW_ON_ERROR) ?: array();
		} catch (\Throwable $e) {
			return \unserialize($sData) ?: array();
		}
	}
}
