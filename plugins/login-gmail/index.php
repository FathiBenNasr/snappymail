<?php

/**
 * https://developers.google.com/gmail/imap/imap-smtp
 * https://developers.google.com/gmail/imap/xoauth2-protocol
 * https://console.cloud.google.com/apis/dashboard
 */

class LoginGMailPlugin extends \Tachyon\Plugins\AbstractPlugin
{
	const
		NAME     = 'Login GMail OAuth2',
		VERSION  = '2.38',
		RELEASE  = '2026-09-26',
		REQUIRED = '2.36.1',
		CATEGORY = 'Login',
		DESCRIPTION = 'GMail IMAP, Sieve & SMTP login using RFC 7628 OAuth2';

	const
		LOGIN_URI = 'https://accounts.google.com/o/oauth2/auth',
		TOKEN_URI = 'https://accounts.google.com/o/oauth2/token';

	use \Tachyon\Plugins\OAuth2Accounts;

	protected function oauthPrefix() : string
	{
		return 'login-gmail';
	}

	protected function oauthTokenUri() : string
	{
		return static::TOKEN_URI;
	}

	protected function oauthClient() : ?\OAuth2\Client
	{
		return $this->gmailConnector();
	}

	public function Init() : void
	{
		$this->UseLangs(true);
		$this->addJs('LoginOAuth2.js');
		$this->addHook('imap.before-login', 'clientLogin');
		$this->addHook('smtp.before-login', 'clientLogin');
		$this->addHook('sieve.before-login', 'clientLogin');

		$this->addPartHook('LoginGMail', 'ServiceLoginGMail');

		// Prevent Disallowed Sec-Fetch Dest: document Mode: navigate Site: cross-site User: true
		$this->addHook('filter.http-paths', 'httpPaths');
	}

	public function httpPaths(array $aPaths) : void
	{
		if (!empty($aPaths[0]) && 'LoginGMail' === $aPaths[0]) {
			$oConfig = \Tachyon\Api::Config();
			$oConfig->Set('security', 'secfetch_allow',
				\trim($oConfig->Get('security', 'secfetch_allow', '') . ';site=cross-site', ';')
			);
		}
	}

	public function ServiceLoginGMail() : string
	{
		$oActions = \Tachyon\Api::Actions();
		$oHttp = $oActions->Http();
		$oHttp->ServerNoCache();

		$uri = \preg_replace('/.LoginGMail.*$/D', '', $_SERVER['REQUEST_URI']);

		try
		{
			if (isset($_GET['error'])) {
				throw new \RuntimeException($_GET['error']);
			}
			if (isset($_GET['code']) && isset($_GET['state']) && 'gmail' === $_GET['state']) {
				$oGMail = $this->gmailConnector();
			}
			if (empty($oGMail)) {
				$oActions->Location($uri);
				exit;
			}

			$iExpires = \time();
			$aResponse = $oGMail->getAccessToken(
				static::TOKEN_URI,
				'authorization_code',
				array(
					'code' => $_GET['code'],
					'redirect_uri' => $oHttp->GetFullUrl().'?LoginGMail'
				)
			);
			if (200 != $aResponse['code']) {
				if (isset($aResponse['result']['error'])) {
					throw new \RuntimeException(
						$aResponse['code']
						. ': '
						. $aResponse['result']['error']
						. ' / '
						. $aResponse['result']['error_description']
					);
				}
				throw new \RuntimeException("HTTP: {$aResponse['code']}");
			}
			$aResponse = $aResponse['result'];
			if (empty($aResponse['access_token'])) {
				throw new \RuntimeException('access_token missing');
			}
			if (empty($aResponse['refresh_token'])) {
				throw new \RuntimeException('refresh_token missing');
			}

			$sAccessToken = $aResponse['access_token'];
			$iExpires += $aResponse['expires_in'];

			$oGMail->setAccessToken($sAccessToken);
			$aUserInfo = $oGMail->fetch('https://www.googleapis.com/oauth2/v2/userinfo');
			if (200 != $aUserInfo['code']) {
				throw new \RuntimeException("HTTP: {$aResponse['code']}");
			}
			$aUserInfo = $aUserInfo['result'];
			if (empty($aUserInfo['id'])) {
				throw new \RuntimeException('unknown id');
			}
			if (empty($aUserInfo['email'])) {
				throw new \RuntimeException('unknown email address');
			}

			$aTokens = [
				'access_token' => $sAccessToken,
				'refresh_token' => $aResponse['refresh_token'],
				'expires_in' => $aResponse['expires_in'],
				'expires' => $iExpires
			];
			$this->oauthSeedToken($aUserInfo['email'], $aTokens);

			$oPassword = new \Tachyon\Util\SensitiveString($aUserInfo['id']);
			$oAccount = $oActions->LoginProcess($aUserInfo['email'], $oPassword);
//			$oAccount = MainAccount::NewInstanceFromCredentials($oActions, $aUserInfo['email'], $aUserInfo['email'], $oPassword, true);
			if ($oAccount) {
//				$oActions->SetMainAuthAccount($oAccount);
//				$oActions->SetAuthToken($oAccount);
				$this->oauthSaveTokensFor($oAccount, $aTokens);
			}
		}
		catch (\Exception $oException)
		{
			$oActions->Logger()->WriteException($oException, \LOG_ERR);
		}
		$oActions->Location($uri);
		exit;
	}

	public function configMapping() : array
	{
		return [
			\Tachyon\Plugins\Property::NewInstance('client_id')
				->SetLabel('Client ID')
				->SetType(\Tachyon\Enumerations\PluginPropertyType::STRING)
				->SetAllowedInJs()
				->SetDescription('https://github.com/the-djmaze/snappymail/wiki/FAQ#gmail'),
			\Tachyon\Plugins\Property::NewInstance('client_secret')
				->SetLabel('Client Secret')
				->SetType(\Tachyon\Enumerations\PluginPropertyType::STRING)
				->SetEncrypted()
		];
	}

	public function clientLogin(\Tachyon\Model\Account $oAccount, \MailSo\Net\NetClient $oClient, \MailSo\Net\ConnectSettings $oSettings) : void
	{
		// Additional accounts used to be excluded here, which left a Gmail account
		// added alongside the login one with no way to authenticate but an app
		// password, and so 2-step verification turned on to get one.
		if (\str_ends_with(\strtolower($oAccount->Email()), '@gmail.com')) {
			$this->oauthApplySettings($oAccount, $oSettings);
		}
	}

	protected function gmailConnector() : ?\OAuth2\Client
	{
		$client_id = \trim($this->Config()->Get('plugin', 'client_id', ''));
		$client_secret = \trim($this->Config()->getDecrypted('plugin', 'client_secret', ''));
		if ($client_id && $client_secret) {
			try
			{
				$oGMail = new \OAuth2\Client($client_id, $client_secret);
				$oActions = \Tachyon\Api::Actions();
				$sProxy = $oActions->Config()->Get('labs', 'curl_proxy', '');
				if (\strlen($sProxy)) {
					$oGMail->setCurlOption(CURLOPT_PROXY, $sProxy);
					$sProxyAuth = $oActions->Config()->Get('labs', 'curl_proxy_auth', '');
					if (\strlen($sProxyAuth)) {
						$oGMail->setCurlOption(CURLOPT_PROXYUSERPWD, $sProxyAuth);
					}
				}
				return $oGMail;
			}
			catch (\Exception $oException)
			{
				$oActions->Logger()->WriteException($oException, \LOG_ERR);
			}
		}
		return null;
	}
}
