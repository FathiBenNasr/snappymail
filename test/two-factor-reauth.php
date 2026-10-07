<?php

// Run with: php test/two-factor-reauth.php
define('APP_VERSION', 'test');
spl_autoload_register(static function (string $class): void {
	$base = dirname(__DIR__).'/tachyon/v/0.0.0/app/libraries/';
	$file = str_starts_with($class, 'Tachyon\\Util\\')
		? $base.'tachyon_util/'.strtolower(str_replace('\\', '/', substr($class, 13))).'.php'
		: $base.str_replace('\\', '/', $class).'.php';
	if (is_file($file)) {
		require_once $file;
	}
});
require dirname(__DIR__).'/plugins/two-factor-auth/index.php';
require_once dirname(__DIR__).'/plugins/two-factor-auth/providers/interface.php';

function check(bool $condition, string $message): void
{
	if (!$condition) {
		throw new RuntimeException($message);
	}
}

// Storage, provider and logger replaced; the gate itself is the real code.
// The records are stored in the clear format of 2.19.1, which the plugin seals
// on first read: the gate has to work for accounts enrolled before 2.20.0.
class MemoryStorage implements \Tachyon\Providers\Storage\IStorage
{
	public array $data = [];
	public function Put($mAccount, int $iStorageType, string $sKey, string $sValue) : bool { $this->data[$sKey] = $sValue; return true; }
	public function Get($mAccount, int $iStorageType, string $sKey, $mDefault = false) { return $this->data[$sKey] ?? $mDefault; }
	public function Clear($mAccount, int $iStorageType, string $sKey) : bool { unset($this->data[$sKey]); return true; }
	public function IsLocal() : bool { return true; }
}
class TestTwoFactor extends TwoFactorAuthPlugin
{
	public MemoryStorage $store;
	public function setInfo(array $info) : void
	{
		$this->store = new MemoryStorage;
		$info['IsSet'] && $this->store->data['two_factor'] = json_encode(['User' => 'user@example.com'] + $info);
	}
	protected function StorageProvider() : \Tachyon\Providers\Storage { return new \Tachyon\Providers\Storage($this->store); }
	protected function TwoFactorAuthProvider(\Tachyon\Model\MainAccount $oAccount) : ?\TwoFactorAuthInterface
	{
		return new class implements \TwoFactorAuthInterface {
			public function Label() : string { return 'test'; }
			public function VerifyCode(string $sSecret, string $sCode) : bool { return 'SECRET' === $sSecret && '123456' === $sCode; }
			public function CreateSecret() : string { return 'SECRET'; }
		};
	}
	protected function Logger() : \MailSo\Log\Logger { return new \MailSo\Log\Logger(false); }
}

$plugin = (new ReflectionClass(TestTwoFactor::class))->newInstanceWithoutConstructor();
$actions = (new ReflectionClass(\Tachyon\Actions::class))->newInstanceWithoutConstructor();
$manager = (new ReflectionClass(\Tachyon\Plugins\Manager::class))->newInstanceWithoutConstructor();
(new ReflectionProperty(\Tachyon\Plugins\Manager::class, 'oActions'))->setValue($manager, $actions);
(new ReflectionProperty(\Tachyon\Plugins\AbstractPlugin::class, 'oPluginManager'))->setValue($plugin, $manager);
$account = (new ReflectionClass(\Tachyon\Model\MainAccount::class))->newInstanceWithoutConstructor();
(new ReflectionProperty(\Tachyon\Model\Account::class, 'sEmail'))->setValue($account, 'user@example.com');
define('APP_SALT', 'test-salt');
$gate = (new ReflectionMethod(TwoFactorAuthPlugin::class, 'requireCurrentCode'));

$params = new ReflectionProperty(\Tachyon\Actions::class, 'aCurrentActionParams');
$allowed = function (array $values) use ($plugin, $actions, $account, $gate, $params) : bool {
	$params->setValue($actions, $values);
	try {
		$gate->invoke($plugin, $account);
		return true;
	} catch (\Tachyon\Exceptions\ClientException $e) {
		return false;
	}
};

// Not set up, or set up but not enabled: nothing to protect yet.
$plugin->setInfo(['IsSet' => false, 'Enable' => false, 'Secret' => '']);
check($allowed([]), 'blocked although 2FA is not set up');
$plugin->setInfo(['IsSet' => true, 'Enable' => false, 'Secret' => 'SECRET', 'BackupCodes' => '111111111']);
check($allowed([]), 'blocked although 2FA is not enabled');

// Enabled: a valid TOTP or backup code is required.
$plugin->setInfo(['IsSet' => true, 'Enable' => true, 'Secret' => 'SECRET', 'BackupCodes' => '111111111 222222222']);
check(!$allowed([]), 'change allowed with no code while enabled');
check(!$allowed(['Code' => '000000']), 'change allowed with a wrong code');
check(!$allowed(['Code' => '33333333']), 'change allowed with an unknown backup code');
check($allowed(['Code' => '123456']), 'valid TOTP code refused');
check($allowed(['Code' => '222222222']), 'valid backup code refused');
check(!$allowed(['Code' => '222222222']), 'used backup code was not spent');
check($allowed(['Code' => '111111111']), 'the other backup code was spent too');

// Backup codes come from random_int now, not rand().
$source = file_get_contents(dirname(__DIR__).'/plugins/two-factor-auth/index.php')
	.file_get_contents(dirname(__DIR__).'/plugins/two-factor-auth/providers/record.php');
check(!preg_match('/\\\\rand\(/', $source) && str_contains($source, '\\random_int('), 'backup codes not from random_int()');

echo "two-factor-reauth: ok\n";
