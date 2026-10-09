<?php
/**
 * S-21 (audit 2026-10): enabling a second factor must be able to revoke every
 * "remember me" token of the account. The core gives ClearAllSignMeTokens();
 * the two-factor plugin has to call it. This proves the primitive, and that
 * the call the audit proposed (Clear with an empty key) revokes nothing.
 * Run with: php test/signme-revoke.php
 */
define('APP_VERSION', '0.0.0-test');
spl_autoload_register(static function (string $class): void {
	$base = dirname(__DIR__).'/snappymail/v/0.0.0/app/libraries/';
	$file = str_starts_with($class, 'SnappyMail\\')
		? $base.strtolower(str_replace('\\', '/', $class)).'.php'
		: $base.str_replace('\\', '/', $class).'.php';
	if (is_file($file)) {
		require_once $file;
	}
});

use RainLoop\Providers\Storage\Enumerations\StorageType;

$iChecks = 0;
function check(bool $condition, string $message): void
{
	global $iChecks;
	++$iChecks;
	if (!$condition) {
		fwrite(STDERR, "FAIL: {$message}\n");
		exit(1);
	}
}

class Host
{
	use \RainLoop\Actions\UserAuth;
	public $oStorage;
	public function StorageProvider() { return $this->oStorage; }
}

$sData = sys_get_temp_dir() . '/signme-revoke-' . getmypid();
$oStorage = new \RainLoop\Providers\Storage\FileStorage($sData);
$account = static function (string $sEmail) : \RainLoop\Model\MainAccount {
	$o = (new ReflectionClass(\RainLoop\Model\MainAccount::class))->newInstanceWithoutConstructor();
	(new ReflectionProperty(\RainLoop\Model\Account::class, 'sEmail'))->setValue($o, $sEmail);
	return $o;
};
$oVictim = $account('ahmed@bank.tn');
$oOther = $account('leila@bank.tn');

// Three remembered devices for the victim, one for somebody else.
foreach (['uuid-a', 'uuid-b', 'uuid-c'] as $u) {
	$oStorage->Put($oVictim, StorageType::SIGN_ME, $u, 'server-half');
}
$oStorage->Put($oOther, StorageType::SIGN_ME, 'uuid-z', 'server-half');
$oStorage->Put($oVictim, StorageType::CONFIG, 'contacts_sync', 'kept');

// What the audit proposed does nothing (the key '' names the directory).
@$oStorage->Clear($oVictim, StorageType::SIGN_ME, '');
check('server-half' === $oStorage->Get($oVictim, StorageType::SIGN_ME, 'uuid-a'),
	'Clear with an empty key now revokes: update the note in UserAuth.php');

$oHost = new Host;
$oHost->oStorage = $oStorage;
check(3 === $oHost->ClearAllSignMeTokens($oVictim), 'not every token revoked');
foreach (['uuid-a', 'uuid-b', 'uuid-c'] as $u) {
	check(false === $oStorage->Get($oVictim, StorageType::SIGN_ME, $u), "token {$u} survived");
}
check('server-half' === $oStorage->Get($oOther, StorageType::SIGN_ME, 'uuid-z'), "another account's token revoked");
check('kept' === $oStorage->Get($oVictim, StorageType::CONFIG, 'contacts_sync'), 'other storage touched');
check(0 === $oHost->ClearAllSignMeTokens($oVictim), 'second call found tokens');
check(0 === $oHost->ClearAllSignMeTokens($account('nobody@nowhere.tn')), 'account without tokens');

exec('rm -rf ' . escapeshellarg($sData));
echo "signme-revoke: ok ({$iChecks} checks)\n";
