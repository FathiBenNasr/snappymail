<?php
/**
 * S-01 (audit 2026-10): the backup plugin's restore must require a logged-in
 * administrator, reject zip slip, and never write PHP.
 * Run with: php test/backup-restore.php  (needs the zip extension, no network)
 * The real plugins/backup/index.php is loaded; only the core classes it
 * extends or calls are stubbed.
 */
namespace RainLoop\Plugins {
	abstract class AbstractPlugin
	{
		public $oManager;
		public function Manager() { return $this->oManager; }
		public function jsonResponse(string $sFunction, $mData) { return [$sFunction => $mData]; }
		public function addJs(...$a) {}
		public function addJsonHook(...$a) {}
		public function addTemplate(...$a) {}
	}
}
namespace RainLoop {
	class Actions {}
	class ActionsAdmin extends Actions
	{
		public bool $bLogged = false;
		public int $iCalls = 0;
		public function IsAdminLoggined(bool $bThrow = true) : bool
		{
			++$this->iCalls;
			if (!$this->bLogged && $bThrow) {
				throw new \RuntimeException('would have thrown');
			}
			return $this->bLogged;
		}
	}
}
namespace {
	define('APP_PRIVATE_DATA', sys_get_temp_dir() . '/backup-restore-test-' . getmypid() . '/data/');
	require dirname(__DIR__) . '/plugins/backup/index.php';

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

	/** $_FILES stand-in that records whether the action looked at the upload. */
	class FilesSpy implements ArrayAccess
	{
		public bool $bRead = false;
		public function offsetExists($k) : bool { $this->bRead = true; return true; }
		public function offsetGet($k) : mixed { $this->bRead = true; return ['tmp_name' => '/nonexistent', 'type' => 'application/zip']; }
		public function offsetSet($k, $v) : void {}
		public function offsetUnset($k) : void {}
	}

	$oPlugin = (new ReflectionClass('BackupPlugin'))->newInstanceWithoutConstructor();
	$oPlugin->oManager = new class { public $a; public function Actions() { return $this->a; } };

	// 1. Abuse: anonymous visitor on the admin entry point (ActionsAdmin, no session).
	foreach (['JsonAdminRestoreData', 'JsonAdminBackupData'] as $sAction) {
		$oAdmin = new RainLoop\ActionsAdmin;
		$oPlugin->oManager->a = $oAdmin;
		$_FILES = $oSpy = new FilesSpy;
		check(false === $oPlugin->{$sAction}()[$sAction], "{$sAction}: anonymous admin entry point accepted");
		check(1 === $oAdmin->iCalls, "{$sAction}: admin session not checked");
		check(!$oSpy->bRead, "{$sAction}: upload looked at before the session was checked");
	}
	// User-side actions object: refused too.
	$oPlugin->oManager->a = new RainLoop\Actions;
	$_FILES = $oSpy = new FilesSpy;
	check(false === $oPlugin->JsonAdminRestoreData()['JsonAdminRestoreData'], 'user actions accepted');
	// Logged-in admin: goes on to the upload (which is_uploaded_file refuses in CLI).
	$oAdmin = new RainLoop\ActionsAdmin;
	$oAdmin->bLogged = true;
	$oPlugin->oManager->a = $oAdmin;
	$_FILES = $oSpy = new FilesSpy;
	check(false === $oPlugin->JsonAdminRestoreData()['JsonAdminRestoreData'], 'non-uploaded file accepted');
	check($oSpy->bRead, 'logged-in admin never reached the upload');

	// 2. Entry names.
	foreach (['../index.php', 'configs/../../x', '/etc/passwd', 'configs/..', './configs/a',
		'configs\\..\\x', "configs/a\0.ini", 'C:/x', 'index.php', 'SALT.php', 'cache/x', '', 'configsX/a'] as $sName) {
		check(null !== BackupPlugin::restoreEntryRefusal($sName), "entry '{$sName}' accepted");
	}
	foreach (['configs/application.ini', 'domains/example.com.json', 'plugins/x/config.json',
		'storage/a/b/c', 'AddressBook.sqlite', 'configs/'] as $sName) {
		check(null === BackupPlugin::restoreEntryRefusal($sName), "entry '{$sName}' refused");
	}
	check(null !== BackupPlugin::restoreEntryRefusal('configs/l', 0120777 << 16, ZipArchive::OPSYS_UNIX), 'symlink accepted');
	check(null === BackupPlugin::restoreEntryRefusal('configs/f', 0100644 << 16, ZipArchive::OPSYS_UNIX), 'regular file refused');
	foreach (['plugins/x/index.php', 'plugins/x/A.PHP', 'plugins/x/a.php7', 'plugins/x/a.phtml',
		'plugins/x/a.phar', 'storage/.htaccess', 'configs/.user.ini'] as $sName) {
		check(BackupPlugin::restoreEntryIsCode($sName), "{$sName} not treated as code");
	}
	check(!BackupPlugin::restoreEntryIsCode('configs/application.ini'), 'ini treated as code');

	// 3. Real archives, extracted into a scratch APP_PRIVATE_DATA.
	$sBase = dirname(APP_PRIVATE_DATA);
	@mkdir(APP_PRIVATE_DATA, 0700, true);
	$zip = static function (array $aEntries) use ($sBase) : string {
		$sFile = $sBase . '/' . uniqid() . '.zip';
		$o = new ZipArchive;
		$o->open($sFile, ZipArchive::CREATE);
		foreach ($aEntries as $k => $v) {
			$o->addFromString($k, $v);
		}
		$o->close();
		return $sFile;
	};

	// Zip slip: nothing written at all, not even the good entry before it.
	$r = BackupPlugin::restoreArchive($zip(['configs/a.ini' => 'a', '../escaped.txt' => 'x']), APP_PRIVATE_DATA);
	check(false === $r, 'zip slip archive accepted');
	check(!is_file($sBase . '/escaped.txt'), 'zip slip wrote outside the target');
	check(!is_file(APP_PRIVATE_DATA . 'configs/a.ini'), 'partial write before the refusal');

	// PHP never written, even over an existing plugin file.
	@mkdir(APP_PRIVATE_DATA . 'plugins/p', 0700, true);
	file_put_contents(APP_PRIVATE_DATA . 'plugins/p/index.php', 'ORIGINAL');
	$r = BackupPlugin::restoreArchive($zip([
		'configs/application.ini' => "[x]\n",
		'plugins/p/index.php' => '<?php system($_GET[0]);',
		'plugins/p/config.json' => '{}',
	]), APP_PRIVATE_DATA);
	check(is_array($r) && 2 === $r['restored'] && ['plugins/p/index.php'] === $r['skipped'], 'unexpected restore result');
	check('ORIGINAL' === file_get_contents(APP_PRIVATE_DATA . 'plugins/p/index.php'), 'PHP overwritten');
	check(is_file(APP_PRIVATE_DATA . 'configs/application.ini'), 'data entry not restored');

	// Not a zip (client MIME is irrelevant now).
	file_put_contents($sBase . '/not.zip', 'hello');
	check(false === BackupPlugin::restoreArchive($sBase . '/not.zip', APP_PRIVATE_DATA), 'non-zip accepted');

	exec('rm -rf ' . escapeshellarg($sBase));
	echo "backup-restore: ok ({$iChecks} checks)\n";
}
