<?php

class BackupPlugin extends \RainLoop\Plugins\AbstractPlugin
{
	const
		NAME     = 'Backup',
		AUTHOR   = 'SnappyMail',
		URL      = 'https://snappymail.eu/',
		VERSION  = '1.3',
		RELEASE  = '2026-10-09',
		REQUIRED = '2.30.0',
		CATEGORY = 'General',
		LICENSE  = 'MIT',
		DESCRIPTION = '';

	public function Init() : void
	{
		// Admin Settings tab
		$this->addJs('js/BackupAdminSettings.js', true); // add js file
		$this->addJsonHook('JsonAdminBackupData');
		$this->addJsonHook('JsonAdminRestoreData');
		$this->addTemplate('templates/BackupAdminSettingsTab.html', true);
	}

	/**
	 * WHY (S-01, audit 2026-10): the core's admin guard only covers actions
	 * whose name starts with "Admin"; plugin actions are "Plugin…", so it never
	 * runs for them, and ActionsAdmin is built from the URL alone, for an
	 * anonymous visitor too. Every admin action of this plugin must therefore
	 * prove the admin session itself. Fail closed: IsAdminLoggined(false)
	 * never throws, and anything but true is a refusal.
	 */
	private function adminLoggedIn() : bool
	{
		$oActions = $this->Manager()->Actions();
		return $oActions instanceof \RainLoop\ActionsAdmin
			&& true === $oActions->IsAdminLoggined(false);
	}

	public function JsonAdminBackupData()
	{
		if (!$this->adminLoggedIn()) {
			return $this->jsonResponse(__FUNCTION__, false);
		}

		\file_put_contents(APP_PRIVATE_DATA.'cache/CACHEDIR.TAG', 'Signature: 8a477f597d28d172789f06886806bc55');

		$sFileName = APP_PRIVATE_DATA . \MailSo\Base\Utils::Sha1Rand();

		if (true) {
			$sType = 'application/zip';
			$sFileName .= '.zip';
			if (\class_exists('ZipArchive')) {
//				$oArchive = new \ZipArchive();
//				$oArchive->open($sFileName, \ZIPARCHIVE::CREATE | \ZIPARCHIVE::OVERWRITE);
//				$oArchive->setArchiveComment('SnappyMail/'.APP_VERSION);
			}
			$oArchive = new \SnappyMail\Stream\ZIP($sFileName);
		} else {
			$sType = 'application/x-gzip';
			$sFileName .= '.tgz';
			$oArchive = new \SnappyMail\Stream\TAR($sFileName);
		}

//		$oArchive->addRecursive(APP_PRIVATE_DATA, '#/(cache.*)#');
		$oArchive->addRecursive(APP_PRIVATE_DATA.'configs', 'configs');
		$oArchive->addRecursive(APP_PRIVATE_DATA.'domains', 'domains');
		$oArchive->addRecursive(APP_PRIVATE_DATA.'plugins', 'plugins');
		$oArchive->addRecursive(APP_PRIVATE_DATA.'storage', 'storage');
		if (\is_readable(APP_PRIVATE_DATA.'AddressBook.sqlite')) {
			$oArchive->addFile(APP_PRIVATE_DATA.'AddressBook.sqlite');
		}
//		$oArchive->addFile(APP_DATA_FOLDER_PATH.'SALT.php');
		$oArchive->close();

		$data = \base64_encode(\file_get_contents($sFileName));
		\unlink($sFileName);

		return $this->jsonResponse(__FUNCTION__, array(
			'name' => \basename($sFileName),
			'data' => "data:{$sType};base64,{$data}"
		));
	}

	public function JsonAdminRestoreData()
	{
		// The session first, before looking at anything the request carries.
		// The client-sent MIME type is not checked: it proves nothing, and
		// ZipArchive::open() below is what decides whether this is a zip.
		if (!$this->adminLoggedIn()
		 || empty($_FILES['backup']['tmp_name'])
		 || !\is_uploaded_file($_FILES['backup']['tmp_name'])
		) {
			return $this->jsonResponse(__FUNCTION__, false);
		}

		return $this->jsonResponse(__FUNCTION__,
			static::restoreArchive($_FILES['backup']['tmp_name'], APP_PRIVATE_DATA));
	}

	/** What a backup made by JsonAdminBackupData() contains, and nothing else. */
	const RESTORE_ROOTS = ['configs/', 'domains/', 'plugins/', 'storage/'];
	const RESTORE_FILES = ['AddressBook.sqlite'];

	/**
	 * Why an archive entry may not be written at all, or null when its path is
	 * acceptable. Any refusal rejects the whole archive.
	 * WHY: ZipArchive::extractTo() writes "../x" and "/x" outside the target
	 * (zip slip); a symbolic link entry would redirect later writes; a path
	 * outside the four backup folders has no business in APP_PRIVATE_DATA.
	 */
	public static function restoreEntryRefusal(string $sName, int $iExternalAttributes = 0, int $iOpSys = 0) : ?string
	{
		if ('' === $sName || \strlen($sName) > 1024
		 || \preg_match('/[\x00-\x1F\x7F\\\\:]/', $sName)) {
			return 'invalid name';
		}
		if ('/' === $sName[0]) {
			return 'absolute path';
		}
		foreach (\explode('/', $sName) as $sSegment) {
			if ('..' === $sSegment || '.' === $sSegment) {
				return 'path traversal';
			}
		}
		// Unix mode in the upper 16 bits: S_IFLNK is 0120000.
		if (\ZipArchive::OPSYS_UNIX === $iOpSys && 0120000 === (($iExternalAttributes >> 16) & 0170000)) {
			return 'symbolic link';
		}
		if (\in_array($sName, static::RESTORE_FILES, true)) {
			return null;
		}
		foreach (static::RESTORE_ROOTS as $sRoot) {
			if (\str_starts_with($sName, $sRoot)) {
				return null;
			}
		}
		return 'outside the backup folders';
	}

	/**
	 * Whether an acceptable entry is code or server configuration, which a
	 * restore never writes: an uploaded archive must not become executable
	 * PHP (plugins/<name>/index.php is loaded on every request).
	 */
	public static function restoreEntryIsCode(string $sName) : bool
	{
		$sBase = \strtolower(\basename($sName));
		return (bool) \preg_match('/\.(php\d*|phtml|phar|phps|pht|inc)$/', $sBase)
			|| \str_starts_with($sBase, '.ht')
			|| '.user.ini' === $sBase;
	}

	/**
	 * Validate every entry, then extract only data entries. Nothing is
	 * written unless the whole archive passes.
	 * @return false|array ['restored' => int, 'skipped' => string[]]
	 */
	public static function restoreArchive(string $sZip, string $sTarget)
	{
		if (!\class_exists('ZipArchive')) {
			// The former PharData fallback used an undefined variable; fail closed.
			return false;
		}
		$oArchive = new \ZipArchive();
		if (true !== $oArchive->open($sZip, \ZipArchive::RDONLY | \ZipArchive::CHECKCONS)) {
			return false;
		}
		$aExtract = [];
		$aSkipped = [];
		for ($i = 0; $i < $oArchive->numFiles; ++$i) {
			$sName = $oArchive->getNameIndex($i);
			$iOpSys = $iAttr = 0;
			if (!\is_string($sName)
			 || !$oArchive->getExternalAttributesIndex($i, $iOpSys, $iAttr)
			 || null !== static::restoreEntryRefusal($sName, $iAttr, $iOpSys)
			) {
				$oArchive->close();
				return false;
			}
			if (\str_ends_with($sName, '/')) {
				continue; // directories are created as needed
			}
			if (static::restoreEntryIsCode($sName)) {
				$aSkipped[] = $sName;
				continue;
			}
			$aExtract[] = $sName;
		}
		$bResult = !$aExtract || $oArchive->extractTo($sTarget, $aExtract);
		$oArchive->close();
		return $bResult ? ['restored' => \count($aExtract), 'skipped' => $aSkipped] : false;
	}

}
