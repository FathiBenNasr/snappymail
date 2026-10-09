<?php

namespace RainLoop;

class KeyPathHelper
{
	static public function SsoCacherKey(string $sSsoHash) : string
	{
		return '/Sso/Data/'.$sSsoHash.'/Login/';
	}

	static public function ReadReceiptCache(string $sEmail, string $sFolderFullName, int $iUid) : string
	{
		return '/ReadReceipt/'.$sEmail.'/'.$sFolderFullName.'/'.$iUid;
	}

	static public function LangCache(string $sLanguage, bool $bAdmim, string $sPluginsHash) : string
	{
		return '/LangCache/'.$sPluginsHash.'/'.$sLanguage.'/'.($bAdmim ? 'Admin' : 'App').'/'.APP_VERSION.'/';
	}

	/**
	 * WHY (S-14, audit 2026-10): CompileJs($bAdmin) and compileCss($sTheme,
	 * $bAdmin) produce a different bundle per scope, and the scope comes from
	 * the URL of an unauthenticated request. Without it in the key, one
	 * anonymous GET /?/Plugins/0/Admin/ on a cold cache stored the admin
	 * bundle where every user's page reads its own, until the next flush.
	 * The scope is part of what the content is, so it is part of its key.
	 */
	static public function PluginsJsCache(string $sPluginsHash, bool $bAdmin) : string
	{
		return '/PluginsJsCache/'.$sPluginsHash.'/'.($bAdmin ? 'Admin' : 'App').'/'.APP_VERSION.'/';
	}

	static public function CssCache(string $sPluginsHash, string $sTheme, bool $bAdmin) : string
	{
		return '/CssCache/'.$sPluginsHash.'/'.$sTheme.'/'.($bAdmin ? 'Admin' : 'App').'/'.APP_VERSION.'/';
	}

	static public function SessionAdminKey(string $sRand) : string
	{
		return '/Session/AdminKey/'.\md5($sRand).'/';
	}
}
