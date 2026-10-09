<?php
/**
 * S-14 (audit 2026-10): the plugin JS and CSS bundles are cached under a key
 * that must carry the admin/user scope, or an anonymous GET of the admin bundle
 * on a cold cache is served to every user.
 * Run with: php test/plugins-cache-scope.php
 */
define('APP_VERSION', '2.38.2');
$dir = dirname(__DIR__) . '/snappymail/v/0.0.0/app/libraries/RainLoop/';
require $dir . 'KeyPathHelper.php';
use RainLoop\KeyPathHelper;

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

$sHash = 'abc123';
check(KeyPathHelper::PluginsJsCache($sHash, true) !== KeyPathHelper::PluginsJsCache($sHash, false),
	'admin and user JS bundles share a cache key');
check(KeyPathHelper::CssCache($sHash, 'Convergent', true) !== KeyPathHelper::CssCache($sHash, 'Convergent', false),
	'admin and user CSS share a cache key');
check(KeyPathHelper::CssCache($sHash, 'A', false) !== KeyPathHelper::CssCache($sHash, 'B', false),
	'themes share a cache key');
check(KeyPathHelper::PluginsJsCache('h1', false) !== KeyPathHelper::PluginsJsCache('h2', false),
	'plugin hash missing from the key');

// The service must pass the scope it compiles with: read the source, since
// ServicePlugins()/ServiceCss() need the whole application to run.
$sSource = file_get_contents($dir . 'ServiceActions.php');
check(1 === preg_match_all('/KeyPathHelper::PluginsJsCache\([^;]*,\s*\$bAdmin\)/', $sSource),
	'ServicePlugins does not key the cache by scope');
check(1 === preg_match_all('/KeyPathHelper::CssCache\([^;]*,\s*\$bAdmin\)/', $sSource),
	'ServiceCss does not key the cache by scope');
check(!str_contains($sSource, "'/CssCache/'"), 'a hand-written CssCache key is back');
check(1 === substr_count($sSource, 'PluginsJsCache('), 'an unscoped PluginsJsCache call is back');

echo "plugins-cache-scope: ok ({$iChecks} checks)\n";
