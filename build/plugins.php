<?php
define('PLUGINS_DEST_DIR', __DIR__ . '/dist/releases/plugins');

is_dir(PLUGINS_DEST_DIR) || mkdir(PLUGINS_DEST_DIR, 0777, true);
$files = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator(PLUGINS_DEST_DIR, RecursiveDirectoryIterator::SKIP_DOTS),
    RecursiveIteratorIterator::CHILD_FIRST
);
foreach ($files as $fileinfo) {
    $fileinfo->isDir() || unlink($fileinfo->getRealPath());
}

$terser = ROOT_DIR . '/node_modules/terser/bin/terser';

// Use /releases/latest/download/ so packages.json never has stale version-pinned URLs
$releaseTag = $options['release-tag'] ?? null;
$githubBase = $releaseTag
	? "https://github.com/kimusan/Tachyon/releases/latest/download/"
	: null;

$manifest = [];

/**
 * Hash of everything a human or Weblate can change in a plugin. Derived files are
 * left out: the .min.js are regenerated during this build, so including them
 * would make the hash depend on the minifier rather than on the plugin.
 */
function plugin_content_sha(string $dir) : string
{
	$files = [];
	$it = new RecursiveIteratorIterator(
		new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS));
	foreach ($it as $file) {
		$path = str_replace('\\', '/', $file->getPathname());
		if ($file->isFile()
		 && !preg_match('/\.(min\.(js|css)|bak)$/', $path)
		 && !str_contains($path, '/.git')) {
			$files[$path] = sha1_file($path);
		}
	}
	ksort($files);
	return sha1(json_encode($files));
}

/**
 * The version to publish: whatever the plugin declares, plus a build number that
 * rises each time its contents change.
 *
 * Weblate merges a translation into plugins/x/langs/ and never touches index.php,
 * so the declared version stays put. packages.json then advertises a version the
 * install already has, repository.php finds canBeUpdated false, and the admin
 * panel offers nothing. The translation sits in the package, unreachable.
 *
 * The previous state comes from the committed packages.json, so this needs no git
 * and works the same in a shallow clone or a Docker context without .git.
 */
function plugin_publish_version(string $declared, string $sha, ?array $previous) : string
{
	$build = 0;
	if ($previous && preg_match('/^' . preg_quote($declared, '/') . '(?:\.(\d+))?$/', (string) ($previous['version'] ?? ''), $m)) {
		// Same declared version as last time, so carry its build number and move
		// it on only if the contents actually differ.
		$build = (int) ($m[1] ?? 0);
		// An entry from before this existed has no hash to compare against. Adopt
		// the current one rather than bumping, or the first release after this
		// would advertise an update for every plugin at once and mean nothing by
		// any of them. Anything genuinely pending is bumped by hand instead.
		if (isset($previous['sha']) && $sha !== $previous['sha']) {
			++$build;
		}
	}
	// A previous version that does not match means the author bumped the real
	// version, which supersedes any build number we had added to the old one.
	return $build ? "{$declared}.{$build}" : $declared;
}

// Previously published state, to tell whether a plugin's contents moved. Read
// before anything writes over it further down.
$published = [];
if (is_file(ROOT_DIR . '/packages.json')) {
	foreach (json_decode((string) file_get_contents(ROOT_DIR . '/packages.json'), true) ?: [] as $item) {
		if (!empty($item['id'])) {
			$published[$item['id']] = $item;
		}
	}
}

// Load AbstractPlugin so plugin classes can extend it
if (is_file(ROOT_DIR . '/tachyon/v/0.0.0/app/libraries/Tachyon/Plugins/AbstractPlugin.php')) {
	require ROOT_DIR . '/tachyon/v/0.0.0/app/libraries/Tachyon/Plugins/AbstractPlugin.php';
	// Alias for plugins that still use the RainLoop namespace
	class_alias(\Tachyon\Plugins\AbstractPlugin::class, \RainLoop\Plugins\AbstractPlugin::class);
} else {
	require ROOT_DIR . '/tachyon/v/0.0.0/app/libraries/RainLoop/Plugins/AbstractPlugin.php';
}

// Reading a plugin's metadata means declaring its class, and a trait it composes
// has to exist by then. There is no autoloader here, so the traits under Plugins/
// are loaded up front. Only traits: the classes beside them compose things of
// their own from elsewhere in the tree, so requiring those would just move the
// problem (Manager needs MailSo\Log\Inherit, for one), and a plugin cannot "use"
// a class anyway.
foreach (glob(ROOT_DIR . '/tachyon/v/0.0.0/app/libraries/Tachyon/Plugins/*.php') as $file) {
	preg_match('/^\s*trait\s+\w/m', file_get_contents($file)) && require_once $file;
}

$keys = [
	'author',
	'category',
	'description',
	'file',
	'id',
	'license',
	'name',
	'release',
	'required',
	'type',
	'url',
	'version'
];

foreach (glob(ROOT_DIR . '/plugins/*', GLOB_NOSORT | GLOB_ONLYDIR) as $dir) {
	if (is_file("{$dir}/index.php") && !strpos($dir, '.bak')) {
		require "{$dir}/index.php";
		$name = basename($dir);
		$class = new ReflectionClass(str_replace('-', '', $name) . 'Plugin');
		$manifest_item = [];
		foreach ($class->getConstants() as $key => $value) {
			$key = \strtolower($key);
			if (in_array($key, $keys)) {
				$manifest_item[$key] = $value;
			}
		}
		$declared = $manifest_item['version'] ?? '0';
		if (0 < floatval($declared)) {
			$sha = plugin_content_sha($dir);
			$version = plugin_publish_version($declared, $sha, $published[$name] ?? null);
			$manifest_item['version'] = $version;
			$manifest_item['sha'] = $sha;
			echo "+ {$name} {$version}" . ($version === $declared ? '' : " (declared {$declared})") . "\n";

			// Minify JavaScript
			foreach (glob("{$dir}/*.js") as $file) {
				if (!strpos($file,'.min')) {
					$mfile = str_replace('.js', '.min.js', $file);
					passthru("{$terser} {$file} --output {$mfile} --compress 'drop_console' --ecma 6 --mangle");
				}
			}
			foreach (glob("{$dir}/js/*.js") as $file) {
				if (!strpos($file,'.min')) {
					$mfile = str_replace('.js', '.min.js', $file);
					passthru("{$terser} {$file} --output {$mfile} --compress 'drop_console' --ecma 6 --mangle");
				}
			}

			$archive = "{$name}-{$version}.tgz";
			$manifest_item['type'] = 'plugin';
			$manifest_item['id']   = $name;
			$manifest_item['file'] = $githubBase
				? $githubBase . $archive
				: "plugins/{$archive}";

			$tar_destination = PLUGINS_DEST_DIR . "/{$name}-{$version}.tar";
			$tgz_destination = PLUGINS_DEST_DIR . "/{$archive}";
			@unlink($tgz_destination);
			@unlink("{$tar_destination}.gz");
			$tar = new PharData($tar_destination);
			$tar->buildFromDirectory('./plugins/', '/' . \preg_quote("./plugins/{$name}/", '/') . '((?!\.bak).)*$/');
			$tar->compress(Phar::GZ);
			unlink($tar_destination);
			rename("{$tar_destination}.gz", $tgz_destination);

			if (isset($options['sign'])) {
				passthru('gpg --local-user ' . escapeshellarg(SIGNING_KEY) . ' --armor --detach-sign '.escapeshellarg($tgz_destination), $return_var);
				$manifest_item['pgp_sig'] = trim(preg_replace('/-----(BEGIN|END) PGP SIGNATURE-----/', '', file_get_contents($tgz_destination.'.asc')));
			}
			ksort($manifest_item);
			$manifest[$name] = $manifest_item;

		} else {
			echo "- {$name} {$declared}\n";
		}
	} else {
		echo "- " . basename($dir) . "\n";
	}
}

ksort($manifest);
$json = json_encode(array_values($manifest), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

// Write to build output dir
file_put_contents(dirname(PLUGINS_DEST_DIR) . '/packages.json', $json . "\n");

// Also write to repo root so raw.githubusercontent.com serves the current version
file_put_contents(ROOT_DIR . '/packages.json', $json . "\n");
echo "packages.json written (" . count($manifest) . " plugins)\n";

return;
