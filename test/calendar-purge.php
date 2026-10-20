<?php

// Run with: php test/calendar-purge.php
define('APP_VERSION', 'test');
spl_autoload_register(static function (string $class): void {
	if (str_starts_with($class, 'Tachyon\\Util\\')) {
		$file = dirname(__DIR__).'/tachyon/v/0.0.0/app/libraries/tachyon_util/'.strtolower(str_replace('\\', '/', substr($class, 13))).'.php';
	} else {
		$file = dirname(__DIR__).'/tachyon/v/0.0.0/app/libraries/'.str_replace('\\', '/', $class).'.php';
	}
	if (is_file($file)) {
		require_once $file;
	}
});

function check(bool $condition, string $message): void
{
	if (!$condition) {
		throw new RuntimeException($message);
	}
}

use Tachyon\Providers\Calendar\PdoCalendar;

$rows = [
	['id_calendar' => 1, 'dav_path' => '/remote.php/dav/public-calendars/abc123/'],
	['id_calendar' => 2, 'dav_path' => '/remote.php/dav/calendars/kim/personal/'],
	['id_calendar' => 3, 'dav_path' => '/remote.php/dav/calendars/kim/work/']
];

// Discovery still returns everything: nothing goes.
check(PdoCalendar::calendarsToPurge($rows, [
	'/remote.php/dav/public-calendars/abc123/',
	'/remote.php/dav/calendars/kim/personal/',
	'/remote.php/dav/calendars/kim/work/'
]) === [], 'a normal sync would delete calendars that are still there');

// The reported case: the URL moved from one public calendar to the DAV root, so
// the public collection is no longer listed and only it should go.
check(PdoCalendar::calendarsToPurge($rows, [
	'/remote.php/dav/calendars/kim/personal/',
	'/remote.php/dav/calendars/kim/work/'
]) === [1], 'the calendar of the old URL survived the change');

// Switched off, or the URL cleared.
check(PdoCalendar::calendarsToPurge($rows, []) === [1, 2, 3], 'clearing the URL left calendars behind');

// A trailing slash on one side only is the same collection.
check(PdoCalendar::calendarsToPurge(
	[['id_calendar' => 7, 'dav_path' => '/dav/calendars/kim/personal/']],
	['/dav/calendars/kim/personal']
) === [], 'a missing trailing slash was read as a different calendar');

check(PdoCalendar::calendarsToPurge(
	[['id_calendar' => 7, 'dav_path' => '/dav/calendars/kim/personal']],
	['/dav/calendars/kim/personal/']
) === [], 'a trailing slash on the remote side was read as a different calendar');

// A prefix is not a match: /work must not keep /workshop alive, or the reverse.
check(PdoCalendar::calendarsToPurge(
	[['id_calendar' => 8, 'dav_path' => '/dav/calendars/kim/workshop/']],
	['/dav/calendars/kim/work/']
) === [8], 'a calendar whose path merely shares a prefix was kept');

// A row written before dav_path existed, or one left empty, is not a collection
// any discovery can return, so it goes with the rest.
check(PdoCalendar::calendarsToPurge(
	[['id_calendar' => 9, 'dav_path' => '']],
	['/dav/calendars/kim/personal/']
) === [9], 'a calendar with no path was kept');

// A flagged row and an unflagged one are both "not in the keep list". The caller
// tells them apart by the deleted column, which is what makes a miss take two
// runs; calendarsToPurge() itself must report both.
$mixed = [
	['id_calendar' => 4, 'dav_path' => '/dav/calendars/kim/gone/', 'deleted' => 1],
	['id_calendar' => 5, 'dav_path' => '/dav/calendars/kim/missing/', 'deleted' => 0]
];
check(PdoCalendar::calendarsToPurge($mixed, []) === [4, 5], 'the deleted flag changed which rows were reported');

echo "calendar-purge: ok\n";
