<?php

// Run with: php test/addressbook-sync-guards.php
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

use Tachyon\Providers\AddressBook\PdoAddressBook;

$live    = ['a' => ['deleted' => 0, 'etag' => 'e1', 'id_contact' => 1], 'b' => ['deleted' => 0, 'etag' => 'e2', 'id_contact' => 2]];
$remote  = ['a' => ['vcf' => 'a.vcf'], 'b' => ['vcf' => 'b.vcf']];

// Both sides populated: nothing is protected, sync deletes as before.
check(PdoAddressBook::syncDeletionGuards($live, $remote) === [false, false], 'a normal sync was blocked');

// Empty remote listing while local holds contacts: keep local.
check(PdoAddressBook::syncDeletionGuards($live, []) === [false, true], 'an empty remote listing would delete every local contact');

// Empty (fresh or rebuilt) local store while remote holds contacts: keep remote.
check(PdoAddressBook::syncDeletionGuards([], $remote) === [true, false], 'an empty local store would delete every remote contact');

// Local entries only marked deleted are not live contacts.
$onlyDeleted = ['a' => ['deleted' => 1, 'etag' => 'e1', 'id_contact' => 1]];
check(PdoAddressBook::syncDeletionGuards($onlyDeleted, $remote) === [true, false], 'deleted markers counted as live contacts');

// Both empty: nothing to protect.
check(PdoAddressBook::syncDeletionGuards([], []) === [false, false], 'two empty sides were treated as a fault');

echo "addressbook-sync-guards: ok\n";
