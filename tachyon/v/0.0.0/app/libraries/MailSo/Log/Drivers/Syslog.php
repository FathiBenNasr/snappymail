<?php

/*
 * This file is part of MailSo.
 *
 * (c) 2014 Usenko Timur
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace MailSo\Log\Drivers;

/**
 * @category MailSo
 * @package Log
 * @subpackage Drivers
 */
class Syslog extends \MailSo\Log\Driver
{
	private bool $bAvailable = false;

	function __construct()
	{
		parent::__construct();

		$this->bAvailable = \is_callable('openlog');
	}

	/**
	 * With the message's own severity, not a fixed one. Everything used to go out
	 * as LOG_INFO whatever it was, so an error and a debug line reached syslog at
	 * the same priority and filtering on it did nothing, which is most of the
	 * reason to send logs there at all (#163).
	 */
	protected function writeImplementation($mDesc, int $iType = \LOG_INFO) : bool
	{
		$result = false;
		if ($this->bAvailable && \openlog(\Tachyon\Util\Log::ident(), LOG_ODELAY, LOG_USER)) {
			$result = \syslog(
				isset(static::PREFIXES[$iType]) ? $iType : \LOG_INFO,
				\is_array($mDesc) ? \implode(PHP_EOL, $mDesc) : $mDesc
			);
			\closelog();
		}
		return $result;
	}

	protected function clearImplementation() : bool
	{
		return true;
	}
}
