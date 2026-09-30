<?php

namespace Tachyon\Util\HTTP;

abstract class Request
{
	const
		/**
		 * Authentication
		 * These are bitwise options
		 */
		AUTH_BASIC = 1,
		AUTH_DIGEST = 2,
		AUTH_BEARER = 4;

	public
		$timeout = 5, // timeout in seconds.
		$max_response_kb = 1024,
		$user_agent,
		$max_redirects = 0,
		$verify_peer = false,
		$proxy = null,
		$proxy_auth = null,
		// When true, refuse to fetch URLs whose host resolves to a
		// private, reserved, loopback or link-local IP. Enable for
		// request paths where the URL is attacker-influenced.
		$block_private_ips = false;

	protected
		$auth = [
			'type' => 0,
			'user' => '',
			'pass' => ''
		],
		$stream = null,
		$headers = array(),
		$ca_bundle = null;

	protected static $scheme_ports = array(
		'http'  => 80,
		'https' => 443
	);

	public static function factory(string $type = 'curl')
	{
		if ('curl' === $type && \function_exists('curl_init')) {
			return new Request\CURL();
		}
		return new Request\Socket();
	}

	function __construct()
	{
		$this->user_agent = 'Tachyon/' . APP_VERSION;
	}

	public function setAuth(int $type, string $user,
		#[\SensitiveParameter]
		string $pass
	) : void
	{
		$this->auth = [
			'type' => $type,
			'user' => $user,
			'pass' => $pass
		];
	}

	public function addHeader($header)
	{
		$this->headers[] = $header;
		return $this;
	}

	public function streamBodyTo($stream)
	{
		if (!\is_resource($stream)) {
			throw new \Exception('Invalid body target');
		}
		$this->stream = $stream;
	}

	public function setCABundleFile($file)
	{
		$this->ca_bundle = $file;
	}

	/**
	 * Return whether a URI can be fetched.  Returns false if the URI scheme is not allowed
	 * or is not supported by this fetcher implementation; returns true otherwise.
	 *
	 * @return bool
	 */
	public function canFetchURI($uri)
	{
		if ('https:' === \substr($uri, 0, 6) && !$this->supportsSSL()) {
			\trigger_error('HTTPS URI unsupported fetching '.$uri, E_USER_WARNING);
			return false;
		}
		if (!self::URIHasAllowedScheme($uri)) {
			\trigger_error('URI fetching not allowed for '.$uri, E_USER_WARNING);
			return false;
		}
		if ($this->block_private_ips && !self::URIHasPublicHost($uri)) {
			\trigger_error('URI host is not a public IP for '.$uri, E_USER_WARNING);
			return false;
		}
		return true;
	}

	/**
	 * Whether the URI host resolves exclusively to public IPs.
	 * Blocks literal private/reserved/loopback/link-local IPs (including
	 * decimal-dottedless forms like http://2130706433/ and bracketed IPv6
	 * like http://[::1]/) as well as hostnames that resolve to one. Fails
	 * closed when the host cannot be resolved. Note: this is a pre-request
	 * check; a hostile DNS that rebinds between check and connect (TOCTOU)
	 * is not covered.
	 */
	public static function URIHasPublicHost(string $uri) : bool
	{
		$host = \parse_url($uri, PHP_URL_HOST);
		if (!\is_string($host) || '' === $host) {
			return false;
		}
		// Bracketed IPv6 literals (http://[::1]/): parse_url keeps the
		// brackets, which filter_var rejects, so strip them first.
		if (\str_starts_with($host, '[') && \str_ends_with($host, ']')) {
			$host = \substr($host, 1, -1);
		}
		// Decimal-dottedless IPv4 literals (http://2130706433/ == 127.0.0.1).
		// Note: ip2long() does NOT parse this form (it returns false), so
		// convert the 32-bit value directly.
		if (\preg_match('/^[0-9]+$/', $host)) {
			$long = (int) $host;
			if ($long >= 0 && $long <= 4294967295) {
				$host = \long2ip($long);
			}
		}
		$flags = FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE;
		if (\filter_var($host, FILTER_VALIDATE_IP, $flags)) {
			return true;
		}
		if (\filter_var($host, FILTER_VALIDATE_IP)) {
			return false; // literal non-public IP
		}
		$ips = array();
		foreach (\dns_get_record($host, DNS_A + DNS_AAAA) ?: array() as $record) {
			if (!empty($record['ip'])) {
				$ips[] = $record['ip'];
			}
			if (!empty($record['ipv6'])) {
				$ips[] = $record['ipv6'];
			}
		}
		if (!$ips) {
			$ips = \gethostbynamel($host) ?: array();
		}
		if (!$ips) {
			return false; // fail closed on unresolvable hosts
		}
		foreach ($ips as $ip) {
			if (!\filter_var($ip, FILTER_VALIDATE_IP, $flags)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Does this fetcher implementation (and runtime) support fetching HTTPS URIs?
	 * May inspect the runtime environment.
	 *
	 * @return bool $support True if this fetcher supports HTTPS
	 * fetching; false if not.
	 */
	abstract public function supportsSSL() : bool;

	abstract protected function __doRequest(string &$method, string &$request_url, &$body, array $extra_headers) : Response;

	public function doRequest($method, $request_url, /*string|array*/$body = null, array $extra_headers = array()) : ?Response
	{
		$method = \strtoupper($method);
		$url    = $request_url;
		$etime  = \time() + $this->timeout;
		$redirects = \max(0, $this->max_redirects);
		if (\is_array($body)) {
			$body = \http_build_query($body, '', '&');
		}
		if ($body && 'GET' === $method) {
			$url .= (\strpos($url, '?') ? '&' : '?') . $body;
			$body = null;
		}
		do
		{
			if (!$this->canFetchURI($url)) {
				throw new \RuntimeException("Can't fetch URL: {$url}");
			}

			if (!self::URIHasAllowedScheme($url)) {
				throw new \RuntimeException("Fetching URL not allowed: {$url}");
			}

			$this->stream && \rewind($this->stream);
			$result = $this->__doRequest($method, $url, $body, \array_merge($this->headers, $extra_headers));

			// http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html#sec10.3
			// In response to a request other than GET or HEAD, the user agent MUST NOT
			// automatically redirect the request unless it can be confirmed by the user
			if ($redirects-- && \in_array($result->status, array(301, 302, 303, 307)) && \in_array($method, ['GET','HEAD'])) {
				$url = $result->getRedirectLocation();
			} else {
				$result->final_uri = $url;
				$result->request_uri = $request_url;
				return $result;
			}

		} while ($etime-time() > 0);

		return null;
	}

	/**
	 * Return whether a URI should be allowed. Override this method to conform to your local policy.
	 * By default, will attempt to fetch any http or https URI.
	 */
	public static function URIHasAllowedScheme($uri) : bool
	{
		return (bool) \preg_match('#^https?://#i', $uri);
	}

	public static function getSchemePort($scheme) : int
	{
		return self::$scheme_ports[$scheme] ?? 0;
	}
}
