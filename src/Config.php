<?php
namespace Spaze\ContentSecurityPolicy;

use Nette\DI\Config\Helpers;

/**
 * ContentSecurityPolicy\Config service.
 *
 * @author Michal Špaček
 */
class Config
{

	/** @internal configuration key for default values */
	const DEFAULT_KEY = '*';

	/** @internal configuration key separator */
	const KEY_SEPARATOR = '.';

	/** @var array of key => array of policies */
	protected $policy = array();

	/** @var array of name => array of policies */
	protected $snippets = array();

	/** @var array of directive => add? */
	protected $addNonce = array();

	/** @var array of directive => add? */
	protected $addStrictDynamic = array();

	/** @var array of snippet names */
	protected $currentSnippets = array();

	/** @var boolean */
	protected $supportLegacyBrowsers = false;

	/** @var array */
	protected $directives = array();

	/** @var string */
	protected $nonce;


	/**
	 * Set policy.
	 *
	 * @param array (key => array of policies)
	 * @return self
	 */
	public function setPolicy(array $policy)
	{
		foreach ($policy as $key => $sources) {
			$this->policy[$key] = $sources;
		}
		return $this;
	}


	/**
	 * Set policy snippets.
	 *
	 * @param array (key => array of policies)
	 * @return self
	 */
	public function setSnippets(array $snippets)
	{
		$this->snippets = $snippets;
		return $this;
	}


	/**
	 * Set directives to which add nonce.
	 *
	 * @param array of directive => add?
	 * @return self
	 */
	public function setAddNonce(array $addNonce)
	{
		$this->addNonce = $addNonce;
		return $this;
	}


	/**
	 * Set directives to which add 'strict-dynamic'.
	 *
	 * @param array of directive => add?
	 * @return self
	 */
	public function setAddStrictDynamic(array $addStrictDynamic)
	{
		$this->addStrictDynamic = $addStrictDynamic;
		return $this;
	}


	/**
	 * Get Content-Security-Policy header value.
	 *
	 * @param  string $presenter
	 * @param  string $action
	 * @return string
	 */
	public function getHeader($presenter, $action)
	{
		$this->directives = array();

		$configKey = $this->findConfigKey($presenter, $action);
		if (isset($this->policy[$configKey][Helpers::EXTENDS_KEY])) {
			$currentPolicy = Helpers::merge($this->policy[$configKey], $this->policy[$this->policy[$configKey][Helpers::EXTENDS_KEY]]);
			unset($currentPolicy[Helpers::EXTENDS_KEY]);
		} else {
			$currentPolicy = $this->policy[$configKey];
		}
		foreach ($this->currentSnippets as $snippetName) {
			foreach ($this->snippets[$snippetName] as $directive => $sources) {
				$currentPolicy[$directive] = (isset($currentPolicy[$directive]) ? array_merge((array)$currentPolicy[$directive], $sources) : $sources);
			}
		}

		foreach ($currentPolicy as $directive => $sources) {
			$this->addDirective($directive, (array)$sources);
		}
		return implode('; ', $this->directives);
	}


	/**
	 * Add named snippet to current CSP config.
	 *
	 * @param string $snippetName
	 * @return self
	 */
	public function addSnippet($snippetName)
	{
		$this->currentSnippets[] = $snippetName;
		return $this;
	}


	/**
	 * Find CSP policy config key.
	 *
	 * @param  string $presenter
	 * @param  string $action
	 * @return string
	 */
	private function findConfigKey($presenter, $action)
	{
		$parts = explode(':', strtolower($presenter));
		$parts[] = strtolower($action);
		for ($i = count($parts) - 1; $i >= 0; $i--) {
			if (isset($this->policy[implode(self::KEY_SEPARATOR, $parts)])) {
				break;
			}
			$parts[$i] = self::DEFAULT_KEY;
		}
		return implode(self::KEY_SEPARATOR, $parts);
	}


	/**
	 * Format and add a directive.
	 *
	 * @param string $name
	 * @param array $sources
	 */
	private function addDirective($name, array $sources)
	{
		$values = (isset($this->addNonce[$name]) && $this->addNonce[$name] ? "'nonce-" . $this->getNonce() . "' " : '');
		$values .= (isset($this->addStrictDynamic[$name]) && $this->addStrictDynamic[$name]	? "'strict-dynamic' " : '');
		foreach ($sources as &$source) {
			$values .= $source . ' ';
		}
		$this->directives[$name] = trim("$name $values");
		if ($name === 'child-src' && $this->supportLegacyBrowsers) {
			$this->directives['frame-src'] = trim("frame-src $values");
		}
	}


	/**
	 * Get nonce.
	 *
	 * @return string
	 */
	public function getNonce()
	{
		if ($this->nonce === null) {
			$this->nonce = base64_encode(random_bytes(16));
		}
		return $this->nonce;
	}


	/**
	 * Get default config key.
	 *
	 * @return string
	 */
	public function getDefaultKey()
	{
		return self::DEFAULT_KEY;
	}


	/**
	 * Enable legacy browser (i.e. Safari) support
	 *
	 * @return self
	 */
	public function supportLegacyBrowsers()
	{
		$this->supportLegacyBrowsers = true;
		return $this;
	}

}
