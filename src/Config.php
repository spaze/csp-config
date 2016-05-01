<?php
namespace Spaze\ContentSecurityPolicy;

/**
 * ContentSecurityPolicy\Config service.
 *
 * @author Michal Špaček
 */
class Config
{

	/** @internal configuration key for default values */
	const DEFAULT_KEY = 'DEFAULT';

	/** @var array of key => array of policies */
	protected $policy = array();

	/** @var array of name => array of policies */
	protected $snippets = array();

	/** @var array of snippet names */
	protected $currentSnippets = array();

	/** @var boolean */
	protected $supportLegacyBrowsers = false;

	/** @var array */
	protected $directives = array();


	/**
	 * Set policy.
	 *
	 * @param array (key => array of policies)
	 */
	public function setPolicy(array $policy)
	{
		foreach ($policy as $key => $sources) {
			$this->policy[$key] = $sources;
		}
	}


	/**
	 * Set policy snippets.
	 *
	 * @param array (key => array of policies)
	 */
	public function setSnippets(array $snippets)
	{
		$this->snippets = $snippets;
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
		$currentPolicy = $this->policy[$this->findConfigKey($presenter, $action)];

		foreach ($this->currentSnippets as $snippetName) {
			foreach ($this->snippets[$snippetName] as $directive => $sources) {
				$currentPolicy[$directive][] = $sources;
			}
		}

		foreach ($currentPolicy as $directive => $sources) {
			if (is_int($directive)) {
				foreach ($sources as $name => $value) {
					$this->addDirective($name, $value);
				}
			} else {
				$this->addDirective($directive, $sources);
			}
		}
		return implode('; ', $this->directives);
	}


	/**
	 * Add named snippet to current CSP config.
	 *
	 * @param string $snippetName
	 */
	public function addSnippet($snippetName)
	{
		$this->currentSnippets[] = $snippetName;
	}


	/**
	 * Make string from (possible) arrays.
	 *
	 * @param  string|array $sources
	 * @return string
	 */
	private function flattenSources($sources)
	{
		if (is_array($sources)) {
			$items = [];
			array_walk_recursive($sources, function($value) use (&$items) {
				$items[] = $value;
			});
			$sources = implode(' ', $items);
		}
		return $sources;
	}


	/**
	 * Find CPS policy config key.
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
			if (isset($this->policy[implode('_', $parts)])) {
				break;
			}
			$parts[$i] = self::DEFAULT_KEY;
		}
		return implode('_', $parts);
	}


	/**
	 * Format and add a directive.
	 *
	 * @param string $name
	 * @param string|array $value
	 */
	private function addDirective($name, $value)
	{
		$values = $this->flattenSources($value);
		$this->directives[$name] = trim("$name $values");
		if ($name === 'child-src' && $this->supportLegacyBrowsers) {
			$this->directives['frame-src'] = trim("frame-src $values");
		}
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
