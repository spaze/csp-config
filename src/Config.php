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
	 * Get Content-Security-Policy header value.
	 *
	 * @param  string $presenter
	 * @param  string $action
	 * @return string
	 */
	public function getHeader($presenter, $action)
	{
		$policy = array();
		$key = $this->findConfigKey($presenter, $action);
		foreach ($this->policy[$key] as $directive => $sources) {
			if (is_int($directive)) {
				foreach ($sources as $name => $value) {
					$policy[$name] = trim("$name " . $this->flattenSources($value));
				}
			} else {
				$policy[$directive] = trim("$directive " . $this->flattenSources($sources));
			}
		}
		return implode('; ', $policy);
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
	 * Get default config key.
	 *
	 * @return string
	 */
	public function getDefaultKey()
	{
		return self::DEFAULT_KEY;
	}

}
