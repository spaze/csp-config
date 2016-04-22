<?php
namespace Spaze\CspConfig;

/**
 * ContentSecurityPolicy service.
 *
 * @author Michal Špaček
 */
class ContentSecurityPolicy
{

	/** @var string */
	const DEFAULT_PART = 'DEFAULT';

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
		foreach ($this->policy[$this->findConfigKey($presenter, $action)] as $directive => $sources) {
			if (is_int($directive)) {
				foreach ($sources as $key => $value) {
					$policy[$key] = trim("$key " . $this->flattenSources($value));
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
			$parts[$i] = self::DEFAULT_PART;
		}
		return implode('_', $parts);
	}

}
