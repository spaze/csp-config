<?php
declare(strict_types = 1);

namespace Spaze\ContentSecurityPolicy;

use Nette\Schema\Helpers;
use Spaze\NonceGenerator\GeneratorInterface;

/**
 * ContentSecurityPolicy\Config service.
 *
 * @author Michal Špaček
 * @phpstan-type PolicyArray array<string, array<string, array<int, string>>>
 */
class Config
{

	private const DEFAULT_KEY = '*';

	private const KEY_SEPARATOR = '.';

	private const EXTENDS_KEY = '@extends';

	/** @var GeneratorInterface|null */
	private $nonceGenerator;

	/** @var PolicyArray */
	private $policy = [];

	/** @var PolicyArray */
	private $policyReportOnly = [];

	/** @var PolicyArray */
	private $snippets = [];

	/** @var array<int, string> */
	private $currentSnippets = [];

	/** @var array<string, string> */
	private $directives = [];


	public function __construct(GeneratorInterface $generator = null)
	{
		$this->nonceGenerator = $generator;
	}


	/**
	 * @param PolicyArray $policy
	 * @return self
	 */
	public function setPolicy(array $policy): self
	{
		foreach ($policy as $key => $sources) {
			$this->policy[$key] = $sources;
		}
		return $this;
	}


	/**
	 * @param PolicyArray $policy
	 * @return self
	 */
	public function setPolicyReportOnly(array $policy): self
	{
		foreach ($policy as $key => $sources) {
			$this->policyReportOnly[$key] = $sources;
		}
		return $this;
	}


	/**
	 * @param PolicyArray $snippets
	 * @return self
	 */
	public function setSnippets(array $snippets): self
	{
		$this->snippets = $snippets;
		return $this;
	}


	/**
	 * @return PolicyArray
	 */
	public function getSnippets(): array
	{
		return $this->snippets;
	}


	/**
	 * Get Content-Security-Policy header value.
	 */
	public function getHeader(string $presenter, string $action): string
	{
		return $this->getHeaderValue($presenter, $action, $this->policy);
	}


	/**
	 * Get Content-Security-Policy-Report-Only header value.
	 */
	public function getHeaderReportOnly(string $presenter, string $action): string
	{
		return $this->getHeaderValue($presenter, $action, $this->policyReportOnly);
	}


	/**
	 * @param string $presenter
	 * @param string $action
	 * @param PolicyArray $policy
	 * @return string
	 */
	private function getHeaderValue(string $presenter, string $action, array $policy): string
	{
		$this->directives = [];

		$configKey = $this->findConfigKey($presenter, $action, $policy);
		if (isset($policy[$configKey][self::EXTENDS_KEY])) {
			$currentPolicy = $this->mergeExtends($policy[$configKey], $policy[$configKey][self::EXTENDS_KEY], $policy);
		} else {
			$currentPolicy = $policy[$configKey] ?? [];
		}
		foreach ($this->currentSnippets as $snippetName) {
			foreach ($this->snippets[$snippetName] as $directive => $sources) {
				$currentPolicy[$directive] = (isset($currentPolicy[$directive]) ? array_merge($currentPolicy[$directive], $sources) : $sources);
			}
		}

		foreach ($currentPolicy as $directive => $sources) {
			$this->addDirective($directive, $sources);
		}
		return implode('; ', $this->directives);
	}


	/**
	 * @param array<string, array<int, string>> $currentPolicy
	 * @param array<int, string> $parentKeys
	 * @param PolicyArray $policy
	 * @return array<string, array<int, string>>
	 */
	private function mergeExtends(array $currentPolicy, array $parentKeys, array $policy): array
	{
		$parentKey = current($parentKeys);
		$currentPolicy = (array)Helpers::merge($currentPolicy, $this->policy[$parentKey]);
		if (isset($policy[$parentKey][self::EXTENDS_KEY])) {
			$currentPolicy = $this->mergeExtends($currentPolicy, $policy[$parentKey][self::EXTENDS_KEY], $policy);
		}
		unset($currentPolicy[self::EXTENDS_KEY]);
		return $currentPolicy;
	}


	/**
	 * Add named snippet to current CSP config.
	 */
	public function addSnippet(string $snippetName): self
	{
		$this->currentSnippets[] = $snippetName;
		return $this;
	}


	/**
	 * @param string $presenter
	 * @param string $action
	 * @param PolicyArray $policy
	 * @return string
	 */
	private function findConfigKey(string $presenter, string $action, array $policy): string
	{
		$parts = explode(':', strtolower($presenter));
		$parts[] = strtolower($action);
		for ($i = count($parts) - 1; $i >= 0; $i--) {
			if (isset($policy[implode(self::KEY_SEPARATOR, $parts)])) {
				break;
			}
			$parts[$i] = self::DEFAULT_KEY;
		}
		return implode(self::KEY_SEPARATOR, $parts);
	}


	/**
	 * @param string $name
	 * @param array<int, string> $sources
	 */
	private function addDirective(string $name, array $sources): void
	{
		$values = '';
		foreach ($sources as $source) {
			if ($source === "'nonce'" && $this->nonceGenerator) {
				$source = "'nonce-" . $this->nonceGenerator->getNonce() . "'";
			}
			$values .= $source . ' ';
		}
		$this->directives[$name] = trim("$name $values");
	}


	/**
	 * Get default config key.
	 */
	public function getDefaultKey(): string
	{
		return self::DEFAULT_KEY;
	}


	/**
	 * @deprecated
	 */
	public function supportLegacyBrowsers(): self
	{
		trigger_error('Calling supportLegacyBrowsers() is deprecated, was needed for browsers that support only CSP1. If you still need to support those (you do not), add frame-src with the same values as child-src, if you use child-src in your policy', E_USER_DEPRECATED);
		return $this;
	}

}
