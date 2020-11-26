<?php
declare(strict_types = 1);

namespace Spaze\ContentSecurityPolicy;

use Nette\DI\Config\Helpers;
use Spaze\NonceGenerator\GeneratorInterface;

/**
 * ContentSecurityPolicy\Config service.
 *
 * @author Michal Špaček
 */
class Config
{

	private const DEFAULT_KEY = '*';

	private const KEY_SEPARATOR = '.';

	private const EXTENDS_KEY = '@extends';

	/** @var GeneratorInterface|null */
	private $nonceGenerator;

	/** @var array<string, array<string, string|array<integer, string>>> */
	private $policy = [];

	/** @var array<string, array<string, array<integer, string>>> */
	private $snippets = [];

	/** @var array<integer, string> */
	private $currentSnippets = [];

	/** @var array<string, string> */
	private $directives = [];


	public function __construct(GeneratorInterface $generator = null)
	{
		$this->nonceGenerator = $generator;
	}


	/**
	 * @param array<string, array<string, string|array<integer, string>>> $policy
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
	 * @param array<string, array<string, array<integer, string>>> $snippets
	 * @return self
	 */
	public function setSnippets(array $snippets): self
	{
		$this->snippets = $snippets;
		return $this;
	}


	/**
	 * @return array<string, array<string, array<integer, string>>>
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
		$this->directives = [];

		$configKey = $this->findConfigKey($presenter, $action);
		if (isset($this->policy[$configKey][self::EXTENDS_KEY])) {
			$currentPolicy = $this->mergeExtends($this->policy[$configKey], $this->policy[$configKey][self::EXTENDS_KEY]);
		} else {
			$currentPolicy = $this->policy[$configKey];
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
	 * @param array<string, string|array<integer, string>> $currentPolicy
	 * @param array<integer, string> $parentKeys
	 * @return array<string, array<string, string>>
	 */
	private function mergeExtends(array $currentPolicy, array $parentKeys): array
	{
		$parentKey = current($parentKeys);
		$currentPolicy = (array)Helpers::merge($currentPolicy, $this->policy[$parentKey]);
		if (isset($this->policy[$parentKey][self::EXTENDS_KEY])) {
			$currentPolicy = $this->mergeExtends($currentPolicy, $this->policy[$parentKey][self::EXTENDS_KEY]);
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


	private function findConfigKey(string $presenter, string $action): string
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
	 * @param string $name
	 * @param array<integer, string> $sources
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
