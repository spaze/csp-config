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

	/** @var boolean */
	private $supportLegacyBrowsers = false;

	/** @var array<string, string> */
	private $directives = [];


	/**
	 * Constructor.
	 *
	 * @param GeneratorInterface $generator
	 */
	public function __construct(GeneratorInterface $generator = null)
	{
		$this->nonceGenerator = $generator;
	}


	/**
	 * Set policy.
	 *
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
	 * Set policy snippets.
	 *
	 * @param array<string, array<string, array<integer, string>>> $snippets
	 * @return self
	 */
	public function setSnippets(array $snippets): self
	{
		$this->snippets = $snippets;
		return $this;
	}


	/**
	 * Get policy snippets.
	 *
	 * @return array<string, array<string, array<integer, string>>>
	 */
	public function getSnippets(): array
	{
		return $this->snippets;
	}


	/**
	 * Get Content-Security-Policy header value.
	 *
	 * @param  string $presenter
	 * @param  string $action
	 * @return string
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
	 * Merge parent policies.
	 *
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
	 *
	 * @param string $snippetName
	 * @return self
	 */
	public function addSnippet(string $snippetName): self
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
	 * Format and add a directive.
	 *
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
		if ($name === 'child-src' && $this->supportLegacyBrowsers) {
			$this->directives['frame-src'] = trim("frame-src $values");
		}
	}


	/**
	 * Get default config key.
	 *
	 * @return string
	 */
	public function getDefaultKey(): string
	{
		return self::DEFAULT_KEY;
	}


	/**
	 * Enable legacy browser (i.e. Safari) support
	 *
	 * @return self
	 */
	public function supportLegacyBrowsers(): self
	{
		$this->supportLegacyBrowsers = true;
		return $this;
	}

}
