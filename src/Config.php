<?php
declare(strict_types = 1);

namespace Spaze\ContentSecurityPolicy;

use Nette\Schema\Helpers;
use Spaze\NonceGenerator\Nonce;

/**
 * @phpstan-type PolicyArray array<string, array<string, array<int, string>>>
 */
class Config
{

	private const DEFAULT_KEY = '*';

	private const KEY_SEPARATOR = '.';

	private const EXTENDS_KEY = '@extends';

	private const OVERRIDE_FLAG = '!';

	/** @phpstan-var PolicyArray */
	private array $policy = [];

	/** @phpstan-var PolicyArray */
	private array $policyReportOnly = [];

	/** @phpstan-var PolicyArray */
	private array $snippets = [];

	/** @var array<int, string> */
	private array $currentSnippets = [];

	/** @var array<string, string> */
	private array $directives = [];


	public function __construct(
		private readonly Nonce $nonce,
	) {
	}


	/**
	 * @phpstan-param PolicyArray $policy
	 */
	public function setPolicy(array $policy): self
	{
		foreach ($policy as $key => $sources) {
			$this->policy[$key] = $sources;
		}
		return $this;
	}


	/**
	 * @phpstan-param PolicyArray $policy
	 */
	public function setPolicyReportOnly(array $policy): self
	{
		foreach ($policy as $key => $sources) {
			$this->policyReportOnly[$key] = $sources;
		}
		return $this;
	}


	/**
	 * @phpstan-param PolicyArray $snippets
	 */
	public function setSnippets(array $snippets): self
	{
		$this->snippets = $snippets;
		return $this;
	}


	/**
	 * @phpstan-return PolicyArray
	 */
	public function getSnippets(): array
	{
		return $this->snippets;
	}


	/**
	 * Get Content-Security-Policy header value.
	 */
	public function getHeader(string $fullyQualifiedAction): string
	{
		return $this->getHeaderValue($fullyQualifiedAction, $this->policy);
	}


	/**
	 * Get Content-Security-Policy-Report-Only header value.
	 */
	public function getHeaderReportOnly(string $fullyQualifiedAction): string
	{
		return $this->getHeaderValue($fullyQualifiedAction, $this->policyReportOnly);
	}


	/**
	 * @phpstan-param PolicyArray $policy
	 */
	private function getHeaderValue(string $fullyQualifiedAction, array $policy): string
	{
		$this->directives = [];

		$configKey = $this->findConfigKey($fullyQualifiedAction, $policy);
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
	 * @phpstan-param PolicyArray $policy
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
	 * @phpstan-param PolicyArray $policy
	 */
	private function findConfigKey(string $fullyQualifiedAction, array $policy): string
	{
		$parts = explode(':', strtolower(trim($fullyQualifiedAction, ':')));
		for ($i = count($parts) - 1; $i >= 0; $i--) {
			if (isset($policy[implode(self::KEY_SEPARATOR, $parts)])) {
				break;
			}
			$parts[$i] = self::DEFAULT_KEY;
		}
		return implode(self::KEY_SEPARATOR, $parts);
	}


	/**
	 * @param array<int, string> $sources
	 */
	private function addDirective(string $name, array $sources): void
	{
		$values = '';
		foreach ($sources as $source) {
			if ($source === "'nonce'") {
				$source = "'nonce-" . $this->nonce->getValue() . "'";
			}
			$values .= $source . ' ';
		}
		if (isset($name[0]) && $name[0] === self::OVERRIDE_FLAG) {
			$name = substr($name, 1);
		}
		$this->directives[$name] = trim("$name $values");
	}


	/**
	 * Get default config key.
	 */
	public function getDefaultKey(): string
	{
		return self::DEFAULT_KEY . ':' . self::DEFAULT_KEY;
	}

}
