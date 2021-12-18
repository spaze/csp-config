<?php
declare(strict_types = 1);

namespace Spaze\ContentSecurityPolicy\Bridges\Nette;

use Nette\DI\CompilerExtension;
use Nette\Schema\Expect;
use Nette\Schema\Schema;
use stdClass;

/**
 * ContentSecurityPolicy\Config extension.
 *
 * @author Michal Špaček
 */
class ConfigExtension extends CompilerExtension
{

	/** @var array<string, mixed>|stdClass */
	protected $config = [];


	public function getConfigSchema(): Schema
	{
		$expectPolicies = Expect::arrayOf(
			Expect::arrayOf(
				Expect::anyOf(
					Expect::listOf(Expect::string()),
					Expect::string()
				)->castTo('array')
			)
		);
		return Expect::structure([
			'supportLegacyBrowsers' => Expect::bool()->default(false),
			'snippets' => (clone $expectPolicies)->default([]),
			'policies' => (clone $expectPolicies)->required(),
			'policiesReportOnly' => (clone $expectPolicies)->default([]),
		]);
	}


	public function loadConfiguration(): void
	{
		$builder = $this->getContainerBuilder();

		$cspConfig = $builder->addDefinition($this->prefix('config'))
			->setClass('Spaze\ContentSecurityPolicy\Config')
			->addSetup('setPolicy', [$this->config->policies])
			->addSetup('setPolicyReportOnly', [$this->config->policiesReportOnly])
			->addSetup('setSnippets', [$this->config->snippets]);

		if ($this->config->supportLegacyBrowsers) {
			$cspConfig->addSetup('supportLegacyBrowsers');
		}
	}

}
