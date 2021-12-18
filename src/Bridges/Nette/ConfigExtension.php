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

	/** @var stdClass */
	protected $config;


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
			'snippets' => (clone $expectPolicies)->default([]),
			'policies' => (clone $expectPolicies)->required(),
			'policiesReportOnly' => (clone $expectPolicies)->default([]),
		]);
	}


	public function loadConfiguration(): void
	{
		$this->getContainerBuilder()->addDefinition($this->prefix('config'))
			->setType('Spaze\ContentSecurityPolicy\Config')
			->addSetup('setPolicy', [$this->config->policies])
			->addSetup('setPolicyReportOnly', [$this->config->policiesReportOnly])
			->addSetup('setSnippets', [$this->config->snippets]);
	}

}
