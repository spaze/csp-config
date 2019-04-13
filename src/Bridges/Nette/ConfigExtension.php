<?php
declare(strict_types = 1);

namespace Spaze\ContentSecurityPolicy\Bridges\Nette;

/**
 * ContentSecurityPolicy\Config extension.
 *
 * @author Michal Špaček
 */
class ConfigExtension extends \Nette\DI\CompilerExtension
{

	public function loadConfiguration(): void
	{
		$config = $this->getConfig();
		$builder = $this->getContainerBuilder();

		$cspConfig = $builder->addDefinition($this->prefix('config'))
			->setClass('Spaze\ContentSecurityPolicy\Config')
			->addSetup('setPolicy', array($config['policies'] ?? []))
			->addSetup('setSnippets', array($config['snippets'] ?? []));

		if ($config['supportLegacyBrowsers'] ?? false) {
			$cspConfig->addSetup('supportLegacyBrowsers');
		}
	}

}
