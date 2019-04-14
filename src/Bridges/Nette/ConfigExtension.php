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

	private $defaults = array(
		'snippets' => [],
		'policies' => [],
		'supportLegacyBrowsers' => false,
	);


	public function loadConfiguration(): void
	{
		$this->validateConfig($this->defaults);

		$builder = $this->getContainerBuilder();

		$cspConfig = $builder->addDefinition($this->prefix('config'))
			->setClass('Spaze\ContentSecurityPolicy\Config')
			->addSetup('setPolicy', array($this->config['policies']))
			->addSetup('setSnippets', array($this->config['snippets']));

		if ($this->config['supportLegacyBrowsers']) {
			$cspConfig->addSetup('supportLegacyBrowsers');
		}
	}

}
