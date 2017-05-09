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

	/** @var array */
	public $defaults = array(
		'snippets' => array(),
		'policies' => array(),
		'supportLegacyBrowsers' => false,
	);


	public function loadConfiguration()
	{
		$config = $this->getConfig($this->defaults);
		$builder = $this->getContainerBuilder();

		$cspConfig = $builder->addDefinition($this->prefix('config'))
			->setClass('Spaze\ContentSecurityPolicy\Config')
			->addSetup('setPolicy', array($config['policies']))
			->addSetup('setSnippets', array($config['snippets']));

		if ($config['supportLegacyBrowsers']) {
			$cspConfig->addSetup('supportLegacyBrowsers');
		}
	}

}
