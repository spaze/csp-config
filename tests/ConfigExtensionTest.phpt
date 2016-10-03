<?php

/**
 * Test: Spaze\ContentSecurityPolicy\Bridges\Nette\ConfigExtension.
 *
 * @testCase Spaze\ContentSecurityPolicy\ConfigExtensionTest
 * @author Michal Špaček
 * @package Spaze\ContentSecurityPolicy\Config
 */

use Spaze\ContentSecurityPolicy\Config as CspConfig;
use Tester\Assert;

require __DIR__ . '/../vendor/autoload.php';

class ConfigExtensionTest extends Tester\TestCase
{

	public $tempDir;

	protected function createCspConfig()
	{
		$configurator = new Nette\Configurator();
		$configurator->setTempDirectory($this->tempDir);
		$configurator->addParameters(['appDir' => __DIR__]);
		$configurator->addConfig(__DIR__ . '/config.neon');
		$container = $configurator->createContainer();

		$cspConfig = $container->getByType(CspConfig::class);
		/** @var Spaze\ContentSecurityPolicy\Config $cspConfig */
		return $cspConfig;
	}


	public function testService()
	{
		$config = $this->createCspConfig();
		Assert::type(CspConfig::class, $config);
	}


	public function testConfig()
	{
		$config = $this->createCspConfig();
		Assert::type(CspConfig::class, $config);

		$config->addSnippet('ga');
		Assert::same("child-src foo bar; frame-src foo bar; style-src foo bar; script-src foo bar; img-src https://www.google-analytics.com", $config->getHeader('Foo', 'bar'));
	}

}

$testCase = new ConfigExtensionTest();
$testCase->tempDir = __DIR__ . '/../temp/tests';
Tester\Helpers::purge($testCase->tempDir);
$testCase->run();
