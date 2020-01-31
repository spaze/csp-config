<?php
declare(strict_types = 1);

namespace Spaze\ContentSecurityPolicy\Bridges\Nette;

use Nette\Configurator;
use Spaze\ContentSecurityPolicy\Config as CspConfig;
use Tester\Assert;
use Tester\Helpers;
use Tester\TestCase;

require __DIR__ . '/../vendor/autoload.php';

class ConfigExtensionTest extends TestCase
{

	public $tempDir;

	protected function createCspConfig(): CspConfig
	{
		$configurator = new Configurator();
		$configurator->setTempDirectory($this->tempDir);
		$configurator->addParameters(['appDir' => __DIR__]);
		$configurator->addConfig(__DIR__ . '/config.neon');
		$container = $configurator->createContainer();

		$cspConfig = $container->getByType(CspConfig::class);
		/** @var CspConfig $cspConfig */
		return $cspConfig;
	}


	public function testService(): void
	{
		$config = $this->createCspConfig();
		Assert::type(CspConfig::class, $config);
	}


	public function testConfig(): void
	{
		$config = $this->createCspConfig();
		Assert::type(CspConfig::class, $config);

		$config->addSnippet('ga');
		Assert::same("child-src foo bar; style-src foo bar; script-src foo bar; img-src https://www.google-analytics.com", $config->getHeader('Foo', 'bar'));
	}

}

$testCase = new ConfigExtensionTest();
$testCase->tempDir = __DIR__ . '/../temp/tests';
Helpers::purge($testCase->tempDir);
$testCase->run();
