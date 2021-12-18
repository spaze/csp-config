<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\ContentSecurityPolicy\Bridges\Nette;

use Nette\Configurator;
use Spaze\ContentSecurityPolicy\Config as CspConfig;
use Tester\Assert;
use Tester\Helpers;
use Tester\TestCase;

require __DIR__ . '/../vendor/autoload.php';

/** @testCase */
class ConfigExtensionTest extends TestCase
{

	/** @var string */
	public $tempDir = __DIR__ . '/../temp/tests';

	/** @var CspConfig */
	private $cspConfig;


	protected function setUp(): void
	{
		$configurator = new Configurator();
		$configurator->setTempDirectory($this->tempDir);
		$configurator->addParameters(['appDir' => __DIR__]);
		$configurator->addConfig(__DIR__ . '/config.neon');
		$container = $configurator->createContainer();

		$this->cspConfig = $container->getByType(CspConfig::class);
	}


	protected function tearDown()
	{
		Helpers::purge($this->tempDir);
	}


	public function testService(): void
	{
		Assert::type(CspConfig::class, $this->cspConfig);
	}


	public function testConfig(): void
	{
		Assert::type(CspConfig::class, $this->cspConfig);

		$this->cspConfig->addSnippet('ga');
		Assert::same("child-src foo bar; style-src foo bar; script-src foo bar; img-src https://www.google-analytics.com", $this->cspConfig->getHeader('Foo', 'bar'));
	}

}

(new ConfigExtensionTest())->run();
