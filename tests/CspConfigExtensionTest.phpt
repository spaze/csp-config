<?php
/** @noinspection PhpUnhandledExceptionInspection */
declare(strict_types = 1);

namespace Spaze\ContentSecurityPolicy\Bridges\Nette;

use Nette\Bootstrap\Configurator;
use Spaze\ContentSecurityPolicy\CspConfig;
use Tester\Assert;
use Tester\Environment;
use Tester\Helpers;
use Tester\TestCase;

require __DIR__ . '/../vendor/autoload.php';
Environment::setup();

/** @testCase */
class CspConfigExtensionTest extends TestCase
{

	public string $tempDir = __DIR__ . '/../temp/tests';
	private CspConfig $cspConfig;


	protected function setUp(): void
	{
		$this->cspConfig = $this->getService(__DIR__ . '/config.neon');
	}


	private function getService(string $config): CspConfig
	{
		$configurator = new Configurator();
		$configurator->setTempDirectory($this->tempDir);
		$configurator->addStaticParameters(['appDir' => __DIR__]);
		$configurator->addConfig($config);
		$container = $configurator->createContainer();
		return $container->getByType(CspConfig::class);
	}


	protected function tearDown(): void
	{
		Helpers::purge($this->tempDir);
	}


	public function testService(): void
	{
		Assert::type(CspConfig::class, $this->cspConfig);
	}


	public function testConfig(): void
	{
		$this->cspConfig->addSnippet('ga');
		Assert::noError(function (): void {
			Assert::same('child-src foo bar; style-src foo bar; script-src foo bar; img-src https://www.google-analytics.com', $this->cspConfig->getHeader(':Foo:bar'));
		});
	}


	public function testConfigExtendsOverride(): void
	{
		$this->cspConfig->addSnippet('ga');
		Assert::noError(function (): void {
			Assert::same("child-src foo bar; style-src foo bar; script-src 'none'; img-src https://www.google-analytics.com", $this->cspConfig->getHeader('Bar:foo:'));
		});
	}


	public function testConfigExtendsMerge(): void
	{
		$this->cspConfig->addSnippet('ga');
		Assert::noError(function (): void {
			Assert::same("child-src foo bar; style-src foo bar; script-src foo bar 'self'; img-src https://www.google-analytics.com", $this->cspConfig->getHeader(':Waldo:fred:'));
		});
	}


	public function testConfigExtendsSnippetsOverride(): void
	{
		$this->cspConfig->addSnippet('ga-override');
		Assert::noError(function (): void {
			Assert::same('child-src foo bar; style-src foo bar; script-src foo bar; img-src https://www.google-analytics.com https://ga.example', $this->cspConfig->getHeader('Foobar:baz'));
		});
	}


	public function testConfigExtendsSnippetsMerge(): void
	{
		$this->cspConfig->addSnippet('ga');
		Assert::noError(function (): void {
			Assert::same('child-src foo bar; style-src foo bar; script-src foo bar; img-src https://example.com https://www.google-analytics.com', $this->cspConfig->getHeader('Foobar:baz'));
		});
	}


	public function testConfigNoReportOnly(): void
	{
		Assert::noError(function (): void {
			Assert::same('child-src foo bar; style-src foo bar; script-src foo bar', $this->cspConfig->getHeader('Foo:bar'));
			Assert::same('', $this->cspConfig->getHeaderReportOnly('Foo', 'bar'));
		});
	}


	public function testReportOnlyConfig(): void
	{
		$cspConfig = $this->getService(__DIR__ . '/config-with-report-only.neon');
		$this->cspConfig->addSnippet('ga');
		Assert::noError(function () use ($cspConfig): void {
			Assert::same('child-src foo bar; style-src foo bar; script-src foo bar', $cspConfig->getHeader('Foo:bar'));
			Assert::same('form-action foobar; script-src waldo quux', $cspConfig->getHeaderReportOnly('Foo:bar'));
		});
	}

}

(new CspConfigExtensionTest())->run();
