<?php
declare(strict_types = 1);

namespace Spaze\ContentSecurityPolicy;

use Spaze\NonceGenerator\GeneratorInterface;
use Tester\Assert;
use Tester\Environment;
use Tester\TestCase;

require __DIR__ . '/../vendor/autoload.php';
Environment::setup();

/** @testCase */
class ConfigTest extends TestCase
{

	/** @var GeneratorInterface */
	private $nonceGenerator;


	public function __construct()
	{
		$this->nonceGenerator = new class implements GeneratorInterface {

			/** @var string */
			private $random;


			/**
			 * @param string $random
			 * @return GeneratorInterface
			 */
			public function setRandom($random): GeneratorInterface
			{
				$this->random = $random;
				return $this;
			}


			public function getNonce(): string
			{
				return base64_encode($this->random);
			}

		};
	}


	public function testGetDefaultKey()
	{
		$config = new Config();
		Assert::same('*', $config->getDefaultKey());
	}


	public function testGetHeaderDefaultKeys()
	{
		$config = new Config();
		$config->setPolicy([
			'*.*' => [
				'default-src' => ["'none'"],
				'img-src' => ['https://example.com'],
			],
		]);
		Assert::same("default-src 'none'; img-src https://example.com", $config->getHeader('Foo', 'bar'));
	}


	public function testGetHeaderDefaultAction()
	{
		$config = new Config();
		$config->setPolicy([
			'foo.*' => [
				'default-src' => ["'none'"],
				'img-src' => ['https://foo.example.com'],
			],
		]);
		Assert::same("default-src 'none'; img-src https://foo.example.com", $config->getHeader('Foo', 'bar'));
	}


	public function testGetHeader()
	{
		$config = new Config();
		$config->setPolicy([
			'foo.bar' => [
				'default-src' => ["'none'"],
				'img-src' => ['https://foobar.example.com'],
			],
		]);
		Assert::same("default-src 'none'; img-src https://foobar.example.com", $config->getHeader('Foo', 'bar'));
		Assert::same('', $config->getHeaderReportOnly('Foo', 'bar'));
	}


	public function testGetHeaderReportOnly()
	{
		$config = new Config();
		$config->setPolicyReportOnly([
			'foo.bar' => [
				'default-src' => ["'none'"],
			],
		]);
		Assert::same('', $config->getHeader('Foo', 'bar'));
		Assert::same("default-src 'none'", $config->getHeaderReportOnly('Foo', 'bar'));
	}


	public function testGetHeaderBoth()
	{
		$config = new Config();
		$config->setPolicy([
			'foo.bar' => [
				'default-src' => ["'none'"],
				'img-src' => ['https://foobar.example.com'],
			],
		]);
		$config->setPolicyReportOnly([
			'foo.bar' => [
				'default-src' => ["'none'"],
			],
		]);
		Assert::same("default-src 'none'; img-src https://foobar.example.com", $config->getHeader('Foo', 'bar'));
		Assert::same("default-src 'none'", $config->getHeaderReportOnly('Foo', 'bar'));
	}


	public function testGetHeaderModule()
	{
		$config = new Config();
		$config->setPolicy([
			'foo.foo.bar' => [
				'default-src' => ["'none'"],
				'img-src' => ['https://foobar.example.com'],
			],
		]);
		Assert::same("default-src 'none'; img-src https://foobar.example.com", $config->getHeader('Foo:Foo', 'bar'));
	}


	public function testGetHeaderDefaultModule()
	{
		$config = new Config();
		$config->setPolicy([
			'*.*.*' => [
				'default-src' => ["'none'"],
				'img-src' => ['https://default.example.com'],
			],
			'foo.bar' => [
				'default-src' => ["'none'"],
				'img-src' => 'https://foobar.example.com',
			],
		]);
		Assert::same("default-src 'none'; img-src https://default.example.com", $config->getHeader('Waldo:Foo', 'bar'));
	}


	public function testGetHeaderDefaultActionWithSnippets()
	{
		$config = new Config();
		$config->setPolicy([
			'foo.*' => [
				'default-src' => ["'none'"],
				'img-src' => ['https://foo.example.com'],
			],
		]);
		$config->setSnippets([
			'ga' => [
				'img-src' => ['https://www.google-analytics.com'],
				'script-src' => ['https://www.google-analytics.com'],
			],
		]);
		Assert::same("default-src 'none'; img-src https://foo.example.com https://www.google-analytics.com; script-src https://www.google-analytics.com", $config->addSnippet('ga')->getHeader('Foo', 'bar'));
	}


	public function testGetHeaderInheritance()
	{
		$config = new Config();
		$config->setPolicy([
			'*.*' => [
				'default-src' => ["'self'"],
				'img-src' => ['https://default.example.com'],
			],
			'foo.bar' => [
				'@extends' => ['*.*'],
				'default-src' => ['https://extends.example.com'],
				'img-src' => ['https://extends.example.com'],
			],
		]);
		Assert::same("default-src 'self' https://extends.example.com; img-src https://default.example.com https://extends.example.com", $config->getHeader('Foo', 'bar'));
	}


	public function testGetHeaderDeepInheritance()
	{
		$config = new Config();
		$config->setPolicy([
			'*.*' => [
				'default-src' => ["'self'"],
				'img-src' => ['https://default.example.com'],
			],
			'foo.bar' => [
				'@extends' => ['*.*'],
				'default-src' => ['https://extends.example.com'],
				'img-src' => ['https://extends.example.com'],
			],
			'bar.baz' => [
				'@extends' => ['foo.bar'],
				'connect-src' => ['https://extends.example.com'],
			],
		]);
		Assert::same("default-src 'self' https://extends.example.com; img-src https://default.example.com https://extends.example.com; connect-src https://extends.example.com", $config->getHeader('Bar', 'baz'));
	}


	public function testGetHeaderWithNonceDirective()
	{
		$random = 'https://xkcd.com/221/';
		$config = new Config($this->nonceGenerator->setRandom($random));
		$config->setPolicy([
			'foo.bar' => [
				'script-src' => ["'self'", "'nonce'"],
				'style-src' => ['https://foobar.example.com'],
			],
		]);
		Assert::same("script-src 'self' 'nonce-" . base64_encode($random) . "'; style-src https://foobar.example.com", $config->getHeader('Foo', 'bar'));
	}

}

(new ConfigTest())->run();
