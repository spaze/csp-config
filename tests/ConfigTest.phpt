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

	private GeneratorInterface $nonceGenerator;


	public function __construct()
	{
		$this->nonceGenerator = new class implements GeneratorInterface {

			private string $random;


			public function setRandom(string $random): GeneratorInterface
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


	public function testGetDefaultKey(): void
	{
		$config = new Config();
		Assert::same('*', $config->getDefaultKey());
	}


	public function testGetHeaderDefaultKeys(): void
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


	public function testGetHeaderDefaultAction(): void
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


	public function testGetHeader(): void
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


	public function testGetHeaderReportOnly(): void
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


	public function testGetHeaderBoth(): void
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


	public function testGetHeaderModule(): void
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


	public function testGetHeaderDefaultModule(): void
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


	public function testGetHeaderDefaultActionWithSnippets(): void
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


	public function testGetHeaderInheritance(): void
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


	public function testGetHeaderDeepInheritance(): void
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


	public function testGetHeaderWithNonceDirective(): void
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
