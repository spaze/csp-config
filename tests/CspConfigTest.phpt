<?php
declare(strict_types = 1);

namespace Spaze\ContentSecurityPolicy;

use Spaze\NonceGenerator\Nonce;
use Tester\Assert;
use Tester\Environment;
use Tester\TestCase;

require __DIR__ . '/../vendor/autoload.php';
Environment::setup();

/** @testCase */
class CspConfigTest extends TestCase
{

	private const string RANDOM = 'https://xkcd.com/221/';

	private CspConfig $config;


	protected function setUp(): void
	{
		$this->config = new CspConfig(new Nonce(self::RANDOM));
	}


	public function testGetDefaultKey(): void
	{
		Assert::same('*:*', $this->config->getDefaultKey());
	}


	public function testGetHeaderDefaultKeys(): void
	{
		$this->config->setPolicy([
			'*.*' => [
				'default-src' => ["'none'"],
				'img-src' => ['https://example.com'],
			],
		]);
		Assert::same("default-src 'none'; img-src https://example.com", $this->config->getHeader(':Foo:bar'));
	}


	public function testGetHeaderDefaultAction(): void
	{
		$this->config->setPolicy([
			'foo.*' => [
				'default-src' => ["'none'"],
				'img-src' => ['https://foo.example.com'],
			],
		]);
		Assert::same("default-src 'none'; img-src https://foo.example.com", $this->config->getHeader('Foo:bar'));
	}


	public function testGetHeader(): void
	{
		$this->config->setPolicy([
			'foo.bar' => [
				'default-src' => ["'none'"],
				'img-src' => ['https://foobar.example.com'],
			],
		]);
		Assert::same("default-src 'none'; img-src https://foobar.example.com", $this->config->getHeader(':Foo:bar:'));
		Assert::same('', $this->config->getHeaderReportOnly('Foo', 'bar'));
	}


	public function testGetHeaderReportOnly(): void
	{
		$this->config->setPolicyReportOnly([
			'foo.bar' => [
				'default-src' => ["'none'"],
			],
		]);
		Assert::same('', $this->config->getHeader('Foo', 'bar'));
		Assert::same("default-src 'none'", $this->config->getHeaderReportOnly(':Foo:bar'));
	}


	public function testGetHeaderBoth(): void
	{
		$this->config->setPolicy([
			'foo.bar' => [
				'default-src' => ["'none'"],
				'img-src' => ['https://foobar.example.com'],
			],
		]);
		$this->config->setPolicyReportOnly([
			'foo.bar' => [
				'default-src' => ["'none'"],
			],
		]);
		Assert::same("default-src 'none'; img-src https://foobar.example.com", $this->config->getHeader('Foo:bar:'));
		Assert::same("default-src 'none'", $this->config->getHeaderReportOnly(':Foo:bar'));
	}


	public function testGetHeaderModule(): void
	{
		$this->config->setPolicy([
			'foo.foo.bar' => [
				'default-src' => ["'none'"],
				'img-src' => ['https://foobar.example.com'],
			],
		]);
		Assert::same("default-src 'none'; img-src https://foobar.example.com", $this->config->getHeader(':Foo:Foo:bar'));
	}


	public function testGetHeaderDefaultModule(): void
	{
		$this->config->setPolicy([
			'*.*.*' => [
				'default-src' => ["'none'"],
				'img-src' => ['https://default.example.com'],
			],
			'foo.bar' => [
				'default-src' => ["'none'"],
				'img-src' => 'https://foobar.example.com',
			],
		]);
		Assert::same("default-src 'none'; img-src https://default.example.com", $this->config->getHeader(':Waldo:Foo:bar'));
	}


	public function testGetHeaderDefaultActionWithSnippets(): void
	{
		$this->config->setPolicy([
			'foo.*' => [
				'default-src' => ["'none'"],
				'img-src' => ['https://foo.example.com'],
			],
		]);
		$this->config->setSnippets([
			'ga' => [
				'img-src' => ['https://www.google-analytics.com'],
				'script-src' => ['https://www.google-analytics.com'],
			],
		]);
		Assert::same("default-src 'none'; img-src https://foo.example.com https://www.google-analytics.com; script-src https://www.google-analytics.com", $this->config->addSnippet('ga')->getHeader(':Foo:bar'));
	}


	public function testGetHeaderInheritance(): void
	{
		$this->config->setPolicy([
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
		Assert::same("default-src 'self' https://extends.example.com; img-src https://default.example.com https://extends.example.com", $this->config->getHeader(':Foo:bar'));
	}


	public function testGetHeaderDeepInheritance(): void
	{
		$this->config->setPolicy([
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
		Assert::same("default-src 'self' https://extends.example.com; img-src https://default.example.com https://extends.example.com; connect-src https://extends.example.com", $this->config->getHeader(':Bar:baz'));
	}


	public function testGetHeaderWithNonceDirective(): void
	{
		$this->config->setPolicy([
			'foo.bar' => [
				'script-src' => ["'self'", "'nonce'"],
				'style-src' => ['https://foobar.example.com'],
			],
		]);
		Assert::same("script-src 'self' 'nonce-" . self::RANDOM . "'; style-src https://foobar.example.com", $this->config->getHeader(':Foo:bar'));
	}

}

(new CspConfigTest())->run();
