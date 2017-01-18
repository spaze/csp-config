<?php

/**
 * Test: Spaze\ContentSecurityPolicy\Config.
 *
 * @testCase Spaze\ContentSecurityPolicy\ConfigTest
 * @author Michal Špaček
 * @package Spaze\ContentSecurityPolicy\Config
 */

use Spaze\ContentSecurityPolicy\Config;
use Tester\Assert;

require __DIR__ . '/../vendor/autoload.php';

class ConfigTest extends Tester\TestCase
{

	public function testGetDefaultKey()
	{
		$config = new Config();
		Assert::same(Config::DEFAULT_KEY, $config->getDefaultKey());
	}


	public function testGetHeaderDefaultKeys()
	{
		$config = new Config();
		$config->setPolicy([
			'*.*' => [
				'default-src' => "'none'",
				'img-src' => 'https://example.com',
			]
		]);
		Assert::same("default-src 'none'; img-src https://example.com", $config->getHeader('Foo', 'bar'));
	}


	public function testGetHeaderDefaultAction()
	{
		$config = new Config();
		$config->setPolicy([
			'foo.*' => [
				'default-src' => "'none'",
				'img-src' => 'https://foo.example.com',
			]
		]);
		Assert::same("default-src 'none'; img-src https://foo.example.com", $config->getHeader('Foo', 'bar'));
	}


	public function testGetHeader()
	{
		$config = new Config();
		$config->setPolicy([
			'foo.bar' => [
				'default-src' => "'none'",
				'img-src' => 'https://foobar.example.com',
			]
		]);
		Assert::same("default-src 'none'; img-src https://foobar.example.com", $config->getHeader('Foo', 'bar'));
	}


	public function testGetHeaderModule()
	{
		$config = new Config();
		$config->setPolicy([
			'foo.foo.bar' => [
				'default-src' => "'none'",
				'img-src' => 'https://foobar.example.com',
			]
		]);
		Assert::same("default-src 'none'; img-src https://foobar.example.com", $config->getHeader('Foo:Foo', 'bar'));
	}


	public function testGetHeaderDefaultModule()
	{
		$config = new Config();
		$config->setPolicy([
			'*.*.*' => [
				'default-src' => "'none'",
				'img-src' => 'https://default.example.com',
			],
			'foo.bar' => [
				'default-src' => "'none'",
				'img-src' => 'https://foobar.example.com',
			],
		]);
		Assert::same("default-src 'none'; img-src https://default.example.com", $config->getHeader('Waldo:Foo', 'bar'));
	}


	public function testGetHeaderLegacyBrowser()
	{
		$config = new Config();
		$config->setPolicy([
			'foo.bar' => [
				'default-src' => "'none'",
				'child-src' => 'https://example.com',
			]
		]);
		Assert::same("default-src 'none'; child-src https://example.com", $config->getHeader('Foo', 'bar'));
		$config->supportLegacyBrowsers();
		Assert::same("default-src 'none'; child-src https://example.com; frame-src https://example.com", $config->getHeader('Foo', 'bar'));
	}


	public function testGetHeaderDefaultActionWithSnippets()
	{
		$config = new Config();
		$config->setPolicy([
			'foo.*' => [
				'default-src' => "'none'",
				'img-src' => 'https://foo.example.com',
			]
		]);
		$config->setSnippets([
			'ga' => [
				'img-src' => ['https://www.google-analytics.com'],
				'script-src' => ['https://www.google-analytics.com'],
			]
		]);
		Assert::same("default-src 'none'; img-src https://foo.example.com https://www.google-analytics.com; script-src https://www.google-analytics.com", $config->addSnippet('ga')->getHeader('Foo', 'bar'));
	}


	public function testGetHeaderInheritance()
	{
		$config = new Config();
		$config->setPolicy($f=[
			'*.*' => [
				'default-src' => ["'self'"],
				'img-src' => ['https://default.example.com'],
			],
			'foo.bar' => [
				\Nette\DI\Config\Helpers::EXTENDS_KEY => '*.*',
				'default-src' => ['https://extends.example.com'],
				'img-src' => ['https://extends.example.com'],
			],
		]);
		Assert::same("default-src 'self' https://extends.example.com; img-src https://default.example.com https://extends.example.com", $config->getHeader('Foo', 'bar'));
	}


	public function testGetHeaderDeepInheritance()
	{
		$config = new Config();
		$config->setPolicy($f=[
			'*.*' => [
				'default-src' => ["'self'"],
				'img-src' => ['https://default.example.com'],
			],
			'foo.bar' => [
				\Nette\DI\Config\Helpers::EXTENDS_KEY => '*.*',
				'default-src' => ['https://extends.example.com'],
				'img-src' => ['https://extends.example.com'],
			],
			'bar.baz' => [
				\Nette\DI\Config\Helpers::EXTENDS_KEY => 'foo.bar',
				'connect-src' => ['https://extends.example.com'],
			],
		]);
		Assert::same("default-src 'self' https://extends.example.com; img-src https://default.example.com https://extends.example.com; connect-src https://extends.example.com", $config->getHeader('Bar', 'baz'));
	}


	public function testGetHeaderWithNonceStrictDynamic()
	{
		$random = 'https://xkcd.com/221/';
		$config = new Config(new NonceGeneratorMock($random));
		$config->setPolicy([
			'foo.bar' => [
				'script-src' => "'self'",
				'style-src' => 'https://foobar.example.com',
			]
		]);
		$config->setAddNonce([
			'script-src' => true,
			'style-src' => false,
		]);
		$config->setAddStrictDynamic([
			'script-src' => true,
			'style-src' => true,
		]);
		Assert::same("script-src 'nonce-" . base64_encode($random) . "' 'strict-dynamic' 'self'; style-src https://foobar.example.com", $config->getHeader('Foo', 'bar'));
	}

}

$testCase = new ConfigTest();
$testCase->run();
