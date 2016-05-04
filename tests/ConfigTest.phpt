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
			'DEFAULT_DEFAULT' => [
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
			'foo_DEFAULT' => [
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
			'foo_bar' => [
				'default-src' => "'none'",
				'img-src' => 'https://foobar.example.com',
			]
		]);
		Assert::same("default-src 'none'; img-src https://foobar.example.com", $config->getHeader('Foo', 'bar'));
	}


	public function testGetHeaderDefaultUppercase()
	{
		$config = new Config();
		$config->setPolicy([
			'foo_DEFAULT' => [
				'default-src' => "'none'",
				'img-src' => 'https://example.com',
			],
			'foo_default' => [
				'default-src' => "'none'",
				'img-src' => 'https://default.example.com',
			],
		]);
		Assert::same("default-src 'none'; img-src https://example.com", $config->getHeader('Foo', 'bar'));
		Assert::same("default-src 'none'; img-src https://default.example.com", $config->getHeader('Foo', 'default'));
	}


	public function testGetHeaderModule()
	{
		$config = new Config();
		$config->setPolicy([
			'foo_foo_bar' => [
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
			'DEFAULT_DEFAULT_DEFAULT' => [
				'default-src' => "'none'",
				'img-src' => 'https://default.example.com',
			],
			'DEFAULT_foo_bar' => [
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
			'foo_bar' => [
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
			'foo_DEFAULT' => [
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
			'DEFAULT_DEFAULT' => [
				'default-src' => ["'self'"],
				'img-src' => ['https://default.example.com'],
			],
			'foo_bar' => [
				\Nette\DI\Config\Helpers::EXTENDS_KEY => 'DEFAULT_DEFAULT',
				'default-src' => ['https://extends.example.com'],
				'img-src' => ['https://extends.example.com'],
			],
		]);
		Assert::same("default-src 'self' https://extends.example.com; img-src https://default.example.com https://extends.example.com", $config->getHeader('Foo', 'bar'));
	}

}

$testCase = new ConfigTest();
$testCase->run();
