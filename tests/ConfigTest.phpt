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

}

$testCase = new ConfigTest();
$testCase->run();
