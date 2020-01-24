<?php
declare(strict_types = 1);

namespace Spaze\ContentSecurityPolicy;

use Spaze\ContentSecurityPolicy\Config;
use Spaze\NonceGenerator\NonceGeneratorMock;
use Tester\Assert;
use Tester\TestCase;

require __DIR__ . '/../vendor/autoload.php';

class ConfigTest extends TestCase
{

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
			]
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
			]
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
			]
		]);
		Assert::same("default-src 'none'; img-src https://foobar.example.com", $config->getHeader('Foo', 'bar'));
	}


	public function testGetHeaderModule()
	{
		$config = new Config();
		$config->setPolicy([
			'foo.foo.bar' => [
				'default-src' => ["'none'"],
				'img-src' => ['https://foobar.example.com'],
			]
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


	public function testGetHeaderLegacyBrowser()
	{
		$config = new Config();
		$config->setPolicy([
			'foo.bar' => [
				'default-src' => ["'none'"],
				'child-src' => ['https://example.com'],
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
				'default-src' => ["'none'"],
				'img-src' => ['https://foo.example.com'],
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
		$config->setPolicy($f=[
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
		$config = new Config(new NonceGeneratorMock($random));
		$config->setPolicy([
			'foo.bar' => [
				'script-src' => ["'self'", "'nonce'"],
				'style-src' => ['https://foobar.example.com'],
			]
		]);
		Assert::same("script-src 'self' 'nonce-" . base64_encode($random) . "'; style-src https://foobar.example.com", $config->getHeader('Foo', 'bar'));
	}

}

$testCase = new ConfigTest();
$testCase->run();
