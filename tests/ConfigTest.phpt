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

}

$testCase = new ConfigTest();
$testCase->run();
