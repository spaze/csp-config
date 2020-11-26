<?php
declare(strict_types = 1);

namespace Spaze\ContentSecurityPolicy;

/**
 * Nonce Generator service mock.
 *
 * @author Michal Špaček
 */
class NonceGeneratorMock implements \Spaze\NonceGenerator\GeneratorInterface
{

	/** @var string */
	protected $random;


	/**
	 * Constructor.
	 *
	 * @param string $random
	 */
	public function __construct($random)
	{
		$this->random = $random;
	}


	/**
	 * Get nonce.
	 *
	 * @return string
	 */
	public function getNonce(): string
	{
		return base64_encode($this->random);
	}

}
