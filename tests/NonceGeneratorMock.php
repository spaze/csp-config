<?php
namespace Spaze\NonceGenerator {
	interface GeneratorInterface
	{
		public function getNonce(): string;
	}

	/**
	 * Nonce Generator service mock.
	 *
	 * @author Michal Špaček
	 */
	class NonceGeneratorMock implements GeneratorInterface
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
}
