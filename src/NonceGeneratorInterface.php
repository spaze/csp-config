<?php
namespace Spaze\ContentSecurityPolicy;

/**
 * Nonce generator interface.
 *
 * @author Michal Špaček
 */
interface NonceGeneratorInterface
{
	public function getNonce();
}
