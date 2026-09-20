<?php

declare(strict_types=1);

namespace EzPhp\OAuth;

/**
 * Class Pkce
 *
 * PKCE (RFC 7636) code verifier / challenge generation. S256 only — plain
 * transform is not offered since every provider ez-php targets supports S256
 * and it is the only method that protects the exchange from an intercepted
 * authorization code.
 *
 * @package EzPhp\OAuth
 */
final class Pkce
{
    private const int VERIFIER_BYTES = 64;

    /**
     * Generate a cryptographically random code verifier.
     *
     * @return string Base64url-encoded, 43-128 characters per RFC 7636.
     */
    public static function generateVerifier(): string
    {
        return self::base64UrlEncode(random_bytes(self::VERIFIER_BYTES));
    }

    /**
     * Derive the S256 code challenge for a given verifier.
     *
     * @param string $verifier
     *
     * @return string
     */
    public static function challengeFor(string $verifier): string
    {
        return self::base64UrlEncode(hash('sha256', $verifier, true));
    }

    /**
     * @param string $data
     *
     * @return string
     */
    private static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
