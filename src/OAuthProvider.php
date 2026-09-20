<?php

declare(strict_types=1);

namespace EzPhp\OAuth;

/**
 * Class OAuthProvider
 *
 * Immutable configuration for a single OAuth2 authorization server. There is
 * no built-in catalog of specific providers (Google, GitHub, ...) — the
 * application supplies the provider's own endpoints and credentials.
 *
 * @package EzPhp\OAuth
 */
final readonly class OAuthProvider
{
    /**
     * OAuthProvider Constructor
     *
     * @param string       $authorizeUrl    Authorization endpoint the user is redirected to.
     * @param string       $tokenUrl        Token endpoint used for code exchange and refresh.
     * @param string       $clientId
     * @param string       $clientSecret
     * @param string       $redirectUri
     * @param list<string> $scopes          Requested scopes, space-joined in the authorization URL.
     * @param array<string, string> $authorizeParams  Extra query parameters merged into every authorization URL.
     */
    public function __construct(
        public string $authorizeUrl,
        public string $tokenUrl,
        public string $clientId,
        public string $clientSecret,
        public string $redirectUri,
        public array $scopes = [],
        public array $authorizeParams = [],
    ) {
    }
}
