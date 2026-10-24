<?php

declare(strict_types=1);

namespace EzPhp\OAuth\Oidc;

/**
 * Class IdTokenClaims
 *
 * The verified claims of an OpenID Connect ID token. Only produced by
 * IdTokenValidator after the signature, issuer, audience, expiry and nonce
 * checks passed.
 *
 * @package EzPhp\OAuth\Oidc
 */
final readonly class IdTokenClaims
{
    /**
     * @param string               $subject   `sub` — the provider's stable user identifier.
     * @param string               $issuer    `iss`.
     * @param list<string>         $audience  `aud`, always as a list.
     * @param int                  $expiresAt `exp` (Unix time).
     * @param int                  $issuedAt  `iat` (Unix time).
     * @param string|null          $nonce     `nonce`, when present.
     * @param array<string, mixed> $claims    Every claim of the token, including the ones above.
     */
    public function __construct(
        public string $subject,
        public string $issuer,
        public array $audience,
        public int $expiresAt,
        public int $issuedAt,
        public ?string $nonce,
        public array $claims,
    ) {
    }

    /**
     * Any claim by name (`email`, `email_verified`, `name`, ...), or $default.
     *
     * @param string $name
     * @param mixed  $default
     *
     * @return mixed
     */
    public function get(string $name, mixed $default = null): mixed
    {
        return array_key_exists($name, $this->claims) ? $this->claims[$name] : $default;
    }
}
