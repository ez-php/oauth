<?php

declare(strict_types=1);

namespace Tests\Support;

use OpenSSLAsymmetricKey;
use RuntimeException;

/**
 * Generates RSA / P-256 key pairs, publishes them as JWKs and signs JWS compact tokens with them.
 */
final class OAuthOidcSigner
{
    private OpenSSLAsymmetricKey $key;

    /**
     * @var array<string, string>
     */
    private array $jwk;

    public function __construct(private readonly string $algorithm, string $kid)
    {
        $key = openssl_pkey_new($algorithm === 'RS256'
            ? ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]
            : ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $details = $key === false ? false : openssl_pkey_get_details($key);

        if ($key === false || !is_array($details)) {
            throw new RuntimeException('key generation failed');
        }

        $this->key = $key;
        /** @var array{rsa?: array{n: string, e: string}, ec?: array{x: string, y: string}} $details */
        $this->jwk = $algorithm === 'RS256'
            ? ['kty' => 'RSA', 'kid' => $kid, 'use' => 'sig', 'alg' => 'RS256', 'n' => self::b64($details['rsa']['n'] ?? ''), 'e' => self::b64($details['rsa']['e'] ?? '')]
            : ['kty' => 'EC', 'kid' => $kid, 'crv' => 'P-256', 'x' => self::b64(str_pad($details['ec']['x'] ?? '', 32, "\x00", STR_PAD_LEFT)), 'y' => self::b64(str_pad($details['ec']['y'] ?? '', 32, "\x00", STR_PAD_LEFT))];
    }

    /**
     * @return array<string, string>
     */
    public function jwk(): array
    {
        return $this->jwk;
    }

    /**
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $headerOverrides
     */
    public function sign(array $claims, array $headerOverrides = []): string
    {
        $header = array_merge(['alg' => $this->algorithm, 'typ' => 'JWT', 'kid' => $this->jwk['kid']], $headerOverrides);
        $input = self::b64((string) json_encode(array_filter($header, static fn (mixed $v): bool => $v !== null))) . '.' . self::b64((string) json_encode($claims));
        openssl_sign($input, $der, $this->key, OPENSSL_ALGO_SHA256);

        return $input . '.' . self::b64($this->algorithm === 'ES256' ? self::derToRaw((string) $der) : (string) $der);
    }

    public static function b64(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * ECDSA DER SEQUENCE { INTEGER r, INTEGER s } → 64-byte r || s.
     */
    private static function derToRaw(string $der): string
    {
        $offset = 2;
        $parts = [];

        for ($i = 0; $i < 2; $i++) {
            $length = ord($der[$offset + 1]);
            $parts[] = str_pad(ltrim(substr($der, $offset + 2, $length), "\x00"), 32, "\x00", STR_PAD_LEFT);
            $offset += 2 + $length;
        }

        return $parts[0] . $parts[1];
    }
}
