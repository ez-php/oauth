<?php

declare(strict_types=1);

namespace EzPhp\OAuth\Oidc;

use Closure;
use EzPhp\OAuth\OAuthException;

/**
 * Class IdTokenValidator
 *
 * Verifies an OpenID Connect ID token (a JWS in compact serialization) and
 * returns its claims.
 *
 * - Signature: RS256 or ES256 only. `none`, HMAC algorithms and anything else
 *   are rejected, as is a `crit` header. The key comes from the provider's JWKS,
 *   chosen by `kid` and required to match the algorithm's key type (RSA / EC
 *   P-256); without a `kid` the set must hold exactly one such key. An unknown
 *   `kid` triggers one JWKS refresh (key rotation).
 * - Claims (OpenID Connect Core §3.1.3.7): `iss` equals the configured issuer,
 *   `aud` contains the client ID, `azp` (when present, or when there are several
 *   audiences) equals the client ID, `exp` is in the future and `nbf`/`iat` are
 *   not, each with $leewaySeconds of clock skew, `sub` is a non-empty string, and
 *   `nonce` equals the one sent in the authorization request.
 *
 * @package EzPhp\OAuth\Oidc
 */
final class IdTokenValidator
{
    /**
     * RFC 7518 algorithm => JWK key type.
     */
    private const array ALGORITHMS = ['RS256' => 'RSA', 'ES256' => 'EC'];

    /**
     * @param JwksProvider          $jwks
     * @param string                $issuer        Expected `iss` (ProviderMetadata::$issuer).
     * @param string                $clientId      Expected audience.
     * @param int                   $leewaySeconds Allowed clock skew for exp/nbf/iat.
     * @param (Closure(): int)|null $clock         Current Unix time; null = time().
     */
    public function __construct(
        private readonly JwksProvider $jwks,
        private readonly string $issuer,
        private readonly string $clientId,
        private readonly int $leewaySeconds = 60,
        private readonly ?Closure $clock = null,
    ) {
    }

    /**
     * @param string      $idToken       Compact JWS from the token response.
     * @param string|null $expectedNonce The nonce of the authorization request; null skips the check
     *                                   (only for flows that sent none, e.g. a refresh response).
     *
     * @return IdTokenClaims
     * @throws OAuthException When the token is malformed, unsigned, wrongly signed or fails a claim check.
     */
    public function validate(string $idToken, ?string $expectedNonce): IdTokenClaims
    {
        $parts = explode('.', $idToken);

        if (count($parts) !== 3) {
            throw new OAuthException('id_token is not a compact JWS (three dot-separated parts).');
        }

        [$encodedHeader, $encodedPayload, $encodedSignature] = $parts;
        $header = self::decodeJson($encodedHeader, 'header');
        $claims = self::decodeJson($encodedPayload, 'payload');
        $signature = self::base64UrlDecode($encodedSignature, 'signature');

        $algorithm = $header['alg'] ?? null;

        if (!is_string($algorithm) || !isset(self::ALGORITHMS[$algorithm])) {
            throw new OAuthException('id_token algorithm "' . (is_string($algorithm) ? $algorithm : '?') . '" is not accepted; expected RS256 or ES256.');
        }

        if (array_key_exists('crit', $header)) {
            throw new OAuthException('id_token carries unsupported critical header parameters.');
        }

        $kid = $header['kid'] ?? null;

        if ($kid !== null && !is_string($kid)) {
            throw new OAuthException('id_token "kid" header must be a string.');
        }

        $key = $this->findKey($algorithm, $kid);
        $signingInput = $encodedHeader . '.' . $encodedPayload;

        if (!self::verifySignature($algorithm, $key, $signingInput, $signature)) {
            throw new OAuthException('id_token signature verification failed.');
        }

        return $this->checkClaims($claims, $expectedNonce);
    }

    /**
     * @param string      $algorithm
     * @param string|null $kid
     *
     * @return array<string, mixed>
     * @throws OAuthException
     */
    private function findKey(string $algorithm, ?string $kid): array
    {
        $candidates = $this->candidates($this->jwks->keys(), $algorithm, $kid);

        if ($candidates === [] && $kid !== null) {
            $candidates = $this->candidates($this->jwks->keys(refresh: true), $algorithm, $kid);
        }

        if (count($candidates) !== 1) {
            throw new OAuthException($candidates === []
                ? 'No JWKS key matches the id_token' . ($kid !== null ? " kid \"{$kid}\"" : '') . " for {$algorithm}."
                : "id_token has no kid and the JWKS holds several {$algorithm} keys.");
        }

        return $candidates[0];
    }

    /**
     * @param list<array<string, mixed>> $keys
     * @param string                     $algorithm
     * @param string|null                $kid
     *
     * @return list<array<string, mixed>>
     */
    private function candidates(array $keys, string $algorithm, ?string $kid): array
    {
        return array_values(array_filter($keys, static fn (array $key): bool => ($key['kty'] ?? null) === self::ALGORITHMS[$algorithm]
            && ($kid === null || ($key['kid'] ?? null) === $kid)
            && (!isset($key['alg']) || $key['alg'] === $algorithm)
            && (!isset($key['use']) || $key['use'] === 'sig')));
    }

    /**
     * @param string               $algorithm
     * @param array<string, mixed> $jwk
     * @param string               $data
     * @param string               $signature
     *
     * @return bool
     * @throws OAuthException When the JWK cannot be turned into a public key.
     */
    private static function verifySignature(string $algorithm, array $jwk, string $data, string $signature): bool
    {
        if ($algorithm === 'ES256') {
            if (strlen($signature) !== 64) {
                return false;
            }

            // JWS carries ECDSA signatures as raw r || s; OpenSSL expects DER.
            $signature = self::derSequence(self::derInteger(substr($signature, 0, 32)) . self::derInteger(substr($signature, 32)));
        }

        $publicKey = openssl_pkey_get_public($algorithm === 'RS256' ? self::rsaPem($jwk) : self::ecPem($jwk));

        if ($publicKey === false) {
            throw new OAuthException("JWKS key could not be loaded for {$algorithm}.");
        }

        return openssl_verify($data, $signature, $publicKey, OPENSSL_ALGO_SHA256) === 1;
    }

    /**
     * @param array<string, mixed> $claims
     * @param string|null          $expectedNonce
     *
     * @return IdTokenClaims
     * @throws OAuthException
     */
    private function checkClaims(array $claims, ?string $expectedNonce): IdTokenClaims
    {
        $now = $this->clock !== null ? ($this->clock)() : time();

        if (($claims['iss'] ?? null) !== $this->issuer) {
            throw new OAuthException('id_token issuer does not match the configured issuer.');
        }

        $audience = $claims['aud'] ?? null;
        $audience = is_string($audience) ? [$audience] : $audience;

        if (!is_array($audience) || !array_is_list($audience) || !in_array($this->clientId, $audience, true)) {
            throw new OAuthException('id_token audience does not contain this client.');
        }

        /** @var list<string> $audience */
        $azp = $claims['azp'] ?? null;

        if (($azp !== null || count($audience) > 1) && $azp !== $this->clientId) {
            throw new OAuthException('id_token authorized party (azp) is not this client.');
        }

        $exp = $claims['exp'] ?? null;
        $iat = $claims['iat'] ?? null;

        if (!is_int($exp) || !is_int($iat)) {
            throw new OAuthException('id_token is missing a numeric exp or iat claim.');
        }

        if ($exp + $this->leewaySeconds <= $now) {
            throw new OAuthException('id_token has expired.');
        }

        if ($iat - $this->leewaySeconds > $now) {
            throw new OAuthException('id_token was issued in the future.');
        }

        $nbf = $claims['nbf'] ?? null;

        if ($nbf !== null && (!is_int($nbf) || $nbf - $this->leewaySeconds > $now)) {
            throw new OAuthException('id_token is not valid yet (nbf).');
        }

        $subject = $claims['sub'] ?? null;

        if (!is_string($subject) || $subject === '') {
            throw new OAuthException('id_token has no subject (sub).');
        }

        $nonce = $claims['nonce'] ?? null;

        if ($nonce !== null && !is_string($nonce)) {
            throw new OAuthException('id_token nonce must be a string.');
        }

        if ($expectedNonce !== null && ($nonce === null || !hash_equals($expectedNonce, $nonce))) {
            throw new OAuthException('id_token nonce does not match the authorization request.');
        }

        return new IdTokenClaims($subject, $this->issuer, $audience, $exp, $iat, $nonce, $claims);
    }

    /**
     * @param string $part
     * @param string $label
     *
     * @return array<string, mixed>
     * @throws OAuthException
     */
    private static function decodeJson(string $part, string $label): array
    {
        $decoded = json_decode(self::base64UrlDecode($part, $label), true);

        if (!is_array($decoded) || ($decoded !== [] && array_is_list($decoded))) {
            throw new OAuthException("id_token {$label} is not a JSON object.");
        }

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    /**
     * @param string $value
     * @param string $label
     *
     * @return string
     * @throws OAuthException
     */
    private static function base64UrlDecode(string $value, string $label): string
    {
        $decoded = base64_decode(strtr($value, '-_', '+/'), true);

        if ($decoded === false || preg_match('/^[A-Za-z0-9_-]*$/', $value) !== 1) {
            throw new OAuthException("id_token {$label} is not valid base64url.");
        }

        return $decoded;
    }

    /**
     * @param array<string, mixed> $jwk
     *
     * @return string
     * @throws OAuthException
     */
    private static function rsaPem(array $jwk): string
    {
        $n = is_string($jwk['n'] ?? null) ? self::base64UrlDecode($jwk['n'], 'JWK n') : '';
        $e = is_string($jwk['e'] ?? null) ? self::base64UrlDecode($jwk['e'], 'JWK e') : '';

        if ($n === '' || $e === '') {
            throw new OAuthException('RSA JWK is missing n or e.');
        }

        $rsaPublicKey = self::derSequence(self::derInteger($n) . self::derInteger($e));
        // AlgorithmIdentifier { rsaEncryption, NULL }
        $spki = self::derSequence(hex2bin('300d06092a864886f70d0101010500') . "\x03" . self::derLength(strlen($rsaPublicKey) + 1) . "\x00" . $rsaPublicKey);

        return self::pem($spki);
    }

    /**
     * @param array<string, mixed> $jwk
     *
     * @return string
     * @throws OAuthException
     */
    private static function ecPem(array $jwk): string
    {
        $x = is_string($jwk['x'] ?? null) ? self::base64UrlDecode($jwk['x'], 'JWK x') : '';
        $y = is_string($jwk['y'] ?? null) ? self::base64UrlDecode($jwk['y'], 'JWK y') : '';

        if (($jwk['crv'] ?? null) !== 'P-256' || strlen($x) !== 32 || strlen($y) !== 32) {
            throw new OAuthException('EC JWK must be a P-256 key with 32-byte x and y.');
        }

        // SubjectPublicKeyInfo { id-ecPublicKey, prime256v1 } + uncompressed point
        return self::pem(hex2bin('3059301306072a8648ce3d020106082a8648ce3d030107034200') . "\x04" . $x . $y);
    }

    private static function pem(string $der): string
    {
        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    private static function derInteger(string $bytes): string
    {
        $bytes = ltrim($bytes, "\x00");

        if ($bytes === '' || ord($bytes[0]) > 0x7f) {
            $bytes = "\x00" . $bytes;
        }

        return "\x02" . self::derLength(strlen($bytes)) . $bytes;
    }

    private static function derSequence(string $content): string
    {
        return "\x30" . self::derLength(strlen($content)) . $content;
    }

    /**
     * @param int<0, max> $length
     */
    private static function derLength(int $length): string
    {
        if ($length < 0x80) {
            return pack('C', $length);
        }

        $bytes = ltrim(pack('N', $length), "\x00");

        return pack('C', 0x80 | strlen($bytes)) . $bytes;
    }
}
