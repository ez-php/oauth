<?php

declare(strict_types=1);

namespace Tests;

use EzPhp\Cache\ArrayDriver;
use EzPhp\HttpClient\FakeTransport;
use EzPhp\HttpClient\HttpClient;
use EzPhp\HttpClient\HttpResponse;
use EzPhp\OAuth\OAuthException;
use EzPhp\OAuth\Oidc\IdTokenClaims;
use EzPhp\OAuth\Oidc\IdTokenValidator;
use EzPhp\OAuth\Oidc\JwksProvider;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\Support\OAuthOidcSigner;

#[CoversClass(IdTokenValidator::class)]
#[CoversClass(IdTokenClaims::class)]
#[CoversClass(JwksProvider::class)]
final class OidcIdTokenValidatorTest extends TestCase
{
    private const string ISSUER = 'https://idp.example.com';
    private const string JWKS_URI = 'https://idp.example.com/jwks';
    private const int NOW = 1_800_000_000;

    private static ?OAuthOidcSigner $rsa = null;

    private static ?OAuthOidcSigner $ec = null;

    private static function rsa(): OAuthOidcSigner
    {
        return self::$rsa ??= new OAuthOidcSigner('RS256', 'rsa-1');
    }

    private static function ec(): OAuthOidcSigner
    {
        return self::$ec ??= new OAuthOidcSigner('ES256', 'ec-1');
    }

    /**
     * @param list<array<string, string>> ...$keySets One JWKS per expected fetch.
     */
    private function validator(array ...$keySets): IdTokenValidator
    {
        $keySets = $keySets === [] ? [[self::rsa()->jwk(), self::ec()->jwk()]] : $keySets;
        $transport = FakeTransport::sequence(array_values(array_map(
            static fn (array $keys): HttpResponse => HttpResponse::fake(['keys' => $keys]),
            $keySets,
        )));
        $jwks = new JwksProvider(new HttpClient($transport), self::JWKS_URI);

        return new IdTokenValidator($jwks, self::ISSUER, 'client-id', 60, static fn (): int => self::NOW);
    }

    /**
     * @param array<string, mixed> $overrides
     *
     * @return array<string, mixed>
     */
    private static function claims(array $overrides = []): array
    {
        return array_filter(array_merge([
            'iss' => self::ISSUER,
            'sub' => 'user-123',
            'aud' => 'client-id',
            'exp' => self::NOW + 300,
            'iat' => self::NOW - 10,
            'nonce' => 'n-1',
            'email' => 'ada@example.com',
        ], $overrides), static fn (mixed $v): bool => $v !== null);
    }

    public function testValidRs256Token(): void
    {
        $claims = $this->validator()->validate(self::rsa()->sign(self::claims()), 'n-1');

        self::assertSame('user-123', $claims->subject);
        self::assertSame(['client-id'], $claims->audience);
        self::assertSame('ada@example.com', $claims->get('email'));
        self::assertSame('n-1', $claims->nonce);
        self::assertNull($claims->get('missing'));
    }

    public function testValidEs256Token(): void
    {
        $claims = $this->validator()->validate(self::ec()->sign(self::claims()), 'n-1');

        self::assertSame('user-123', $claims->subject);
    }

    public function testExpiryWithinLeewayIsAccepted(): void
    {
        $claims = $this->validator()->validate(self::rsa()->sign(self::claims(['exp' => self::NOW - 30])), 'n-1');

        self::assertSame(self::NOW - 30, $claims->expiresAt);
    }

    public function testUnknownKidRefreshesTheKeySetOnce(): void
    {
        $rotated = new OAuthOidcSigner('RS256', 'rsa-2');
        $validator = $this->validator([self::rsa()->jwk()], [self::rsa()->jwk(), $rotated->jwk()]);

        self::assertSame('user-123', $validator->validate($rotated->sign(self::claims()), 'n-1')->subject);
    }

    public function testForcedRefreshesAreThrottledWithinTheCooldown(): void
    {
        $now = self::NOW;
        $keys = ['keys' => [self::rsa()->jwk()]];
        $transport = FakeTransport::sequence([HttpResponse::fake($keys), HttpResponse::fake($keys), HttpResponse::fake($keys)]);
        $jwks = new JwksProvider(new HttpClient($transport), self::JWKS_URI, refreshCooldownSeconds: 60, clock: static function () use (&$now): int {
            return $now;
        });
        $validator = new IdTokenValidator($jwks, self::ISSUER, 'client-id', 60, static fn (): int => self::NOW);
        $unknownKid = static function () use ($validator): void {
            try {
                $validator->validate(self::rsa()->sign(self::claims(), ['kid' => 'k-' . bin2hex(random_bytes(4))]), 'n-1');
                self::fail('An unknown kid must be rejected.');
            } catch (OAuthException) {
            }
        };

        $unknownKid(); // initial fetch + one forced refresh
        $unknownKid(); // inside the cooldown: no further fetch
        self::assertCount(2, $transport->getRecorded());

        $now += 61;
        $unknownKid(); // cooldown over: refreshes again
        self::assertCount(3, $transport->getRecorded());
    }

    public function testTheRefreshCooldownIsSharedThroughTheCache(): void
    {
        $cache = new ArrayDriver();
        $keys = ['keys' => [self::rsa()->jwk()]];
        $first = FakeTransport::sequence([HttpResponse::fake($keys), HttpResponse::fake($keys)]);
        $second = new FakeTransport();

        (new JwksProvider(new HttpClient($first), self::JWKS_URI, $cache))->keys(refresh: true);
        $other = (new JwksProvider(new HttpClient($second), self::JWKS_URI, $cache))->keys(refresh: true);

        self::assertSame([self::rsa()->jwk()], $other);
        self::assertSame([], $second->getRecorded());
    }

    public function testTokenWithoutKidUsesTheOnlyMatchingKey(): void
    {
        $claims = $this->validator([self::rsa()->jwk()])->validate(self::rsa()->sign(self::claims(), ['kid' => null]), 'n-1');

        self::assertSame('user-123', $claims->subject);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function rejectedTokens(): iterable
    {
        $rsa = self::rsa();
        $ec = self::ec();
        $valid = $rsa->sign(self::claims());
        [$h, $p] = explode('.', $valid);

        yield 'alg none' => [OAuthOidcSigner::b64('{"alg":"none"}') . '.' . $p . '.', 'is not accepted'];
        yield 'alg HS256' => [OAuthOidcSigner::b64('{"alg":"HS256","kid":"rsa-1"}') . '.' . $p . '.' . OAuthOidcSigner::b64(hash_hmac('sha256', 'x', 'k', true)), 'is not accepted'];
        yield 'crit header' => [$rsa->sign(self::claims(), ['crit' => ['exp']]), 'critical header'];
        yield 'tampered payload' => [$h . '.' . OAuthOidcSigner::b64((string) json_encode(self::claims(['sub' => 'admin']))) . '.' . explode('.', $valid)[2], 'signature verification failed'];
        yield 'RS256 header naming the EC key' => [$rsa->sign(self::claims(), ['kid' => 'ec-1']), 'No JWKS key matches'];
        yield 'ES256 header naming the RSA key' => [$ec->sign(self::claims(), ['kid' => 'rsa-1']), 'No JWKS key matches'];
        yield 'unknown kid after refresh' => [$rsa->sign(self::claims(), ['kid' => 'nope']), 'No JWKS key matches'];
        yield 'wrong issuer' => [$rsa->sign(self::claims(['iss' => 'https://evil.example.com'])), 'issuer'];
        yield 'wrong audience' => [$rsa->sign(self::claims(['aud' => 'other-client'])), 'audience'];
        yield 'several audiences without azp' => [$rsa->sign(self::claims(['aud' => ['client-id', 'other']])), 'azp'];
        yield 'foreign azp' => [$rsa->sign(self::claims(['azp' => 'other'])), 'azp'];
        yield 'expired beyond leeway' => [$rsa->sign(self::claims(['exp' => self::NOW - 61])), 'expired'];
        yield 'issued in the future' => [$rsa->sign(self::claims(['iat' => self::NOW + 120])), 'future'];
        yield 'not before' => [$rsa->sign(self::claims(['nbf' => self::NOW + 120])), 'nbf'];
        yield 'missing exp' => [$rsa->sign(self::claims(['exp' => null])), 'exp or iat'];
        yield 'missing sub' => [$rsa->sign(self::claims(['sub' => null])), 'subject'];
        yield 'wrong nonce' => [$rsa->sign(self::claims(['nonce' => 'n-2'])), 'nonce'];
        yield 'missing nonce' => [$rsa->sign(self::claims(['nonce' => null])), 'nonce'];
        yield 'two parts' => ['a.b', 'compact JWS'];
        yield 'bad base64' => ['***.' . $p . '.x', 'base64url'];
        yield 'payload not an object' => [$h . '.' . OAuthOidcSigner::b64('[1]') . '.x', 'JSON object'];
    }

    #[DataProvider('rejectedTokens')]
    public function testRejectsToken(string $token, string $message): void
    {
        $this->expectException(OAuthException::class);
        $this->expectExceptionMessage($message);

        $keys = [self::rsa()->jwk(), self::ec()->jwk()];
        $this->validator($keys, $keys)->validate($token, 'n-1');
    }

    public function testNoKidWithSeveralKeysOfTheTypeIsRejected(): void
    {
        $second = new OAuthOidcSigner('RS256', 'rsa-2');

        $this->expectException(OAuthException::class);
        $this->expectExceptionMessage('several RS256 keys');

        $this->validator([self::rsa()->jwk(), $second->jwk()])->validate(self::rsa()->sign(self::claims(), ['kid' => null]), 'n-1');
    }

    public function testNullExpectedNonceSkipsTheNonceCheck(): void
    {
        self::assertNull($this->validator()->validate(self::rsa()->sign(self::claims(['nonce' => null])), null)->nonce);
    }
}
