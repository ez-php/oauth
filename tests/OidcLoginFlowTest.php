<?php

declare(strict_types=1);

namespace Tests;

use EzPhp\Cache\ArrayDriver;
use EzPhp\HttpClient\FakeTransport;
use EzPhp\HttpClient\HttpClient;
use EzPhp\HttpClient\HttpClientException;
use EzPhp\HttpClient\HttpResponse;
use EzPhp\OAuth\OAuthClient;
use EzPhp\OAuth\OAuthException;
use EzPhp\OAuth\OAuthProvider;
use EzPhp\OAuth\OAuthToken;
use EzPhp\OAuth\Oidc\IdTokenClaims;
use EzPhp\OAuth\Oidc\IdTokenValidator;
use EzPhp\OAuth\Oidc\JwksProvider;
use EzPhp\OAuth\Oidc\ProviderMetadata;
use EzPhp\OAuth\Pkce;
use EzPhp\OAuth\SessionOAuthStateStore;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use Tests\Support\OAuthOidcSigner;

#[CoversClass(OAuthClient::class)]
#[CoversClass(OAuthToken::class)]
#[CoversClass(ProviderMetadata::class)]
#[CoversClass(JwksProvider::class)]
#[UsesClass(IdTokenValidator::class)]
#[UsesClass(IdTokenClaims::class)]
#[UsesClass(OAuthProvider::class)]
#[UsesClass(Pkce::class)]
#[UsesClass(SessionOAuthStateStore::class)]
final class OidcLoginFlowTest extends TestCase
{
    private const string ISSUER = 'https://idp.example.com';

    protected function setUp(): void
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }

        $_SESSION = [];
    }

    protected function tearDown(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_write_close();
        }

        $_SESSION = [];
    }

    /**
     * @return array<string, mixed>
     */
    private static function discoveryDocument(string $issuer = self::ISSUER): array
    {
        return [
            'issuer' => $issuer,
            'authorization_endpoint' => self::ISSUER . '/authorize',
            'token_endpoint' => self::ISSUER . '/token',
            'jwks_uri' => self::ISSUER . '/jwks',
            'userinfo_endpoint' => self::ISSUER . '/userinfo',
        ];
    }

    /**
     * @return array<string, string>
     */
    private static function queryOf(string $url): array
    {
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

        /** @var array<string, string> $query */
        return $query;
    }

    public function testDiscoveryBuildsAnOpenIdProvider(): void
    {
        $http = new HttpClient(new FakeTransport([self::ISSUER . '/.well-known/openid-configuration' => HttpResponse::fake(self::discoveryDocument())]));

        $metadata = ProviderMetadata::discover($http, self::ISSUER);
        $provider = $metadata->toProvider('client-id', 'secret', 'https://app.example.com/cb', ['email']);

        self::assertSame(self::ISSUER . '/jwks', $metadata->jwksUri);
        self::assertSame(self::ISSUER . '/userinfo', $metadata->userinfoEndpoint);
        self::assertSame(self::ISSUER . '/authorize', $provider->authorizeUrl);
        self::assertSame(self::ISSUER . '/token', $provider->tokenUrl);
        self::assertSame(['openid', 'email'], $provider->scopes);
    }

    public function testDiscoveryRejectsADocumentForAnotherIssuer(): void
    {
        $http = new HttpClient(new FakeTransport(['*' => HttpResponse::fake(self::discoveryDocument('https://evil.example.com'))]));

        $this->expectException(OAuthException::class);
        $this->expectExceptionMessage('expected "https://idp.example.com"');

        ProviderMetadata::discover($http, self::ISSUER);
    }

    public function testDiscoveryRejectsIncompleteOrUnreadableDocuments(): void
    {
        $document = self::discoveryDocument();
        unset($document['jwks_uri']);

        try {
            ProviderMetadata::discover(new HttpClient(new FakeTransport(['*' => HttpResponse::fake($document)])), self::ISSUER);
            self::fail('missing jwks_uri accepted');
        } catch (OAuthException $e) {
            self::assertStringContainsString('jwks_uri', $e->getMessage());
        }

        try {
            ProviderMetadata::discover(new HttpClient(new FakeTransport(['*' => HttpResponse::fake('oops', 500)])), self::ISSUER);
            self::fail('500 accepted');
        } catch (OAuthException $e) {
            self::assertStringContainsString('status 500', $e->getMessage());
        }

        $this->expectException(OAuthException::class);
        $this->expectExceptionMessage('discovery request');
        ProviderMetadata::discover(new HttpClient(new FakeTransport(['*' => new HttpClientException('down')])), self::ISSUER);
    }

    public function testJwksAreCachedAcrossProviderInstances(): void
    {
        $cache = new ArrayDriver();
        $first = new FakeTransport(['*' => HttpResponse::fake(['keys' => [['kty' => 'RSA', 'kid' => 'k1'], 'junk']])]);
        $second = new FakeTransport();

        $keys = (new JwksProvider(new HttpClient($first), self::ISSUER . '/jwks', $cache))->keys();
        $cached = (new JwksProvider(new HttpClient($second), self::ISSUER . '/jwks', $cache))->keys();

        self::assertSame([['kty' => 'RSA', 'kid' => 'k1']], $keys);
        self::assertSame($keys, $cached);
        self::assertSame([], $second->getRecorded());
    }

    public function testUnreadableJwksThrows(): void
    {
        $this->expectException(OAuthException::class);
        $this->expectExceptionMessage('could not be read');

        (new JwksProvider(new HttpClient(new FakeTransport(['*' => HttpResponse::fake(['nope' => 1])])), self::ISSUER . '/jwks'))->keys();
    }

    public function testOpenIdLoginSendsANonceAndReturnsVerifiedClaims(): void
    {
        $signer = new OAuthOidcSigner('RS256', 'k1');
        $metadata = ProviderMetadata::fromArray(self::discoveryDocument());
        $provider = $metadata->toProvider('client-id', 'secret', 'https://app.example.com/cb');
        $makeClient = static function (FakeTransport $transport) use ($metadata, $provider): OAuthClient {
            $http = new HttpClient($transport);
            $validator = new IdTokenValidator(new JwksProvider($http, $metadata->jwksUri), $metadata->issuer, 'client-id');

            return new OAuthClient($provider, $http, new SessionOAuthStateStore(), idTokenValidator: $validator);
        };

        $query = self::queryOf($makeClient(new FakeTransport())->createAuthorizationUrl());
        self::assertNotEmpty($query['nonce']);

        // The callback request: the state store (session) carries the nonce over.
        $idToken = $signer->sign(['iss' => self::ISSUER, 'sub' => 'u-1', 'aud' => 'client-id', 'exp' => time() + 300, 'iat' => time(), 'nonce' => $query['nonce']]);
        $token = $makeClient(new FakeTransport([
            self::ISSUER . '/jwks' => HttpResponse::fake(['keys' => [$signer->jwk()]]),
            self::ISSUER . '/token' => HttpResponse::fake(['access_token' => 'at', 'id_token' => $idToken]),
        ]))->exchangeCode('code', $query['state']);

        self::assertSame($idToken, $token->idToken);
        self::assertSame('u-1', $token->idTokenClaims?->subject);
        self::assertArrayNotHasKey('id_token', $token->toStorage());
        self::assertSame('u-1', $token->withIssuedAt(1)->withRefreshToken('r')->idTokenClaims?->subject);
    }

    public function testOpenIdLoginWithoutIdTokenInTheResponseFails(): void
    {
        $metadata = ProviderMetadata::fromArray(self::discoveryDocument());
        $provider = $metadata->toProvider('client-id', 'secret', 'https://app.example.com/cb');
        $http = new HttpClient(new FakeTransport(['*' => HttpResponse::fake(['access_token' => 'at'])]));
        $validator = new IdTokenValidator(new JwksProvider($http, $metadata->jwksUri), $metadata->issuer, 'client-id');
        $client = new OAuthClient($provider, $http, new SessionOAuthStateStore(), idTokenValidator: $validator);
        $query = self::queryOf($client->createAuthorizationUrl());

        $this->expectException(OAuthException::class);
        $this->expectExceptionMessage('missing the "id_token"');

        $client->exchangeCode('code', $query['state']);
    }

    public function testPlainOAuthLoginSendsNoNonceAndSkipsValidation(): void
    {
        $provider = new OAuthProvider(self::ISSUER . '/authorize', self::ISSUER . '/token', 'client-id', 'secret', 'https://app.example.com/cb', ['email']);
        $http = new HttpClient(new FakeTransport(['*' => HttpResponse::fake(['access_token' => 'at', 'id_token' => 'not.a.jwt'])]));
        $validator = new IdTokenValidator(new JwksProvider($http, self::ISSUER . '/jwks'), self::ISSUER, 'client-id');
        $client = new OAuthClient($provider, $http, new SessionOAuthStateStore(), idTokenValidator: $validator);
        $query = self::queryOf($client->createAuthorizationUrl());

        self::assertArrayNotHasKey('nonce', $query);

        $token = $client->exchangeCode('code', $query['state']);
        self::assertSame('not.a.jwt', $token->idToken);
        self::assertNull($token->idTokenClaims);
    }
}
