<?php

declare(strict_types=1);

namespace Tests;

use EzPhp\HttpClient\FakeTransport;
use EzPhp\HttpClient\HttpClient;
use EzPhp\HttpClient\HttpResponse;
use EzPhp\OAuth\OAuthClient;
use EzPhp\OAuth\OAuthException;
use EzPhp\OAuth\OAuthProvider;
use EzPhp\OAuth\SessionOAuthStateStore;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;

/**
 * Class OAuthClientTest
 *
 * @package Tests
 */
#[CoversClass(OAuthClient::class)]
#[UsesClass(OAuthProvider::class)]
#[UsesClass(SessionOAuthStateStore::class)]
final class OAuthClientTest extends TestCase
{
    private OAuthProvider $provider;

    protected function setUp(): void
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }

        $_SESSION = [];

        $this->provider = new OAuthProvider(
            authorizeUrl: 'https://provider.example.com/oauth/authorize',
            tokenUrl: 'https://provider.example.com/oauth/token',
            clientId: 'client-id',
            clientSecret: 'client-secret',
            redirectUri: 'https://app.example.com/oauth/callback',
            scopes: ['profile', 'email'],
        );
    }

    protected function tearDown(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_write_close();
        }

        $_SESSION = [];
    }

    public function testCreateAuthorizationUrlContainsRequiredParameters(): void
    {
        $client = $this->makeClient();

        $url = $client->createAuthorizationUrl();

        self::assertStringStartsWith('https://provider.example.com/oauth/authorize?', $url);

        $query = $this->queryOf($url);

        self::assertSame('code', $query['response_type']);
        self::assertSame('client-id', $query['client_id']);
        self::assertSame('https://app.example.com/oauth/callback', $query['redirect_uri']);
        self::assertSame('profile email', $query['scope']);
        self::assertSame('S256', $query['code_challenge_method']);
        self::assertNotEmpty($query['state']);
        self::assertNotEmpty($query['code_challenge']);
    }

    public function testCreateAuthorizationUrlGeneratesFreshStateEachCall(): void
    {
        $client = $this->makeClient();

        $first = $this->queryOf($client->createAuthorizationUrl());
        $second = $this->queryOf($client->createAuthorizationUrl());

        self::assertNotSame($first['state'], $second['state']);
    }

    public function testCreateAuthorizationUrlMergesExtraParams(): void
    {
        $client = $this->makeClient();

        $url = $client->createAuthorizationUrl(['prompt' => 'consent']);

        $query = $this->queryOf($url);

        self::assertSame('consent', $query['prompt']);
    }

    public function testExchangeCodeSendsPkceVerifierAndReturnsToken(): void
    {
        $transport = new FakeTransport([
            'https://provider.example.com/oauth/token' => HttpResponse::fake([
                'access_token' => 'access-123',
                'token_type' => 'Bearer',
                'expires_in' => 3600,
                'refresh_token' => 'refresh-456',
            ]),
        ]);

        $client = $this->makeClient($transport);

        $query = $this->queryOf($client->createAuthorizationUrl());

        $token = $client->exchangeCode('auth-code', $query['state']);

        self::assertSame('access-123', $token->accessToken);
        self::assertSame('refresh-456', $token->refreshToken);

        $recorded = $transport->getRecorded();
        self::assertCount(1, $recorded);
        self::assertSame('POST', $recorded[0]['method']);

        parse_str($recorded[0]['body'], $sentForm);
        self::assertSame('authorization_code', $sentForm['grant_type']);
        self::assertSame('auth-code', $sentForm['code']);
        self::assertSame('client-secret', $sentForm['client_secret']);
        self::assertNotEmpty($sentForm['code_verifier']);
    }

    public function testExchangeCodeThrowsOnUnknownState(): void
    {
        $client = $this->makeClient();

        $this->expectException(OAuthException::class);

        $client->exchangeCode('auth-code', 'never-issued-state');
    }

    public function testExchangeCodeIsOneTimeUsePerState(): void
    {
        $transport = new FakeTransport([
            '*' => HttpResponse::fake(['access_token' => 'access-123']),
        ]);

        $client = $this->makeClient($transport);

        $state = $this->queryOf($client->createAuthorizationUrl())['state'];

        $client->exchangeCode('auth-code', $state);

        $this->expectException(OAuthException::class);

        $client->exchangeCode('auth-code', $state);
    }

    public function testExchangeCodeThrowsOnTokenEndpointErrorStatus(): void
    {
        $transport = new FakeTransport([
            '*' => HttpResponse::fake(['error' => 'invalid_grant'], 400),
        ]);

        $client = $this->makeClient($transport);

        $query = $this->queryOf($client->createAuthorizationUrl());

        $this->expectException(OAuthException::class);

        $client->exchangeCode('auth-code', $query['state']);
    }

    public function testRefreshSendsRefreshTokenGrant(): void
    {
        $transport = new FakeTransport([
            '*' => HttpResponse::fake(['access_token' => 'access-new']),
        ]);

        $client = $this->makeClient($transport);

        $token = $client->refresh('refresh-456');

        self::assertSame('access-new', $token->accessToken);

        parse_str($transport->getRecorded()[0]['body'], $sentForm);
        self::assertSame('refresh_token', $sentForm['grant_type']);
        self::assertSame('refresh-456', $sentForm['refresh_token']);
    }

    private function makeClient(?FakeTransport $transport = null): OAuthClient
    {
        $http = new HttpClient($transport ?? new FakeTransport());

        return new OAuthClient($this->provider, $http, new SessionOAuthStateStore());
    }

    /**
     * @param string $url
     *
     * @return array<string, string>
     */
    private function queryOf(string $url): array
    {
        $queryString = parse_url($url, PHP_URL_QUERY);
        parse_str(is_string($queryString) ? $queryString : '', $query);

        /** @var array<string, string> $query */
        return $query;
    }
}
