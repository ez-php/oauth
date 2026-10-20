<?php

declare(strict_types=1);

namespace Tests;

use EzPhp\HttpClient\HttpClient;
use EzPhp\HttpClient\HttpClientException;
use EzPhp\HttpClient\HttpResponse;
use EzPhp\OAuth\InMemoryOAuthTokenStore;
use EzPhp\OAuth\OAuthClient;
use EzPhp\OAuth\OAuthException;
use EzPhp\OAuth\OAuthProvider;
use EzPhp\OAuth\OAuthStateStoreInterface;
use EzPhp\OAuth\OAuthToken;
use EzPhp\OAuth\OAuthTokenManager;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use Tests\Support\OAuthSequenceTransport;

/**
 * @package Tests
 */
#[CoversClass(OAuthTokenManager::class)]
#[UsesClass(OAuthClient::class)]
#[UsesClass(OAuthToken::class)]
#[UsesClass(OAuthProvider::class)]
#[UsesClass(OAuthException::class)]
#[UsesClass(InMemoryOAuthTokenStore::class)]
final class OAuthTokenManagerTest extends TestCase
{
    private const int NOW = 1_000_000;

    private InMemoryOAuthTokenStore $store;

    protected function setUp(): void
    {
        parent::setUp();
        $this->store = new InMemoryOAuthTokenStore();
    }

    /**
     * @param list<HttpResponse|HttpClientException> $responses
     *
     * @return array{OAuthTokenManager, OAuthSequenceTransport, HttpClient}
     */
    private function manager(array $responses): array
    {
        $transport = new OAuthSequenceTransport($responses);
        $http = new HttpClient($transport);
        $client = new OAuthClient(
            new OAuthProvider('https://auth.test/authorize', 'https://auth.test/token', 'id', 'secret', 'https://app.test/cb'),
            $http,
            new class () implements OAuthStateStoreInterface {
                public function put(string $state, array $payload, int $ttlSeconds): void
                {
                }

                public function pull(string $state): ?array
                {
                    return null;
                }
            },
        );

        return [new OAuthTokenManager($client, $this->store, 'spotify:1', 30, static fn (): int => self::NOW), $transport, $http];
    }

    private function token(string $access, ?int $expiresIn, ?string $refresh, int $issuedAt = self::NOW): OAuthToken
    {
        return new OAuthToken($access, 'bearer', $expiresIn, $refresh, null, $issuedAt);
    }

    private static function tokenResponse(string $access, ?string $refresh = null): HttpResponse
    {
        $data = ['access_token' => $access, 'token_type' => 'bearer', 'expires_in' => 3600];

        if ($refresh !== null) {
            $data['refresh_token'] = $refresh;
        }

        return new HttpResponse(200, (string) json_encode($data));
    }

    public function test_valid_token_is_sent_as_bearer_without_refresh(): void
    {
        [$manager, $transport, $http] = $this->manager([new HttpResponse(200, 'ok')]);
        $this->store->put('spotify:1', $this->token('A', 3600, 'R'));

        $response = $manager->send($http->get('https://api.test/me'));

        $this->assertSame('ok', $response->body());
        $this->assertCount(1, $transport->requests);
        $this->assertSame('Bearer A', $transport->requests[0]['headers']['Authorization'] ?? null);
    }

    public function test_token_expiring_within_the_leeway_is_refreshed_first(): void
    {
        [$manager, $transport, $http] = $this->manager([self::tokenResponse('B', 'R2'), new HttpResponse(200, 'ok')]);
        $this->store->put('spotify:1', $this->token('A', 3600, 'R', issuedAt: self::NOW - 3590));

        $manager->send($http->get('https://api.test/me'));

        $this->assertSame('https://auth.test/token', $transport->requests[0]['url']);
        $this->assertStringContainsString('grant_type=refresh_token', $transport->requests[0]['body']);
        $this->assertSame('Bearer B', $transport->requests[1]['headers']['Authorization'] ?? null);
        $stored = $this->store->get('spotify:1');
        $this->assertNotNull($stored);
        $this->assertSame('R2', $stored->refreshToken);
        $this->assertSame(self::NOW, $stored->issuedAt);
    }

    public function test_401_refreshes_once_and_retries_once(): void
    {
        [$manager, $transport, $http] = $this->manager([
            new HttpResponse(401, 'expired'),
            self::tokenResponse('B'),
            new HttpResponse(200, 'ok'),
        ]);
        $this->store->put('spotify:1', $this->token('A', null, 'R'));

        $response = $manager->send($http->get('https://api.test/me'));

        $this->assertSame(200, $response->status());
        $this->assertCount(3, $transport->requests);
        $this->assertSame('Bearer B', $transport->requests[2]['headers']['Authorization'] ?? null);
    }

    public function test_second_401_is_returned_not_retried_again(): void
    {
        [$manager, $transport, $http] = $this->manager([
            new HttpResponse(401, ''),
            self::tokenResponse('B'),
            new HttpResponse(401, 'still'),
        ]);
        $this->store->put('spotify:1', $this->token('A', null, 'R'));

        $this->assertSame(401, $manager->send($http->get('https://api.test/me'))->status());
        $this->assertCount(3, $transport->requests);
    }

    public function test_refresh_without_a_new_refresh_token_keeps_the_old_one(): void
    {
        [$manager] = $this->manager([self::tokenResponse('B')]);
        $this->store->put('spotify:1', $this->token('A', 10, 'R', issuedAt: self::NOW - 100));

        $this->assertSame('B', $manager->token()->accessToken);
        $this->assertSame('R', $this->store->get('spotify:1')?->refreshToken);
    }

    public function test_rejected_refresh_deletes_the_stored_token(): void
    {
        [$manager] = $this->manager([new HttpResponse(400, '{"error":"invalid_grant"}')]);
        $this->store->put('spotify:1', $this->token('A', 10, 'R', issuedAt: self::NOW - 100));

        try {
            $manager->token();
            $this->fail('OAuthException expected');
        } catch (OAuthException $e) {
            $this->assertSame('invalid_grant', $e->error);
        }

        $this->assertNull($this->store->get('spotify:1'));
        $this->assertFalse($manager->hasToken());
    }

    public function test_provider_outage_keeps_the_stored_token(): void
    {
        [$manager] = $this->manager([new HttpResponse(503, 'down')]);
        $this->store->put('spotify:1', $this->token('A', 10, 'R', issuedAt: self::NOW - 100));

        try {
            $manager->token();
            $this->fail('OAuthException expected');
        } catch (OAuthException $e) {
            $this->assertSame(503, $e->status);
        }

        $this->assertNotNull($this->store->get('spotify:1'));
    }

    public function test_network_error_keeps_the_stored_token(): void
    {
        [$manager] = $this->manager([new HttpClientException('connection refused')]);
        $this->store->put('spotify:1', $this->token('A', 10, 'R', issuedAt: self::NOW - 100));

        try {
            $manager->token();
            $this->fail('HttpClientException expected');
        } catch (HttpClientException) {
        }

        $this->assertNotNull($this->store->get('spotify:1'));
    }

    public function test_missing_token_and_missing_refresh_token_throw(): void
    {
        [$manager, , $http] = $this->manager([]);

        try {
            $manager->authorize($http->get('https://api.test/me'));
            $this->fail('OAuthException expected');
        } catch (OAuthException $e) {
            $this->assertStringContainsString('No OAuth token stored', $e->getMessage());
        }

        $manager->store($this->token('A', 10, null, issuedAt: self::NOW - 100));

        $this->expectException(OAuthException::class);
        $this->expectExceptionMessage('has no refresh token');

        $manager->token();
    }
}
