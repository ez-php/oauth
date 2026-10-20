<?php

declare(strict_types=1);

namespace Tests;

use EzPhp\OAuth\InMemoryOAuthTokenStore;
use EzPhp\OAuth\OAuthException;
use EzPhp\OAuth\OAuthToken;
use EzPhp\OAuth\OAuthTokenStoreInterface;
use EzPhp\OAuth\PdoOAuthTokenStore;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;

/**
 * One contract run against the in-memory and the PDO (SQLite) token store.
 *
 * @package Tests
 */
#[CoversClass(InMemoryOAuthTokenStore::class)]
#[CoversClass(PdoOAuthTokenStore::class)]
#[UsesClass(OAuthToken::class)]
#[UsesClass(OAuthException::class)]
final class OAuthTokenStoreTest extends TestCase
{
    /**
     * @return array<string, array{\Closure(): OAuthTokenStoreInterface}>
     */
    public static function stores(): array
    {
        return [
            'memory' => [static fn (): OAuthTokenStoreInterface => new InMemoryOAuthTokenStore()],
            'pdo' => [static fn (): OAuthTokenStoreInterface => new PdoOAuthTokenStore(self::sqlite())],
        ];
    }

    private static function sqlite(): PDO
    {
        return new PDO('sqlite::memory:', null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    }

    /**
     * @param \Closure(): OAuthTokenStoreInterface $factory
     */
    #[DataProvider('stores')]
    public function test_put_get_replace_forget(\Closure $factory): void
    {
        $store = $factory();
        $token = new OAuthToken('A', 'bearer', 3600, 'R', 'read', 1234);

        $this->assertNull($store->get('k'));

        $store->put('k', $token);
        $this->assertEquals($token, $store->get('k'));

        $store->put('k', $token->withRefreshToken('R2'));
        $replaced = $store->get('k');
        $this->assertNotNull($replaced);
        $this->assertSame('R2', $replaced->refreshToken);
        $this->assertSame(1234, $replaced->issuedAt, 'issuedAt survives storage');

        $store->forget('k');
        $this->assertNull($store->get('k'));
        $store->forget('k');
    }

    public function test_pdo_store_persists_across_instances_on_one_connection(): void
    {
        $pdo = self::sqlite();
        (new PdoOAuthTokenStore($pdo))->put('k', new OAuthToken('A', 'bearer', null, null, null, 5));

        $this->assertSame('A', (new PdoOAuthTokenStore($pdo))->get('k')?->accessToken);
    }

    public function test_pdo_store_rejects_invalid_table_names(): void
    {
        $this->expectException(OAuthException::class);

        new PdoOAuthTokenStore(self::sqlite(), 'tokens; DROP TABLE users');
    }

    public function test_pdo_store_reports_a_corrupt_row(): void
    {
        $pdo = self::sqlite();
        $store = new PdoOAuthTokenStore($pdo);
        $pdo->exec("INSERT INTO oauth_tokens (token_key, token, updated_at) VALUES ('k', 'not json', 0)");

        $this->expectException(OAuthException::class);

        $store->get('k');
    }
}
