<?php

declare(strict_types=1);

namespace Tests;

use EzPhp\OAuth\OAuthToken;
use EzPhp\OAuth\PdoOAuthTokenStore;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;

/**
 * The MySQL branches of PdoOAuthTokenStore: the MySQL DDL and the
 * `ON DUPLICATE KEY UPDATE` upsert, including rewriting an unchanged row
 * (0 affected rows on MySQL). Uses the testing database; skipped when
 * DB_HOST is not set.
 *
 * @package Tests
 */
#[CoversClass(PdoOAuthTokenStore::class)]
#[UsesClass(OAuthToken::class)]
final class OAuthTokenStoreMysqlTest extends TestCase
{
    private const string TABLE = 'ez_oauth_token_store_test';

    private ?PDO $pdo = null;

    protected function setUp(): void
    {
        parent::setUp();

        $host = (string) getenv('DB_HOST');

        if ($host === '') {
            $this->markTestSkipped('MySQL not available — set DB_HOST to run this test.');
        }

        $port = (string) (getenv('DB_PORT') ?: '3306');
        $database = (string) (getenv('DB_TESTING_DATABASE') ?: 'ez-php_testing');
        $this->pdo = new PDO(
            "mysql:host={$host};port={$port};dbname={$database};charset=utf8mb4",
            (string) getenv('DB_USERNAME'),
            (string) getenv('DB_PASSWORD'),
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION],
        );
        $this->pdo->exec('DROP TABLE IF EXISTS ' . self::TABLE);
    }

    protected function tearDown(): void
    {
        $this->pdo?->exec('DROP TABLE IF EXISTS ' . self::TABLE);
        $this->pdo = null;

        parent::tearDown();
    }

    public function test_upsert_get_and_forget_on_mysql(): void
    {
        $pdo = $this->connection();
        $store = new PdoOAuthTokenStore($pdo, self::TABLE);
        $token = new OAuthToken('A', 'bearer', 3600, 'R', 'read', 1234);

        $store->put('spotify:42', $token);
        $store->put('spotify:42', $token); // unchanged row: 0 affected rows on MySQL
        $this->assertEquals($token, $store->get('spotify:42'));

        $store->put('spotify:42', $token->withRefreshToken('R2'));
        $this->assertSame('R2', $store->get('spotify:42')?->refreshToken);
        $count = $pdo->query('SELECT COUNT(*) FROM ' . self::TABLE);
        $this->assertNotFalse($count);
        $this->assertSame(1, (int) $count->fetchColumn());

        $store->forget('spotify:42');
        $this->assertNull($store->get('spotify:42'));
    }

    public function test_mysql_table_has_the_token_key_as_primary_key(): void
    {
        $pdo = $this->connection();
        new PdoOAuthTokenStore($pdo, self::TABLE);
        new PdoOAuthTokenStore($pdo, self::TABLE); // CREATE TABLE IF NOT EXISTS is repeatable

        $statement = $pdo->query('SHOW KEYS FROM ' . self::TABLE . " WHERE Key_name = 'PRIMARY'");
        $this->assertNotFalse($statement);
        $keys = $statement->fetchAll(PDO::FETCH_ASSOC);

        $this->assertCount(1, $keys);
        $this->assertSame('token_key', $keys[0]['Column_name'] ?? null);
    }

    private function connection(): PDO
    {
        $this->assertNotNull($this->pdo);

        return $this->pdo;
    }
}
