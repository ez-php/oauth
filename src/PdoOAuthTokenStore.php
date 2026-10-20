<?php

declare(strict_types=1);

namespace EzPhp\OAuth;

use PDO;

/**
 * Class PdoOAuthTokenStore
 *
 * OAuthTokenStoreInterface on a plain PDO connection (no ez-php/contracts
 * dependency). Tokens are stored as JSON (OAuthToken::toStorage()) in an
 * `oauth_tokens` table — `token_key` primary key, `token` text, `updated_at`
 * Unix timestamp — created on construction with `CREATE TABLE IF NOT EXISTS`
 * (MySQL, or a portable SQLite/PostgreSQL form). put() is one driver-aware
 * upsert.
 *
 * Tokens are stored UNENCRYPTED — access and refresh token in plain JSON. They
 * are credentials (a refresh token is long-lived): restrict access to the table
 * like any secret store, or wrap this store in an encrypting decorator
 * (README → "Tokens at rest" shows one on ext-sodium).
 *
 * @package EzPhp\OAuth
 */
final readonly class PdoOAuthTokenStore implements OAuthTokenStoreInterface
{
    /**
     * @param PDO    $pdo   Connection in PDO::ERRMODE_EXCEPTION.
     * @param string $table Table name; interpolated into SQL, so limited to `[A-Za-z0-9_]`.
     *
     * @throws OAuthException When the table name contains anything but letters, digits or underscores.
     */
    public function __construct(
        private PDO $pdo,
        private string $table = 'oauth_tokens',
    ) {
        if (preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $table) !== 1) {
            throw new OAuthException("Invalid token table name '{$table}': only [A-Za-z0-9_] are allowed.");
        }

        $this->createTableIfNeeded();
    }

    /**
     * @param string $key
     *
     * @return OAuthToken|null
     * @throws OAuthException When the stored row is not a valid token.
     */
    public function get(string $key): ?OAuthToken
    {
        $statement = $this->pdo->prepare("SELECT token FROM {$this->table} WHERE token_key = ?");
        $statement->execute([$key]);
        $json = $statement->fetchColumn();

        if (!is_string($json)) {
            return null;
        }

        $data = json_decode($json, true);

        if (!is_array($data)) {
            throw new OAuthException("Stored OAuth token '{$key}' is not valid JSON.");
        }

        /** @var array<string, mixed> $data */
        return OAuthToken::fromStorage($data);
    }

    /**
     * @param string     $key
     * @param OAuthToken $token
     *
     * @return void
     */
    public function put(string $key, OAuthToken $token): void
    {
        $sql = "INSERT INTO {$this->table} (token_key, token, updated_at) VALUES (:key, :token, :now)";
        $bindings = ['key' => $key, 'token' => json_encode($token->toStorage(), JSON_THROW_ON_ERROR), 'now' => time()];

        if ($this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'mysql') {
            $sql .= ' ON DUPLICATE KEY UPDATE token = :update_token, updated_at = :update_now';
            $bindings += ['update_token' => $bindings['token'], 'update_now' => $bindings['now']];
        } else {
            $sql .= ' ON CONFLICT (token_key) DO UPDATE SET token = excluded.token, updated_at = excluded.updated_at';
        }

        $this->pdo->prepare($sql)->execute($bindings);
    }

    /**
     * @param string $key
     *
     * @return void
     */
    public function forget(string $key): void
    {
        $this->pdo->prepare("DELETE FROM {$this->table} WHERE token_key = ?")->execute([$key]);
    }

    /**
     * @return void
     */
    private function createTableIfNeeded(): void
    {
        if ($this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'mysql') {
            $this->pdo->exec(
                "CREATE TABLE IF NOT EXISTS {$this->table} (
                    token_key  VARCHAR(255) PRIMARY KEY,
                    token      TEXT         NOT NULL,
                    updated_at INT UNSIGNED NOT NULL
                )"
            );

            return;
        }

        $this->pdo->exec(
            "CREATE TABLE IF NOT EXISTS {$this->table} (
                token_key  VARCHAR(255) PRIMARY KEY,
                token      TEXT         NOT NULL,
                updated_at BIGINT       NOT NULL
            )"
        );
    }
}
