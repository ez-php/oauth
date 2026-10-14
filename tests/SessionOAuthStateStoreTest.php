<?php

declare(strict_types=1);

namespace Tests;

use EzPhp\OAuth\SessionOAuthStateStore;
use PHPUnit\Framework\Attributes\CoversClass;

/**
 * Class SessionOAuthStateStoreTest
 *
 * @package Tests
 */
#[CoversClass(SessionOAuthStateStore::class)]
final class SessionOAuthStateStoreTest extends TestCase
{
    private SessionOAuthStateStore $store;

    protected function setUp(): void
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }

        $_SESSION = [];
        $this->store = new SessionOAuthStateStore();
    }

    protected function tearDown(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_write_close();
        }

        $_SESSION = [];
    }

    public function testPutThenPullReturnsThePayload(): void
    {
        $this->store->put('state-1', ['verifier' => 'verifier-1'], 600);

        self::assertSame(['verifier' => 'verifier-1'], $this->store->pull('state-1'));
    }

    public function testPullIsOneTimeUse(): void
    {
        $this->store->put('state-1', ['verifier' => 'verifier-1'], 600);

        $this->store->pull('state-1');

        self::assertNull($this->store->pull('state-1'));
    }

    public function testPullReturnsNullForUnknownState(): void
    {
        self::assertNull($this->store->pull('never-stored'));
    }

    public function testPullReturnsNullOnceExpired(): void
    {
        $this->store->put('state-1', ['verifier' => 'verifier-1'], -1);

        self::assertNull($this->store->pull('state-1'));
    }

    public function testPutDropsExpiredEntries(): void
    {
        $this->store->put('abandoned', ['verifier' => 'old'], -1);
        $this->store->put('state-2', ['verifier' => 'new'], 600);

        $bucket = $_SESSION['_oauth_state'];
        self::assertIsArray($bucket);
        self::assertSame(['state-2'], array_keys($bucket));
    }

    public function testPutKeepsAtMostMaxPendingEntriesDroppingTheOldest(): void
    {
        for ($i = 0; $i <= SessionOAuthStateStore::MAX_PENDING; $i++) {
            $this->store->put('state-' . $i, ['verifier' => 'v' . $i], 600);
        }

        $bucket = $_SESSION['_oauth_state'];
        self::assertIsArray($bucket);
        self::assertCount(SessionOAuthStateStore::MAX_PENDING, $bucket);
        self::assertNull($this->store->pull('state-0'));
        self::assertSame(['verifier' => 'v' . SessionOAuthStateStore::MAX_PENDING], $this->store->pull('state-' . SessionOAuthStateStore::MAX_PENDING));
    }

    public function testPutThrowsWithoutActiveSession(): void
    {
        session_write_close();
        $_SESSION = [];

        $store = new SessionOAuthStateStore();

        $this->expectException(\RuntimeException::class);

        try {
            $store->put('state-1', [], 600);
        } finally {
            session_start();
        }
    }
}
