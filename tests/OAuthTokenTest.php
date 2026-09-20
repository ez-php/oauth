<?php

declare(strict_types=1);

namespace Tests;

use EzPhp\OAuth\OAuthException;
use EzPhp\OAuth\OAuthToken;
use PHPUnit\Framework\Attributes\CoversClass;

/**
 * Class OAuthTokenTest
 *
 * @package Tests
 */
#[CoversClass(OAuthToken::class)]
final class OAuthTokenTest extends TestCase
{
    public function testFromArrayParsesFullResponse(): void
    {
        $token = OAuthToken::fromArray([
            'access_token' => 'access-123',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'refresh_token' => 'refresh-456',
            'scope' => 'profile email',
        ]);

        self::assertSame('access-123', $token->accessToken);
        self::assertSame('Bearer', $token->tokenType);
        self::assertSame(3600, $token->expiresIn);
        self::assertSame('refresh-456', $token->refreshToken);
        self::assertSame('profile email', $token->scope);
        self::assertFalse($token->isExpired());
    }

    public function testFromArrayDefaultsTokenTypeToBearer(): void
    {
        $token = OAuthToken::fromArray(['access_token' => 'access-123']);

        self::assertSame('bearer', $token->tokenType);
        self::assertNull($token->expiresIn);
        self::assertNull($token->refreshToken);
        self::assertNull($token->scope);
    }

    public function testFromArrayThrowsWhenAccessTokenMissing(): void
    {
        $this->expectException(OAuthException::class);

        OAuthToken::fromArray(['token_type' => 'Bearer']);
    }

    public function testFromArrayThrowsWhenAccessTokenEmpty(): void
    {
        $this->expectException(OAuthException::class);

        OAuthToken::fromArray(['access_token' => '']);
    }

    public function testIsExpiredWithoutExpiryIsAlwaysFalse(): void
    {
        $token = new OAuthToken('access-123', 'bearer', null, null, null, time() - 1_000_000);

        self::assertFalse($token->isExpired());
    }

    public function testIsExpiredReturnsTrueOncePastLifetime(): void
    {
        $token = new OAuthToken('access-123', 'bearer', 60, null, null, time() - 120);

        self::assertTrue($token->isExpired());
    }

    public function testIsExpiredReturnsFalseWithinLifetime(): void
    {
        $token = new OAuthToken('access-123', 'bearer', 3600, null, null, time());

        self::assertFalse($token->isExpired());
    }
}
