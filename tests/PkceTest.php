<?php

declare(strict_types=1);

namespace Tests;

use EzPhp\OAuth\Pkce;
use PHPUnit\Framework\Attributes\CoversClass;

/**
 * Class PkceTest
 *
 * @package Tests
 */
#[CoversClass(Pkce::class)]
final class PkceTest extends TestCase
{
    public function testGenerateVerifierProducesUrlSafeStringOfValidLength(): void
    {
        $verifier = Pkce::generateVerifier();

        self::assertMatchesRegularExpression('/^[A-Za-z0-9\-_]+$/', $verifier);
        self::assertGreaterThanOrEqual(43, strlen($verifier));
        self::assertLessThanOrEqual(128, strlen($verifier));
    }

    public function testGenerateVerifierIsRandomEachCall(): void
    {
        self::assertNotSame(Pkce::generateVerifier(), Pkce::generateVerifier());
    }

    public function testChallengeForIsDeterministicAndUrlSafe(): void
    {
        $verifier = 'fixed-test-verifier-value';

        $challengeOne = Pkce::challengeFor($verifier);
        $challengeTwo = Pkce::challengeFor($verifier);

        self::assertSame($challengeOne, $challengeTwo);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9\-_]+$/', $challengeOne);
        self::assertStringNotContainsString('=', $challengeOne);
    }

    public function testChallengeForMatchesRfc7636TestVector(): void
    {
        // RFC 7636 Appendix B test vector.
        $verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

        self::assertSame('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', Pkce::challengeFor($verifier));
    }

    public function testChallengeDiffersForDifferentVerifiers(): void
    {
        self::assertNotSame(Pkce::challengeFor('verifier-a'), Pkce::challengeFor('verifier-b'));
    }
}
