<?php

declare(strict_types=1);

namespace EzPhp\OAuth;

use RuntimeException;
use Throwable;

/**
 * Class OAuthException
 *
 * Thrown when the OAuth2 authorization-code flow cannot proceed: an invalid
 * or expired state parameter, a token endpoint error, or a malformed token
 * response.
 *
 * A token endpoint error carries the HTTP `$status` and, when the provider
 * sent one, the RFC 6749 §5.2 `$error` code — so callers can tell a rejected
 * grant (`400 invalid_grant`: drop the stored refresh token) from a provider
 * outage (5xx/429: keep it and retry later). Both are null for failures that
 * never reached a non-2xx token endpoint answer.
 *
 * @package EzPhp\OAuth
 */
final class OAuthException extends RuntimeException
{
    /**
     * OAuthException Constructor
     *
     * @param string         $message
     * @param int|null       $status   HTTP status of the failed token endpoint response.
     * @param string|null    $error    RFC 6749 `error` code from that response body.
     * @param Throwable|null $previous
     */
    public function __construct(
        string $message = '',
        public readonly ?int $status = null,
        public readonly ?string $error = null,
        ?Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }
}
