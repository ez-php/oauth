<?php

declare(strict_types=1);

namespace EzPhp\OAuth;

use RuntimeException;

/**
 * Class OAuthException
 *
 * Thrown when the OAuth2 authorization-code flow cannot proceed: an invalid
 * or expired state parameter, a token endpoint error, or a malformed token
 * response.
 *
 * @package EzPhp\OAuth
 */
final class OAuthException extends RuntimeException
{
}
