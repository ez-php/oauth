<?php

declare(strict_types=1);

namespace Tests\Support;

use EzPhp\HttpClient\HttpClientException;
use EzPhp\HttpClient\HttpResponse;
use EzPhp\HttpClient\TransportInterface;
use RuntimeException;

/**
 * Scripted TransportInterface: answers requests in order from a queue and
 * records them; an unexpected extra request fails loudly.
 *
 * @package Tests\Support
 */
final class OAuthSequenceTransport implements TransportInterface
{
    /** @var list<array{method: string, url: string, headers: array<string, string>, body: string}> */
    public array $requests = [];

    /**
     * @param list<HttpResponse|HttpClientException> $queue
     */
    public function __construct(private array $queue)
    {
    }

    /**
     * @param string                $method
     * @param string                $url
     * @param array<string, string> $headers
     * @param string                $body
     * @param int|null              $timeoutSeconds
     *
     * @return HttpResponse
     */
    public function send(string $method, string $url, array $headers, string $body, ?int $timeoutSeconds = null): HttpResponse
    {
        $this->requests[] = compact('method', 'url', 'headers', 'body');
        $next = array_shift($this->queue) ?? throw new RuntimeException("Unexpected request: {$method} {$url}");

        if ($next instanceof HttpClientException) {
            throw $next;
        }

        return $next;
    }
}
