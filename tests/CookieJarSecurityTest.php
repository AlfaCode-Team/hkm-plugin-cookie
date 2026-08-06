<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\Cookie;

use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Response;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Plugins\Cookie\Infrastructure\CookieJar;

/**
 * Regression cover for K-01/K-02/K-03. All three share a failure mode: the
 * browser rejects the cookie and says nothing, so the bug presents as an
 * inexplicable logout rather than an error.
 */
#[CoversClass(CookieJar::class)]
final class CookieJarSecurityTest extends TestCase
{
    private function jar(): CookieJar
    {
        return new CookieJar(defaults: ['path' => '/', 'secure' => false, 'same_site' => 'Lax']);
    }

    /** The Set-Cookie header line for $name, or '' when absent. */
    private function header(Response $response, string $name): string
    {
        foreach ($response->headers->all('set-cookie') as $line) {
            if (str_starts_with((string) $line, $name . '=')) {
                return (string) $line;
            }
        }

        return '';
    }

    // ── K-01 ────────────────────────────────────────────────────────────────

    public function test_samesite_none_forces_secure(): void
    {
        $jar = $this->jar();
        $jar->queue('cross', 'v', secure: false, sameSite: 'None');

        $line = $this->header($jar->applyTo(Response::empty()), 'cross');

        // Without Secure, every modern browser drops a SameSite=None cookie.
        self::assertStringContainsStringIgnoringCase('samesite=none', $line);
        self::assertStringContainsStringIgnoringCase('secure', $line);
    }

    public function test_samesite_lax_does_not_force_secure(): void
    {
        $jar = $this->jar();
        $jar->queue('normal', 'v', secure: false, sameSite: 'Lax');

        self::assertStringNotContainsStringIgnoringCase(
            '; secure',
            $this->header($jar->applyTo(Response::empty()), 'normal'),
        );
    }

    // ── K-02 ────────────────────────────────────────────────────────────────

    public function test_secure_prefix_forces_the_secure_attribute(): void
    {
        $jar = $this->jar();
        $jar->queue('__Secure-token', 'v', secure: false);

        self::assertStringContainsStringIgnoringCase(
            'secure',
            $this->header($jar->applyTo(Response::empty()), '__Secure-token'),
        );
    }

    public function test_host_prefix_forces_secure_root_path_and_no_domain(): void
    {
        $jar = $this->jar();
        $jar->queue('__Host-sid', 'v', path: '/app', domain: 'example.test', secure: false);

        $line = $this->header($jar->applyTo(Response::empty()), '__Host-sid');

        self::assertStringContainsStringIgnoringCase('secure', $line);
        self::assertStringContainsStringIgnoringCase('path=/', $line);
        self::assertStringNotContainsStringIgnoringCase('domain=', $line, '__Host- forbids a Domain attribute');
    }

    // ── K-03 ────────────────────────────────────────────────────────────────

    public function test_an_oversized_cookie_throws_rather_than_vanishing(): void
    {
        $jar = $this->jar();
        $jar->queue('big', str_repeat('x', 5000));

        $this->expectException(\LengthException::class);
        $this->expectExceptionMessageMatches('/over the ~\d+-byte browser limit/');

        $jar->applyTo(Response::empty());
    }

    public function test_a_normal_cookie_is_unaffected(): void
    {
        $jar = $this->jar();
        $jar->queue('small', str_repeat('x', 100));

        self::assertStringContainsString('small=', $this->header($jar->applyTo(Response::empty()), 'small'));
    }
}
