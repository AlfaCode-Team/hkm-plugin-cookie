<?php

declare(strict_types=1);

namespace Plugins\Cookie\Infrastructure;

use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Request;
use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Response;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\EncryptionPort;

/**
 * CookieJar — queue outgoing cookies during a request, flush them onto the
 * response at the end (GDA rewrite of the 0.3 CookieJar + EncryptCookies +
 * AddQueuedCookiesToResponse filters, merged into one request-scoped service).
 *
 * Modules inject the jar and queue cookies without touching the Response:
 *   $jar->queue('theme', 'dark', maxAge: 3600);
 *   $jar->forget('legacy');
 *
 * When an EncryptionPort is available, queued cookie VALUES are encrypted on
 * flush (authenticated, tamper-evident) unless the cookie name is exempt.
 * Reading an encrypted incoming cookie is symmetric: decrypt($request->cookie(...)).
 */
final class CookieJar
{
    /** @var array<string, array{value: string, maxAge: int, path: string, domain: ?string, secure: bool, httpOnly: bool, sameSite: string, raw: bool}> */
    private array $queued = [];

    /**
     * @param list<string>                                                                                          $exempt   cookie names whose values are NOT encrypted
     * @param array{lifetime?: int, path?: string, domain?: ?string, secure?: bool, http_only?: bool, same_site?: string} $defaults env-driven attribute defaults (see config/cookie.php)
     */
    public function __construct(
        private readonly ?EncryptionPort $encrypter = null,
        private readonly array $exempt = [],
        private readonly array $defaults = [],
    ) {}

    /**
     * Queue a cookie. Any attribute left null falls back to the configured
     * default (config/cookie.php), so callers usually pass only name + value.
     * $maxAge is in SECONDS; the default lifetime in config is in MINUTES.
     */
    public function queue(
        string $name,
        string $value,
        ?int $maxAge = null,
        ?string $path = null,
        ?string $domain = null,
        ?bool $secure = null,
        ?bool $httpOnly = null,
        ?string $sameSite = null,
        bool $raw = false,
    ): void {
        $this->queued[$name] = [
            'value'    => $value,
            'maxAge'   => $maxAge   ?? (int) ($this->defaults['lifetime'] ?? 0) * 60,
            'path'     => $path     ?? (string) ($this->defaults['path'] ?? '/'),
            'domain'   => $domain   ?? ($this->defaults['domain'] ?? null),
            'secure'   => $secure   ?? (bool) ($this->defaults['secure'] ?? true),
            'httpOnly' => $httpOnly ?? (bool) ($this->defaults['http_only'] ?? true),
            'sameSite' => $sameSite ?? (string) ($this->defaults['same_site'] ?? 'Lax'),
            'raw'      => $raw,
        ];
    }

    /** Queue a cookie that expires in ~5 years. */
    public function forever(string $name, string $value, string $path = '/', ?string $domain = null): void
    {
        $this->queue($name, $value, maxAge: 60 * 60 * 24 * 365 * 5, path: $path, domain: $domain);
    }

    public function forget(string $name, string $path = '/', ?string $domain = null): void
    {
        $this->queue($name, '', maxAge: -1, path: $path, domain: $domain, raw: true);
    }

    public function hasQueued(string $name): bool
    {
        return isset($this->queued[$name]);
    }

    /**
     * Read an incoming cookie and transparently decrypt it (the symmetric
     * counterpart to applyTo()'s encryption). Exempt cookies are returned raw,
     * mirroring how they were written. Returns null when absent or tampered.
     */
    public function read(Request $request, string $name): ?string
    {
        $raw = $request->cookie($name);
        if ($raw === null) {
            return null;
        }
        return $this->isExempt($name) ? $raw : $this->decrypt($raw);
    }

    /** Decrypt an incoming cookie value; returns null on tampering/format error. */
    public function decrypt(?string $value): ?string
    {
        if ($value === null || $value === '' || $this->encrypter === null) {
            return $value;
        }
        try {
            return $this->encrypter->decryptString($value);
        } catch (\Throwable) {
            return null; // tampered or not encrypted with our key
        }
    }

    /**
     * Apply every queued cookie to the response (encrypting non-exempt, non-cleared
     * values when an EncryptionPort is configured) and return the new response.
     */
    public function applyTo(Response $response): Response
    {
        foreach ($this->queued as $name => $c) {
            $value = $c['value'];
            $clearing = $c['maxAge'] < 0 || $value === '';

            if (!$clearing && !$c['raw'] && $this->encrypter !== null && !$this->isExempt($name)) {
                $value = $this->encrypter->encryptString($value);
            }

            // Normalise the attributes only now: encryption has run, so the
            // final size is known, and every default has been resolved.
            [$secure, $path, $domain] = $this->normaliseAttributes(
                $name,
                (bool) $c['secure'],
                (string) $c['sameSite'],
                (string) $c['path'],
                $c['domain'],
            );

            $this->assertFitsInBrowserLimit($name, $value);

            $response = $response->withCookie(
                name:     $name,
                value:    $value,
                maxAge:   $c['maxAge'],
                path:     $path,
                domain:   $domain,
                secure:   $secure,
                httpOnly: $c['httpOnly'],
                sameSite: $c['sameSite'],
            );
        }
        return $response;
    }

    /**
     * Reconcile attributes that the browser will otherwise silently reject.
     *
     * K-01 — SameSite=None REQUIRES Secure. Without it every modern browser
     * drops the cookie outright: no error, no header, the session simply never
     * arrives. Emitting an impossible combination is never what the caller
     * meant, so Secure is forced rather than the cookie being lost.
     *
     * K-02 — the __Host- and __Secure- name prefixes are a browser-enforced
     * contract, and a cookie that breaks it is rejected just as silently:
     *   __Secure-  requires Secure.
     *   __Host-    requires Secure, Path=/, and NO Domain attribute.
     * Honouring the prefix is the whole point of using it, so the attributes
     * are corrected to match.
     *
     * @return array{0: bool, 1: string, 2: ?string} secure, path, domain
     */
    private function normaliseAttributes(
        string $name,
        bool $secure,
        string $sameSite,
        string $path,
        ?string $domain,
    ): array {
        if (strcasecmp($sameSite, 'None') === 0) {
            $secure = true;
        }

        if (str_starts_with($name, '__Secure-')) {
            $secure = true;
        }

        if (str_starts_with($name, '__Host-')) {
            $secure = true;
            $path   = '/';
            $domain = null;
        }

        return [$secure, $path, $domain];
    }

    /**
     * K-03 — browsers cap a cookie at roughly 4096 bytes for the whole
     * name=value pair, and drop anything larger WITHOUT reporting it. Encryption
     * inflates a value (base64 of JSON), so a payload that looked comfortable
     * before encryption can cross the line afterwards — which is why this runs
     * after encryption rather than at queue() time.
     *
     * Throwing beats a silent drop: a cookie that vanishes in production
     * presents as an inexplicable logout or a lost flash message, with nothing
     * in any log to explain it.
     */
    private function assertFitsInBrowserLimit(string $name, string $value): void
    {
        // 4096 is the pair limit; leave headroom for the attributes that follow
        // (Path, Domain, Expires, SameSite, Secure, HttpOnly).
        $limit = 4096 - 512;
        $size  = strlen($name) + strlen($value) + 1; // +1 for '='

        if ($size > $limit) {
            throw new \LengthException(sprintf(
                'Cookie [%s] is %d bytes, over the ~%d-byte browser limit%s. '
                . 'Browsers drop oversized cookies silently — store the payload '
                . 'server-side and keep only a reference in the cookie.',
                $name,
                $size,
                $limit,
                $this->encrypter !== null && !$this->isExempt($name) ? ' (after encryption)' : '',
            ));
        }
    }

    private function isExempt(string $name): bool
    {
        return in_array($name, $this->exempt, true);
    }
}
