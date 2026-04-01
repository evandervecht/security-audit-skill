# Symfony Security Patterns

### Security Voters for Authorization

Voters provide fine-grained, reusable authorization logic.

```php
<?php
declare(strict_types=1);

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

/**
 * Voter that determines if a user can perform actions on a Document.
 */
final class DocumentVoter extends Voter
{
    public const string VIEW = 'DOCUMENT_VIEW';
    public const string EDIT = 'DOCUMENT_EDIT';
    public const string DELETE = 'DOCUMENT_DELETE';

    protected function supports(string $attribute, mixed $subject): bool
    {
        return in_array($attribute, [self::VIEW, self::EDIT, self::DELETE], true)
            && $subject instanceof Document;
    }

    protected function voteOnAttribute(string $attribute, mixed $subject, TokenInterface $token): bool
    {
        $user = $token->getUser();

        if (!$user instanceof User) {
            return false;  // Not authenticated
        }

        /** @var Document $document */
        $document = $subject;

        return match ($attribute) {
            self::VIEW => $this->canView($document, $user),
            self::EDIT => $this->canEdit($document, $user),
            self::DELETE => $this->canDelete($document, $user),
            default => false,
        };
    }

    private function canView(Document $document, User $user): bool
    {
        // Public documents can be viewed by anyone
        if ($document->isPublic()) {
            return true;
        }

        // Owner can always view
        return $document->getOwner() === $user;
    }

    private function canEdit(Document $document, User $user): bool
    {
        return $document->getOwner() === $user;
    }

    private function canDelete(Document $document, User $user): bool
    {
        // Only owner with admin role can delete
        return $document->getOwner() === $user
            && in_array('ROLE_ADMIN', $user->getRoles(), true);
    }
}

// Usage in controller:
final class DocumentController extends AbstractController
{
    public function edit(Document $document): Response
    {
        // Throws AccessDeniedException if voter denies
        $this->denyAccessUnlessGranted(DocumentVoter::EDIT, $document);

        return $this->render('document/edit.html.twig', ['document' => $document]);
    }
}
```

### Firewall Configuration

```yaml
# config/packages/security.yaml
security:
    password_hashers:
        Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface:
            algorithm: auto  # Uses bcrypt or Argon2id based on PHP config

    providers:
        app_user_provider:
            entity:
                class: App\Entity\User
                property: email

    firewalls:
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false

        api:
            pattern: ^/api
            stateless: true
            jwt: ~  # Or: custom_authenticators, api_key, etc.

        main:
            lazy: true
            provider: app_user_provider
            form_login:
                login_path: app_login
                check_path: app_login
                enable_csrf: true  # CSRF protection on login
            logout:
                path: app_logout
                invalidate_session: true
            remember_me:
                secret: '%kernel.secret%'
                lifetime: 604800  # 1 week
                secure: true
                httponly: true
                samesite: strict

    access_control:
        - { path: ^/admin, roles: ROLE_ADMIN }
        - { path: ^/profile, roles: ROLE_USER }
        - { path: ^/api/public, roles: PUBLIC_ACCESS }
        - { path: ^/api, roles: ROLE_API_USER }
        - { path: ^/login, roles: PUBLIC_ACCESS }
        - { path: ^/, roles: PUBLIC_ACCESS }

    role_hierarchy:
        ROLE_ADMIN: [ROLE_USER, ROLE_API_USER]
        ROLE_SUPER_ADMIN: [ROLE_ADMIN, ROLE_ALLOWED_TO_SWITCH]
```

### CSRF Protection

```php
<?php
declare(strict_types=1);

use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Csrf\CsrfToken;

final class FormController extends AbstractController
{
    public function __construct(
        private readonly CsrfTokenManagerInterface $csrfTokenManager,
    ) {}

    public function delete(Request $request, int $id): Response
    {
        // Validate CSRF token from request
        $token = new CsrfToken(
            'delete_item_' . $id,                          // Token ID (unique per action)
            $request->request->get('_csrf_token', ''),     // Submitted token value
        );

        if (!$this->csrfTokenManager->isTokenValid($token)) {
            throw $this->createAccessDeniedException('Invalid CSRF token');
        }

        // Safe to proceed
        $this->itemRepository->delete($id);

        return $this->redirectToRoute('item_list');
    }
}
```

```twig
{# In Twig template: generate CSRF token #}
<form method="post" action="{{ path('item_delete', {id: item.id}) }}">
    <input type="hidden" name="_csrf_token" value="{{ csrf_token('delete_item_' ~ item.id) }}">
    <button type="submit">Delete</button>
</form>

{# For Symfony forms, CSRF is enabled by default: #}
{{ form_start(form) }}
    {# _token field is automatically included #}
    {{ form_widget(form) }}
{{ form_end(form) }}
```

### Security Bundle Configuration

```yaml
# config/packages/security.yaml - Additional security settings

security:
    # Hide whether a user exists during authentication
    hide_user_not_found: true

    # Session fixation protection
    session_fixation_strategy: migrate  # Regenerates session ID on login

framework:
    # Session security
    session:
        cookie_secure: auto       # HTTPS-only cookies in production
        cookie_httponly: true      # Prevent JavaScript access
        cookie_samesite: lax      # CSRF protection for cookies
        gc_maxlifetime: 1800      # 30-minute session lifetime
```

```php
<?php
declare(strict_types=1);

// Programmatic security checks
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;

final class SecureService
{
    public function __construct(
        private readonly AuthorizationCheckerInterface $authChecker,
    ) {}

    public function performSensitiveAction(): void
    {
        // Check role
        if (!$this->authChecker->isGranted('ROLE_ADMIN')) {
            throw new AccessDeniedException('Admin access required');
        }

        // Check voter-based permission
        if (!$this->authChecker->isGranted('EDIT', $resource)) {
            throw new AccessDeniedException('Cannot edit this resource');
        }
    }
}
```

### Rate Limiter Component

```php
<?php
declare(strict_types=1);

// config/packages/rate_limiter.yaml
// framework:
//     rate_limiter:
//         login_attempts:
//             policy: sliding_window
//             limit: 5
//             interval: '15 minutes'
//         api_requests:
//             policy: token_bucket
//             limit: 100
//             rate: { interval: '1 minute', amount: 10 }

use Symfony\Component\RateLimiter\RateLimiterFactory;

final class LoginController extends AbstractController
{
    public function __construct(
        private readonly RateLimiterFactory $loginLimiter,
    ) {}

    public function login(Request $request): Response
    {
        // Create limiter based on client IP
        $limiter = $this->loginLimiter->create($request->getClientIp());

        // Check if rate limit exceeded
        $limit = $limiter->consume();

        if (!$limit->isAccepted()) {
            $retryAfter = $limit->getRetryAfter();

            return new JsonResponse(
                ['error' => 'Too many login attempts. Try again later.'],
                Response::HTTP_TOO_MANY_REQUESTS,
                ['Retry-After' => $retryAfter->getTimestamp() - time()],
            );
        }

        // Process login
        return $this->processLogin($request);
    }
}
```

### Detection Patterns for Symfony

```php
// Grep patterns for Symfony security issues:
$symfonyPatterns = [
    'security:\s*false',                     // Firewall disabled
    'enable_csrf:\s*false',                  // CSRF disabled on login
    'csrf_protection:\s*false',              // CSRF disabled on forms
    'PUBLIC_ACCESS.*admin',                  // Public access to admin routes
    'isGranted.*ROLE_.*false',               // Ignoring permission check results
    'hide_user_not_found:\s*false',          // User enumeration via login
    '#\[IsGranted\].*without.*attribute',    // Missing role specification
    'password_hashers.*plaintext',           // Plaintext password storage
    'cookie_secure:\s*false',               // Non-secure cookies
];
```

---

## Cross-Framework Patterns

### Middleware Security Pattern

All three frameworks support middleware for cross-cutting security concerns.

```php
<?php
declare(strict_types=1);

// Generic PSR-15 middleware (works with any PSR-15 compatible framework)
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class SecurityHeadersMiddleware implements MiddlewareInterface
{
    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        $response = $handler->handle($request);

        return $response
            ->withHeader('X-Content-Type-Options', 'nosniff')
            ->withHeader('X-Frame-Options', 'DENY')
            ->withHeader('Referrer-Policy', 'strict-origin-when-cross-origin')
            ->withHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
            ->withHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
            ->withHeader('X-XSS-Protection', '0');  // Disabled, use CSP instead
    }
}

final class RateLimitMiddleware implements MiddlewareInterface
{
    public function __construct(
        private readonly RateLimiterInterface $limiter,
    ) {}

    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        $clientIp = $request->getServerParams()['REMOTE_ADDR'] ?? 'unknown';
        $key = 'rate_limit:' . $clientIp;

        if (!$this->limiter->allow($key)) {
            return new JsonResponse(
                ['error' => 'Rate limit exceeded'],
                429,
                ['Retry-After' => '60'],
            );
        }

        return $handler->handle($request);
    }
}
```

### Input Validation Pattern

```php
<?php
declare(strict_types=1);

/**
 * Framework-agnostic input validation.
 * Validate early, validate strictly, reject by default.
 */
final class InputValidator
{
    /**
     * Validate and sanitize an email address.
     */
    public static function email(string $input): string
    {
        $email = filter_var(trim($input), FILTER_VALIDATE_EMAIL);

        if ($email === false) {
            throw new ValidationException('Invalid email address');
        }

        return $email;
    }

    /**
     * Validate a positive integer.
     */
    public static function positiveInt(mixed $input): int
    {
        $value = filter_var($input, FILTER_VALIDATE_INT, [
            'options' => ['min_range' => 1],
        ]);

        if ($value === false) {
            throw new ValidationException('Invalid positive integer');
        }

        return $value;
    }

    /**
     * Validate a string against an allowlist of values.
     *
     * @param list<string> $allowed
     */
    public static function oneOf(string $input, array $allowed): string
    {
        if (!in_array($input, $allowed, true)) {
            throw new ValidationException(
                'Value must be one of: ' . implode(', ', $allowed)
            );
        }

        return $input;
    }

    /**
     * Validate a URL (scheme allowlist + no internal IPs).
     */
    public static function safeUrl(string $input): string
    {
        $url = filter_var($input, FILTER_VALIDATE_URL);

        if ($url === false) {
            throw new ValidationException('Invalid URL');
        }

        $scheme = parse_url($url, PHP_URL_SCHEME);
        if (!in_array($scheme, ['http', 'https'], true)) {
            throw new ValidationException('Only HTTP(S) URLs allowed');
        }

        $host = parse_url($url, PHP_URL_HOST);
        $ip = gethostbyname($host);

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            throw new ValidationException('URL resolves to internal IP');
        }

        return $url;
    }

    /**
     * Strip HTML tags and limit length.
     */
    public static function plainText(string $input, int $maxLength = 1000): string
    {
        $cleaned = strip_tags(trim($input));

        if (mb_strlen($cleaned) > $maxLength) {
            throw new ValidationException("Text exceeds maximum length of {$maxLength}");
        }

        return $cleaned;
    }
}
```

### Output Encoding Pattern

```php
<?php
declare(strict_types=1);

/**
 * Context-aware output encoding.
 * The encoding method MUST match the output context.
 */
final class OutputEncoder
{
    /**
     * HTML body context: encode for safe insertion into HTML elements.
     */
    public static function html(string $input): string
    {
        return htmlspecialchars($input, ENT_QUOTES | ENT_HTML5 | ENT_SUBSTITUTE, 'UTF-8');
    }

    /**
     * HTML attribute context: encode for safe use in HTML attributes.
     */
    public static function attribute(string $input): string
    {
        return htmlspecialchars($input, ENT_QUOTES | ENT_HTML5 | ENT_SUBSTITUTE, 'UTF-8');
    }

    /**
     * JavaScript context: encode for safe embedding in <script> blocks.
     * Prefer using json_encode with safe flags.
     */
    public static function javascript(mixed $input): string
    {
        return json_encode(
            $input,
            JSON_THROW_ON_ERROR
            | JSON_HEX_TAG      // Encode < and >
            | JSON_HEX_APOS     // Encode single quotes
            | JSON_HEX_QUOT     // Encode double quotes
            | JSON_HEX_AMP      // Encode ampersands
            | JSON_UNESCAPED_UNICODE,
        );
    }

    /**
     * URL parameter context: encode for safe use in URL query parameters.
     */
    public static function url(string $input): string
    {
        return rawurlencode($input);
    }

    /**
     * CSS context: encode for safe use in CSS values.
     */
    public static function css(string $input): string
    {
        // Remove anything that is not alphanumeric, space, or safe CSS characters
        return preg_replace('/[^a-zA-Z0-9\s\-_.]/', '', $input) ?? '';
    }
}

// Framework template engine auto-encoding:
//
// TYPO3 Fluid:
//   {variable} is NOT auto-escaped in all contexts
//   Use: {variable -> f:format.htmlspecialchars()}
//   Or: <f:format.htmlspecialchars>{variable}</f:format.htmlspecialchars>
//   Raw output: {variable -> f:format.raw()} -- use only for trusted HTML
//
// Symfony Twig:
//   {{ variable }} is auto-escaped by default
//   Raw output: {{ variable|raw }} -- use only for trusted HTML
//   Custom encoding: {{ variable|e('js') }} for JavaScript context
//
// Laravel Blade:
//   {{ $variable }} is auto-escaped (htmlspecialchars)
//   Raw output: {!! $variable !!} -- use only for trusted HTML
//   JSON in Blade: @json($data) or {{ Js::from($data) }}
```

### Framework Comparison Matrix

| Security Feature | TYPO3 | Symfony | Laravel |
|-----------------|-------|---------|---------|
| SQL injection prevention | `createNamedParameter()` | Doctrine DQL / DBAL | Eloquent / Query Builder |
| CSRF protection | `FormProtectionFactory` | `csrf_token()` / forms | `@csrf` / middleware |
| Mass assignment | Trusted properties (HMAC) | Form types (field list) | `$fillable` / `$guarded` |
| XSS prevention | Fluid ViewHelpers | Twig auto-escape | Blade `{{ }}` auto-escape |
| Authentication | `BackendUserAuthentication` | Security bundle | Auth scaffolding / Sanctum |
| Authorization | Backend module access / custom | Voters / `is_granted()` | Gates / Policies |
| File upload security | FAL + `FileNameValidator` | File constraints + validators | File validation rules |
| Rate limiting | Custom (or middleware) | RateLimiter component | `RateLimiter` facade |
| Encryption | Sodium (manual) | Sodium / OpenSSL | `Crypt` facade (AES-256-CBC) |
| Session security | `$TYPO3_CONF_VARS` settings | `framework.session` config | `config/session.php` |
| Security headers | TypoScript `additionalHeaders` | Middleware / `NelmioSecurityBundle` | Middleware |
| Content Security Policy | CSP API (v12+) | `NelmioSecurityBundle` | `spatie/laravel-csp` |

## Remediation Priority

| Issue | Severity | Action | Timeline |
|-------|----------|--------|----------|
| SQL injection (raw queries) | Critical | Use parameterized queries / ORM | Immediate |
| Missing CSRF protection | High | Enable framework CSRF tokens | Immediate |
| Disabled mass assignment protection | High | Configure fillable/trusted properties | 24 hours |
| Missing authorization checks | High | Implement voters/policies/gates | 24 hours |
| XSS via raw output | High | Use auto-escaping templates | 48 hours |
| Missing security headers | Medium | Add security headers middleware | 1 week |
| Missing rate limiting | Medium | Configure rate limiter | 1 week |
| Weak session configuration | Medium | Harden session settings | 1 week |
| Missing file upload validation | Medium | Use framework file validators | 1 week |
| No Content Security Policy | Low | Implement CSP headers | 2 weeks |

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-03-31 | Extracted from framework-security.md | Phase 2: per-framework file split |
