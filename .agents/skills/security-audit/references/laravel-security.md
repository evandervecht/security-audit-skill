# Laravel Security Patterns

### Gates and Policies

```php
<?php
declare(strict_types=1);

use Illuminate\Auth\Access\Gate;
use Illuminate\Support\Facades\Gate as GateFacade;

// Define gates in AuthServiceProvider
final class AuthServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        // Simple gate: closure-based
        GateFacade::define('manage-settings', function (User $user): bool {
            return $user->is_admin;
        });

        // Gate with resource: checks ownership
        GateFacade::define('update-post', function (User $user, Post $post): bool {
            return $user->id === $post->user_id;
        });
    }
}

// Policy class for fine-grained authorization
final class PostPolicy
{
    /**
     * Determine if the user can view the post.
     */
    public function view(User $user, Post $post): bool
    {
        return $post->published || $user->id === $post->user_id;
    }

    /**
     * Determine if the user can update the post.
     */
    public function update(User $user, Post $post): bool
    {
        return $user->id === $post->user_id;
    }

    /**
     * Determine if the user can delete the post.
     */
    public function delete(User $user, Post $post): bool
    {
        return $user->id === $post->user_id
            && $user->hasRole('editor');
    }
}

// Usage in controller:
final class PostController extends Controller
{
    public function update(Request $request, Post $post): JsonResponse
    {
        // Throws AuthorizationException if denied
        $this->authorize('update', $post);

        $validated = $request->validate([
            'title' => 'required|string|max:255',
            'body' => 'required|string',
        ]);

        $post->update($validated);

        return response()->json($post);
    }
}

// Usage in Blade template:
// @can('update', $post)
//     <a href="{{ route('posts.edit', $post) }}">Edit</a>
// @endcan
```

### Mass Assignment Protection

```php
<?php
declare(strict_types=1);

use Illuminate\Database\Eloquent\Model;

// VULNERABLE: No mass assignment protection
class PostUnsafe extends Model
{
    protected $guarded = [];  // NEVER do this in production
}

// VULNERABLE: Using $request->all() with guarded = []
// Post::create($request->all());  // All fields from request are saved

// SECURE: Explicit fillable (allowlist -- recommended)
class Post extends Model
{
    /**
     * Only these fields can be mass-assigned.
     * @var list<string>
     */
    protected $fillable = [
        'title',
        'body',
        'category_id',
    ];

    // These fields are automatically protected:
    // id, user_id, is_published, is_featured, created_at, updated_at
}

// SECURE: Using validated data only (defense in depth)
final class PostController extends Controller
{
    public function store(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'title' => 'required|string|max:255',
            'body' => 'required|string|max:50000',
            'category_id' => 'required|exists:categories,id',
        ]);

        // Even with $fillable, always use validated data
        $post = $request->user()->posts()->create($validated);

        return response()->json($post, 201);
    }
}

// SECURE: Form Request for complex validation
final class StorePostRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user()->can('create', Post::class);
    }

    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'title' => ['required', 'string', 'max:255'],
            'body' => ['required', 'string'],
            'category_id' => ['required', 'integer', 'exists:categories,id'],
            // is_published, user_id, etc. are NOT in rules = cannot be submitted
        ];
    }
}
```

### CSRF Middleware

```php
<?php
declare(strict_types=1);

// Laravel includes CSRF middleware by default for web routes.
// The VerifyCsrfToken middleware checks _token on all POST/PUT/PATCH/DELETE requests.

// In Blade templates:
// <form method="POST" action="/posts">
//     @csrf                                    <!-- Adds hidden _token field -->
//     <input type="text" name="title">
//     <button type="submit">Create</button>
// </form>

// For AJAX requests:
// <meta name="csrf-token" content="{{ csrf_token() }}">
// <script>
//   fetch('/api/endpoint', {
//       method: 'POST',
//       headers: {
//           'X-CSRF-TOKEN': document.querySelector('meta[name="csrf-token"]').content,
//           'Content-Type': 'application/json',
//       },
//       body: JSON.stringify(data)
//   });
// </script>

// Exclude routes from CSRF (use sparingly, e.g., for webhooks):
// In app/Http/Middleware/VerifyCsrfToken.php:
final class VerifyCsrfToken extends Middleware
{
    /**
     * URIs that should be excluded from CSRF verification.
     * WARNING: Only exclude routes that have alternative authentication
     * (e.g., webhook signature verification, API tokens).
     *
     * @var list<string>
     */
    protected $except = [
        'webhooks/stripe',    // Uses Stripe signature verification
        'webhooks/github',    // Uses GitHub HMAC verification
    ];
}
```

### Encryption (Crypt Facade)

```php
<?php
declare(strict_types=1);

use Illuminate\Support\Facades\Crypt;
use Illuminate\Contracts\Encryption\DecryptException;

// Laravel's Crypt facade uses AES-256-CBC with HMAC (encrypt-then-MAC)
// Key is derived from APP_KEY in .env

final class SecureStorageService
{
    /**
     * Encrypt sensitive data for storage.
     */
    public function store(string $sensitiveData): string
    {
        // Crypt::encrypt serializes and encrypts (handles objects/arrays too)
        return Crypt::encryptString($sensitiveData);

        // For arrays/objects:
        // return Crypt::encrypt(['key' => 'value']);
    }

    /**
     * Decrypt stored data.
     */
    public function retrieve(string $encryptedData): string
    {
        try {
            return Crypt::decryptString($encryptedData);
        } catch (DecryptException $e) {
            // Tampered data, wrong key, or corrupted ciphertext
            throw new \RuntimeException('Data integrity check failed', 0, $e);
        }
    }
}

// IMPORTANT: Protect APP_KEY
// - Never commit APP_KEY to version control
// - Rotate with: php artisan key:generate
// - After rotation, re-encrypt all data encrypted with old key
// - Store in environment variable, never in config files
```

### Query Builder Parameterization

```php
<?php
declare(strict_types=1);

use Illuminate\Support\Facades\DB;

// VULNERABLE: Raw string concatenation
$users = DB::select("SELECT * FROM users WHERE name = '" . $name . "'");

// VULNERABLE: Raw expression without binding
$users = DB::table('users')
    ->whereRaw("name = '$name'")  // SQL injection
    ->get();

// SECURE: Query builder with automatic parameterization
$users = DB::table('users')
    ->where('name', '=', $name)     // Parameterized automatically
    ->where('active', true)
    ->get();

// SECURE: Raw queries with parameter binding
$users = DB::select(
    'SELECT * FROM users WHERE name = ? AND role = ?',
    [$name, $role]
);

// SECURE: Named bindings
$users = DB::select(
    'SELECT * FROM users WHERE name = :name',
    ['name' => $name]
);

// SECURE: whereRaw with bindings (when raw SQL is needed)
$users = DB::table('users')
    ->whereRaw('LOWER(email) = ?', [strtolower($email)])
    ->get();

// SECURE: Eloquent ORM (always parameterized)
$users = User::where('name', $name)
    ->where('active', true)
    ->get();

// SECURE: Subqueries
$latestPosts = DB::table('posts')
    ->select('user_id', DB::raw('MAX(created_at) as last_post'))
    ->groupBy('user_id');

$users = DB::table('users')
    ->joinSub($latestPosts, 'latest_posts', function ($join) {
        $join->on('users.id', '=', 'latest_posts.user_id');
    })
    ->get();
```

### Detection Patterns for Laravel

```php
// Grep patterns for Laravel security issues:
$laravelPatterns = [
    'protected \$guarded = \[\]',           // Empty guarded array
    '->fill\(\$request->all\(\)\)',         // Mass assignment with all()
    '::create\(\$request->all\(\)\)',       // Create with all request data
    'DB::raw\(\$',                          // Raw SQL with variable
    'whereRaw\(.*\$',                       // whereRaw with variable interpolation
    'DB::select\(.*\.\s*\$',               // Concatenated SQL
    'Crypt::decrypt.*catch.*\{\}',         // Swallowed decryption errors
    'except.*=.*\[.*\*',                   // Wildcard CSRF exclusion
    'auth\(\)->user\(\).*without.*check',  // Missing null check on user
    'APP_KEY.*base64:.*config',            // Hardcoded APP_KEY
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
