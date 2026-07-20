# TYPO3 Security Patterns

### QueryBuilder: createNamedParameter() for SQL Safety

TYPO3's QueryBuilder provides SQL injection protection through named parameters.

```php
<?php
declare(strict_types=1);

use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Database\Connection;
use TYPO3\CMS\Core\Database\Query\QueryBuilder;

// VULNERABLE: String concatenation in QueryBuilder
final class UserRepositoryUnsafe
{
    public function findByUsername(string $username): array
    {
        $queryBuilder = $this->connectionPool
            ->getQueryBuilderForTable('fe_users');

        // DO NOT concatenate user input into queries
        return $queryBuilder
            ->select('*')
            ->from('fe_users')
            ->where('username = ' . $queryBuilder->quote($username))  // quote() is NOT sufficient
            ->executeQuery()
            ->fetchAllAssociative();
    }
}

// SECURE: Use createNamedParameter()
final class UserRepositorySafe
{
    public function __construct(
        private readonly ConnectionPool $connectionPool,
    ) {}

    public function findByUsername(string $username): array
    {
        $queryBuilder = $this->connectionPool
            ->getQueryBuilderForTable('fe_users');

        return $queryBuilder
            ->select('*')
            ->from('fe_users')
            ->where(
                $queryBuilder->expr()->eq(
                    'username',
                    $queryBuilder->createNamedParameter($username)
                )
            )
            ->executeQuery()
            ->fetchAllAssociative();
    }

    public function findByIds(array $ids): array
    {
        $queryBuilder = $this->connectionPool
            ->getQueryBuilderForTable('fe_users');

        return $queryBuilder
            ->select('*')
            ->from('fe_users')
            ->where(
                $queryBuilder->expr()->in(
                    'uid',
                    $queryBuilder->createNamedParameter(
                        $ids,
                        Connection::PARAM_INT_ARRAY  // Type hint for integer arrays
                    )
                )
            )
            ->executeQuery()
            ->fetchAllAssociative();
    }

    /**
     * For LIKE queries, use createNamedParameter with explicit escaping.
     */
    public function searchByName(string $searchTerm): array
    {
        $queryBuilder = $this->connectionPool
            ->getQueryBuilderForTable('fe_users');

        return $queryBuilder
            ->select('*')
            ->from('fe_users')
            ->where(
                $queryBuilder->expr()->like(
                    'username',
                    $queryBuilder->createNamedParameter(
                        '%' . $queryBuilder->escapeLikeWildcards($searchTerm) . '%'
                    )
                )
            )
            ->executeQuery()
            ->fetchAllAssociative();
    }
}
```

### FormProtection (CSRF Prevention)

TYPO3 uses form protection tokens (CSRF tokens) for backend modules and install tool.

```php
<?php
declare(strict_types=1);

use TYPO3\CMS\Core\FormProtection\FormProtectionFactory;
use TYPO3\CMS\Core\FormProtection\BackendFormProtection;

// SECURE: Generate and validate CSRF tokens in backend modules
final class BackendModuleController
{
    public function __construct(
        private readonly FormProtectionFactory $formProtectionFactory,
    ) {}

    public function formAction(): ResponseInterface
    {
        $formProtection = $this->formProtectionFactory->createFromRequest($request);

        // Generate token for a specific form/action combination
        $token = $formProtection->generateToken(
            'myExtension',       // Form identifier
            'deleteRecord',      // Action
            (string) $recordUid  // Optional: specific record
        );

        // Pass token to Fluid template
        $this->view->assign('csrfToken', $token);

        return $this->htmlResponse();
    }

    public function deleteAction(ServerRequestInterface $request): ResponseInterface
    {
        $formProtection = $this->formProtectionFactory->createFromRequest($request);
        $token = $request->getParsedBody()['csrfToken'] ?? '';

        // Validate token before processing
        if (!$formProtection->validateToken(
            $token,
            'myExtension',
            'deleteRecord',
            (string) $recordUid
        )) {
            throw new \RuntimeException('CSRF token validation failed');
        }

        // Safe to proceed with deletion
        $this->repository->remove($recordUid);
        $formProtection->clean();

        return $this->redirect('list');
    }
}
```

### Trusted Properties (HMAC-Signed Form Field Lists)

```php
<?php
declare(strict_types=1);

// TYPO3 Extbase trusted properties protect against mass assignment.
// The form generates an HMAC-signed list of allowed properties as a hidden field.

// In Fluid template:
// <f:form action="update" object="{user}" name="user">
//   <f:form.textfield property="firstName" />
//   <f:form.textfield property="lastName" />
//   <f:form.textfield property="email" />
//   <!-- __trustedProperties auto-generated: HMAC(['firstName','lastName','email']) -->
// </f:form>

// The following patterns WEAKEN trusted properties protection:

// VULNERABLE: Allowing all properties bypasses HMAC protection
use TYPO3\CMS\Extbase\Mvc\Controller\ActionController;

final class UserControllerUnsafe extends ActionController
{
    public function initializeUpdateAction(): void
    {
        // DO NOT allow all properties
        $this->arguments['user']
            ->getPropertyMappingConfiguration()
            ->allowAllProperties();  // Bypasses trusted properties entirely
    }
}

// VULNERABLE: Setting creation/modification allowed without restriction
// $this->arguments['user']
//     ->getPropertyMappingConfiguration()
//     ->setTypeConverterOption(
//         PersistentObjectConverter::class,
//         PersistentObjectConverter::CONFIGURATION_CREATION_ALLOWED,
//         true
//     );

// SECURE: Only allow explicitly needed properties
final class UserControllerSafe extends ActionController
{
    public function initializeUpdateAction(): void
    {
        $config = $this->arguments['user']->getPropertyMappingConfiguration();

        // Only allow the specific properties the form should set
        $config->allowProperties('firstName', 'lastName', 'email');

        // Explicitly skip sensitive properties
        $config->skipProperties('admin', 'usergroup', 'disable', 'deleted');
    }

    public function updateAction(\MyVendor\MyExt\Domain\Model\User $user): void
    {
        $this->userRepository->update($user);
        $this->redirect('list');
    }
}
```

### FAL (File Abstraction Layer) for Safe File Handling

```php
<?php
declare(strict_types=1);

use TYPO3\CMS\Core\Resource\ResourceFactory;
use TYPO3\CMS\Core\Resource\Security\FileNameValidator;

// VULNERABLE: Direct file operations bypass FAL security
// move_uploaded_file($_FILES['file']['tmp_name'], 'fileadmin/' . $_FILES['file']['name']);

// SECURE: Use FAL for all file operations
final class FileUploadService
{
    public function __construct(
        private readonly ResourceFactory $resourceFactory,
        private readonly FileNameValidator $fileNameValidator,
    ) {}

    public function handleUpload(array $uploadedFile, string $targetFolder): void
    {
        $fileName = $uploadedFile['name'];

        // FAL validates file extensions against deny patterns
        if (!$this->fileNameValidator->isValid($fileName)) {
            throw new \RuntimeException('File type not allowed: ' . $fileName);
        }

        // Use FAL storage for upload (applies all configured security checks)
        $storage = $this->resourceFactory->getDefaultStorage();
        $folder = $storage->getFolder($targetFolder);

        $storage->addFile(
            $uploadedFile['tmp_name'],
            $folder,
            $fileName,
        );
    }
}

// FAL denies these file extensions by default (configurable in Install Tool):
// php, php3, php4, php5, php6, php7, php8, phpsh, phtml, pht, phar,
// shtml, cgi, pl, asp, aspx, js, htaccess, ...
//
// Configuration: $GLOBALS['TYPO3_CONF_VARS']['BE']['fileDenyPattern']
```

### IgnoreValidation Annotation Risks

```php
<?php
declare(strict_types=1);

use TYPO3\CMS\Extbase\Annotation\IgnoreValidation;
use TYPO3\CMS\Extbase\Mvc\Controller\ActionController;

// WARNING: @IgnoreValidation skips ALL validators on the argument.
// Use only for actions that display forms, never for actions that process data.

final class RegistrationController extends ActionController
{
    // SAFE: IgnoreValidation on "new" form display (no data persisted)
    #[IgnoreValidation(['value' => 'user'])]
    public function newAction(?\MyVendor\MyExt\Domain\Model\User $user = null): void
    {
        // Just display the empty form - no data processing
        $this->view->assign('user', $user ?? new User());
    }

    // VULNERABLE: IgnoreValidation on a create/update action
    // #[IgnoreValidation(['value' => 'user'])]
    // public function createAction(User $user): void
    // {
    //     // User input NOT validated - can contain invalid/malicious data
    //     $this->userRepository->add($user);
    // }

    // SECURE: Let validation run on data-processing actions
    public function createAction(\MyVendor\MyExt\Domain\Model\User $user): void
    {
        // Extbase validates $user against model validators before this runs
        $this->userRepository->add($user);
        $this->redirect('list');
    }
}
```

### Content Security in TypoScript

```typoscript
# Configure Content Security Policy headers via TypoScript
config {
    additionalHeaders {
        10 {
            header = Content-Security-Policy
            # Strict CSP: only allow same-origin resources
            header.value = default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; frame-ancestors 'self'; base-uri 'self'; form-action 'self'
        }
        20 {
            header = X-Content-Type-Options
            header.value = nosniff
        }
        30 {
            header = X-Frame-Options
            header.value = SAMEORIGIN
        }
        40 {
            header = Referrer-Policy
            header.value = strict-origin-when-cross-origin
        }
        50 {
            header = Permissions-Policy
            header.value = camera=(), microphone=(), geolocation=()
        }
    }
}

# TYPO3 v12+ CSP integration (backend and frontend)
# Configured in sites/<identifier>/csp.yaml or ext_localconf.php
```

```php
<?php
declare(strict_types=1);

// TYPO3 v12+ Content Security Policy API
use TYPO3\CMS\Core\Security\ContentSecurityPolicy\Directive;
use TYPO3\CMS\Core\Security\ContentSecurityPolicy\Mutation;
use TYPO3\CMS\Core\Security\ContentSecurityPolicy\MutationCollection;
use TYPO3\CMS\Core\Security\ContentSecurityPolicy\MutationMode;
use TYPO3\CMS\Core\Security\ContentSecurityPolicy\Scope;
use TYPO3\CMS\Core\Security\ContentSecurityPolicy\SourceKeyword;
use TYPO3\CMS\Core\Security\ContentSecurityPolicy\SourceScheme;
use TYPO3\CMS\Core\Security\ContentSecurityPolicy\UriValue;

// In ext_localconf.php or Configuration/ContentSecurityPolicies.php:
return \TYPO3\CMS\Core\Security\ContentSecurityPolicy\Map::fromArray([
    Scope::frontend() => new MutationCollection(
        new Mutation(
            MutationMode::Extend,
            Directive::DefaultSrc,
            SourceKeyword::Self,
        ),
        new Mutation(
            MutationMode::Extend,
            Directive::ScriptSrc,
            SourceKeyword::Self,
        ),
    ),
]);
```

### Backend Module Access Control

```php
<?php
declare(strict_types=1);

// Backend module registration with access control (TYPO3 v12+)
// In Configuration/Backend/Modules.php:
return [
    'my_module' => [
        'parent' => 'web',
        'position' => ['after' => 'web_info'],
        'access' => 'admin',  // Restrict to admin users
        // Or: 'access' => 'user,group'  // Authenticated backend users
        'labels' => 'LLL:EXT:my_ext/Resources/Private/Language/locallang_mod.xlf',
        'extensionName' => 'MyExt',
        'controllerActions' => [
            \MyVendor\MyExt\Controller\AdminController::class => [
                'list', 'show',
            ],
        ],
    ],
];

// Additional permission checks within controller
use TYPO3\CMS\Core\Authentication\BackendUserAuthentication;

final class AdminController extends ActionController
{
    public function listAction(): ResponseInterface
    {
        $backendUser = $GLOBALS['BE_USER'];

        // Check specific table permissions
        if (!$backendUser->check('tables_select', 'tx_myext_domain_model_record')) {
            throw new \RuntimeException('Access denied: no permission to read records');
        }

        // Check custom permission
        if (!$backendUser->check('custom_options', 'tx_myext:manage_settings')) {
            throw new \RuntimeException('Access denied: insufficient permissions');
        }

        $records = $this->recordRepository->findAll();
        $this->view->assign('records', $records);

        return $this->htmlResponse();
    }
}
```

### Detection Patterns for TYPO3

```php
// Grep patterns for TYPO3 security issues:
$typo3Patterns = [
    '->quote\(',                        // Using quote() instead of createNamedParameter()
    'allowAllProperties',               // Disabling trusted properties
    'IgnoreValidation.*create',         // IgnoreValidation on write actions
    'IgnoreValidation.*update',         // IgnoreValidation on write actions
    'IgnoreValidation.*delete',         // IgnoreValidation on write actions
    '\$_FILES\[',                       // Direct file access bypassing FAL
    'move_uploaded_file',               // Direct upload bypassing FAL
    'GeneralUtility::_GP\(',            // Accessing GET/POST directly (deprecated)
    'GeneralUtility::_GET\(',           // Accessing GET directly (deprecated)
    'GeneralUtility::_POST\(',          // Accessing POST directly (deprecated)
    '\$GLOBALS\[.TSFE.\].*cObj->data',  // Direct TypoScript data access
];
```

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
