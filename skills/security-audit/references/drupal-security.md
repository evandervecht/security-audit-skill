# Drupal Security Patterns

Security patterns, common misconfigurations, and detection regexes for Drupal applications (modules, themes, and core customizations).

## Injection

### SQL Injection via `db_query()` Without Placeholders

Drupal's database abstraction layer provides placeholder-based query construction. Using `db_query()` (Drupal 7) or direct `\Drupal::database()->query()` (Drupal 8+) with string interpolation bypasses this protection.

```php
<?php
// VULNERABLE: String concatenation in db_query (Drupal 7)
function mymodule_get_user_unsafe($username) {
    $result = db_query("SELECT * FROM {users} WHERE name = '$username'");
    return $result->fetchObject();
}

// VULNERABLE: String interpolation in database query (Drupal 8+)
function mymodule_get_node_unsafe($title) {
    $connection = \Drupal::database();
    $result = $connection->query("SELECT * FROM {node_field_data} WHERE title = '$title'");
    return $result->fetchAll();
}

// VULNERABLE: sprintf used instead of placeholders
function mymodule_search_unsafe($term) {
    $query = sprintf("SELECT nid FROM {node_field_data} WHERE title LIKE '%%%s%%'", $term);
    $result = \Drupal::database()->query($query);
    return $result->fetchCol();
}

// SECURE: Use placeholders in db_query (Drupal 7)
function mymodule_get_user_safe($username) {
    $result = db_query("SELECT * FROM {users} WHERE name = :name", array(
        ':name' => $username,
    ));
    return $result->fetchObject();
}

// SECURE: Use placeholders in database query (Drupal 8+)
function mymodule_get_node_safe($title) {
    $connection = \Drupal::database();
    $result = $connection->query(
        "SELECT * FROM {node_field_data} WHERE title = :title",
        [':title' => $title]
    );
    return $result->fetchAll();
}

// SECURE: Use database select API (preferred in Drupal 8+)
function mymodule_search_safe($term) {
    $query = \Drupal::database()->select('node_field_data', 'n');
    $query->fields('n', ['nid']);
    $query->condition('title', '%' . $connection->escapeLike($term) . '%', 'LIKE');
    return $query->execute()->fetchCol();
}

// SECURE: Use Entity Query API (most idiomatic)
function mymodule_search_entity_safe($term) {
    $nids = \Drupal::entityQuery('node')
        ->condition('title', $term, 'CONTAINS')
        ->accessCheck(TRUE)
        ->execute();
    return $nids;
}
```

**Detection regex:** `db_query\s*\(\s*["'].*\$|->query\s*\(\s*["'].*\$|sprintf\s*\(\s*["']SELECT`
**Checkpoint:** SA-DRUPAL-01
**Severity:** error

Important: In Drupal 8+, always prefer the Entity Query API with `->accessCheck(TRUE)` over raw database queries. This automatically respects entity access control.

## Cross-Site Scripting (XSS)

### Render Array `#markup` With User Input

Drupal's render API uses `#markup` for pre-sanitized HTML. Passing user input through `#markup` bypasses Drupal's auto-escaping and enables XSS.

```php
<?php
// VULNERABLE: User input in #markup — not auto-escaped
function mymodule_render_username_unsafe($username) {
    return [
        '#markup' => '<div class="username">' . $username . '</div>',
    ];
}

// VULNERABLE: Concatenation in #markup with request parameter
function mymodule_search_results_unsafe() {
    $query = \Drupal::request()->query->get('q');
    return [
        '#markup' => '<h2>Results for: ' . $query . '</h2>',
    ];
}

// SECURE: Use #plain_text for plain text output (auto-escaped)
function mymodule_render_username_safe($username) {
    return [
        '#plain_text' => $username,
        '#prefix' => '<div class="username">',
        '#suffix' => '</div>',
    ];
}

// SECURE: Use Twig template (auto-escapes by default)
function mymodule_render_username_twig($username) {
    return [
        '#theme' => 'mymodule_username',
        '#username' => $username,
    ];
}
// In mymodule-username.html.twig: <div class="username">{{ username }}</div>

// SECURE: Use Html::escape() when #markup is required
use Drupal\Component\Utility\Html;
use Drupal\Component\Utility\Xss;

function mymodule_search_results_safe() {
    $query = \Drupal::request()->query->get('q');
    return [
        '#markup' => '<h2>Results for: ' . Html::escape($query) . '</h2>',
    ];
}

// SECURE: Use Xss::filter() to allow specific safe tags
function mymodule_render_body_safe($body) {
    return [
        '#markup' => Xss::filter($body, ['p', 'br', 'strong', 'em', 'a']),
    ];
}

// SECURE: Use Xss::filterAdmin() for admin-only content
function mymodule_render_admin_safe($content) {
    return [
        '#markup' => Xss::filterAdmin($content),
    ];
}
```

**Detection regex:** `#markup.*\$|#markup.*\.\s*\$|#markup.*getRequest|#markup.*->get\s*\(`
**Checkpoint:** SA-DRUPAL-02
**Severity:** error

### Unsafe Output Without `Html::escape()`

When building HTML strings outside the render API, failing to escape user input leads to XSS.

```php
<?php
use Drupal\Component\Utility\Html;

// VULNERABLE: Direct output in preprocess function
function mymodule_preprocess_node_unsafe(&$variables) {
    $variables['custom_title'] = '<h3>' . $variables['node']->getTitle() . '</h3>';
}

// SECURE: Escape before output
function mymodule_preprocess_node_safe(&$variables) {
    $variables['custom_title'] = '<h3>' . Html::escape($variables['node']->getTitle()) . '</h3>';
}

// SECURE: Better — use render array, let Twig handle escaping
function mymodule_preprocess_node_best(&$variables) {
    $variables['custom_title'] = [
        '#type' => 'html_tag',
        '#tag' => 'h3',
        '#value' => $variables['node']->getTitle(),
    ];
}
```

**Detection regex:** `['"]#markup['"]\s*=>\s*.*\$(?!.*Html::escape|.*Xss::filter|.*check_plain|.*t\()`
**Checkpoint:** SA-DRUPAL-03
**Severity:** error

## CSRF Protection

### Form API Bypass in Custom Handlers

Drupal's Form API includes built-in CSRF tokens. However, custom route controllers that process POST data without using the Form API bypass this protection.

```php
<?php
// VULNERABLE: Custom route handling POST without CSRF token
// mymodule.routing.yml:
// mymodule.delete:
//   path: '/mymodule/delete/{nid}'
//   defaults:
//     _controller: '\Drupal\mymodule\Controller\DeleteController::delete'
//   requirements:
//     _permission: 'administer content'

namespace Drupal\mymodule\Controller;

use Drupal\Core\Controller\ControllerBase;
use Symfony\Component\HttpFoundation\Request;

class DeleteController extends ControllerBase {
    // VULNERABLE: No CSRF token validation on state-changing operation
    public function delete($nid, Request $request) {
        $node = $this->entityTypeManager()->getStorage('node')->load($nid);
        $node->delete();
        return $this->redirect('view.content.page_1');
    }
}

// SECURE: Use Form API for state-changing operations
namespace Drupal\mymodule\Form;

use Drupal\Core\Form\ConfirmFormBase;
use Drupal\Core\Url;

class DeleteConfirmForm extends ConfirmFormBase {
    // Form API handles CSRF automatically
    public function getFormId() {
        return 'mymodule_delete_confirm';
    }

    public function getQuestion() {
        return $this->t('Are you sure you want to delete this item?');
    }

    public function getCancelUrl() {
        return new Url('view.content.page_1');
    }

    public function submitForm(array &$form, FormStateInterface $form_state) {
        // Safe — Form API validated CSRF token
        $node = $this->entityTypeManager()->getStorage('node')->load($this->nid);
        $node->delete();
        $form_state->setRedirect('view.content.page_1');
    }
}

// SECURE: For AJAX/link-based actions, use CSRF token service
// In routing.yml, add: requirements: _csrf_token: 'TRUE'
```

**Detection regex:** `->delete\s*\(\s*\)|->save\s*\(\s*\).*(?!FormInterface|FormBase|submitForm)`
**Checkpoint:** SA-DRUPAL-04
**Severity:** warning

## Authentication & Authorization

### Missing Entity Access Checks

Drupal's entity system has built-in access handlers. Loading and displaying entities without access checks bypasses node access, field access, and role-based permissions.

```php
<?php
// VULNERABLE: Loading entity without access check
function mymodule_view_node_unsafe($nid) {
    $node = \Drupal::entityTypeManager()->getStorage('node')->load($nid);
    // No access check — any user can view any node
    return \Drupal::entityTypeManager()
        ->getViewBuilder('node')
        ->view($node);
}

// VULNERABLE: Entity query without accessCheck
function mymodule_list_nodes_unsafe() {
    $nids = \Drupal::entityQuery('node')
        ->condition('type', 'article')
        ->execute();  // Missing ->accessCheck(TRUE)
    return $nids;
}

// SECURE: Check entity access before rendering
function mymodule_view_node_safe($nid) {
    $node = \Drupal::entityTypeManager()->getStorage('node')->load($nid);

    if (!$node || !$node->access('view')) {
        throw new AccessDeniedHttpException();
    }

    return \Drupal::entityTypeManager()
        ->getViewBuilder('node')
        ->view($node);
}

// SECURE: Entity query with access check enabled
function mymodule_list_nodes_safe() {
    $nids = \Drupal::entityQuery('node')
        ->condition('type', 'article')
        ->accessCheck(TRUE)
        ->execute();
    return $nids;
}
```

**Detection regex:** `entityQuery\s*\([^)]*\)(?!.*accessCheck)|->load\s*\(\s*\$.*(?!.*->access\s*\()`
**Checkpoint:** SA-DRUPAL-05
**Severity:** error

### Missing Module Permissions in Routing

Route definitions without proper permission requirements allow unauthorized access to module pages and APIs.

```php
# VULNERABLE: Route with no access requirements (mymodule.routing.yml)
# mymodule.admin:
#   path: '/admin/mymodule/settings'
#   defaults:
#     _form: '\Drupal\mymodule\Form\SettingsForm'
#   # Missing requirements — accessible to all!

# SECURE: Proper permission requirement
# mymodule.admin:
#   path: '/admin/mymodule/settings'
#   defaults:
#     _form: '\Drupal\mymodule\Form\SettingsForm'
#   requirements:
#     _permission: 'administer mymodule'

# SECURE: Role-based access
# mymodule.report:
#   path: '/admin/mymodule/report'
#   defaults:
#     _controller: '\Drupal\mymodule\Controller\ReportController::view'
#   requirements:
#     _role: 'administrator'

# SECURE: Custom access check
# mymodule.special:
#   path: '/mymodule/special/{node}'
#   defaults:
#     _controller: '\Drupal\mymodule\Controller\SpecialController::view'
#   requirements:
#     _custom_access: '\Drupal\mymodule\Access\SpecialAccess::access'
```

**Detection regex:** `_controller.*Controller.*(?!.*_permission|.*_role|.*_access)`
**Checkpoint:** SA-DRUPAL-06
**Severity:** error

## Security Misconfiguration

### `settings.php` Sensitive Information

Drupal's `settings.php` contains database credentials, hash salts, and trusted host patterns. Misconfigurations here have severe consequences.

```php
<?php
// VULNERABLE: Weak or missing hash_salt
$settings['hash_salt'] = '';
// Empty hash_salt weakens all Drupal cryptographic operations

// VULNERABLE: Missing trusted_host_patterns
// Without this, Drupal accepts requests for any Host header — HTTP Host header attacks
// $settings['trusted_host_patterns'] is not set

// VULNERABLE: Error display enabled in production
$config['system.logging']['error_level'] = 'verbose';
// Exposes stack traces and file paths

// SECURE: Strong hash_salt
$settings['hash_salt'] = 'a-long-random-string-generated-during-install-or-via-drush';

// SECURE: Trusted host patterns
$settings['trusted_host_patterns'] = [
    '^www\.example\.com$',
    '^example\.com$',
];

// SECURE: Error display disabled in production
$config['system.logging']['error_level'] = 'hide';

// SECURE: Database credentials from environment
$databases['default']['default'] = [
    'database' => getenv('DB_NAME'),
    'username' => getenv('DB_USER'),
    'password' => getenv('DB_PASS'),
    'host'     => getenv('DB_HOST'),
    'port'     => getenv('DB_PORT') ?: '3306',
    'driver'   => 'mysql',
    'prefix'   => '',
];

// SECURE: File permissions
$settings['file_chmod_directory'] = 0755;
$settings['file_chmod_file'] = 0644;

// SECURE: Disable update manager in production
$settings['update_free_access'] = FALSE;
```

**Detection regex:** `hash_salt.*=\s*['\"]['\"]|error_level.*verbose|update_free_access.*TRUE`
**Checkpoint:** SA-DRUPAL-07
**Severity:** error

### `.htaccess` and File Access Security

Drupal's `.htaccess` files restrict access to sensitive files. Missing or weakened rules expose configuration, install scripts, and PHP files in upload directories.

```apache
# VULNERABLE: Missing protection for sensitive files
# No .htaccess in sites/default/ or files/ directories

# SECURE: Drupal default .htaccess protections (verify these exist)

# Root .htaccess — block access to sensitive files:
<FilesMatch "\.(engine|inc|install|make|module|profile|po|sh|.*sql|theme|twig|tpl(\.php)?|xtmpl|yml|yaml)(~|\.sw[op]|\.bak|\.orig|\.save)?$|^(\.(?!well-known).*|Entries.*|Repository|Root|Tag|Template|composer\.(json|lock)|web\.config)$|^#.*#$|\.php(~|\.sw[op]|\.bak|\.orig|\.save)$">
  <IfModule mod_authz_core.c>
    Require all denied
  </IfModule>
</FilesMatch>

# sites/default/files/.htaccess — prevent PHP execution in uploads:
SetHandler Drupal_Security_Do_Not_Remove_See_SA_2006_006
<Files *>
  SetHandler none
  SetHandler default-handler
  Options -ExecCGI
</Files>
```

**Detection regex:** `SetHandler\s+Drupal_Security_Do_Not_Remove`
**Checkpoint:** SA-DRUPAL-08
**Severity:** warning

## Remediation Priority

| Finding | Severity | Remediation Timeline | Effort |
|---------|----------|---------------------|--------|
| SQL injection (db_query without placeholders) | Critical | Immediate | Low |
| XSS (#markup with user input) | High | Immediate | Low |
| XSS (missing Html::escape) | High | Immediate | Low |
| CSRF bypass (custom handlers) | High | 1 week | Medium |
| Missing entity access checks | High | 1 week | Medium |
| Missing route permissions | High | 1 week | Low |
| settings.php misconfiguration | High | 1 week | Low |
| .htaccess weakening | Medium | 1 month | Low |

## Related References

- `owasp-top10.md` — OWASP Top 10 mapping
- `php-security-features.md` — PHP-level security patterns
- `input-validation.md` — Input validation strategies
- `authentication-patterns.md` — Authentication and authorization patterns

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-03-31 | Initial release | CMS security references — Phase 3 |
