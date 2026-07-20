# WordPress Security Patterns

Security patterns, common misconfigurations, and detection regexes for WordPress applications (themes, plugins, and core customizations).

## Injection

### SQL Injection via `$wpdb->query()` Without `$wpdb->prepare()`

WordPress provides the `$wpdb` global for database access. Direct queries without `$wpdb->prepare()` are the single most common vulnerability in WordPress plugins.

```php
<?php
// VULNERABLE: Direct variable interpolation in SQL query
function get_user_posts_unsafe($user_id) {
    global $wpdb;

    // User input directly in query — SQL injection
    $results = $wpdb->get_results(
        "SELECT * FROM {$wpdb->prefix}posts WHERE post_author = $user_id"
    );

    return $results;
}

// VULNERABLE: String concatenation in query
function search_posts_unsafe($search_term) {
    global $wpdb;

    $results = $wpdb->get_results(
        "SELECT * FROM {$wpdb->prefix}posts WHERE post_title LIKE '%" . $search_term . "%'"
    );

    return $results;
}

// SECURE: Use $wpdb->prepare() with format specifiers
function get_user_posts_safe($user_id) {
    global $wpdb;

    $results = $wpdb->get_results(
        $wpdb->prepare(
            "SELECT * FROM {$wpdb->prefix}posts WHERE post_author = %d",
            $user_id
        )
    );

    return $results;
}

// SECURE: Use $wpdb->prepare() with LIKE
function search_posts_safe($search_term) {
    global $wpdb;

    $like = '%' . $wpdb->esc_like($search_term) . '%';
    $results = $wpdb->get_results(
        $wpdb->prepare(
            "SELECT * FROM {$wpdb->prefix}posts WHERE post_title LIKE %s",
            $like
        )
    );

    return $results;
}
```

**Detection regex:** `\$wpdb\s*->\s*(query|get_results|get_row|get_var|get_col)\s*\(\s*["']`
**Checkpoint:** SA-WP-01
**Severity:** error

Key rules for `$wpdb->prepare()`:
- Always use `%d` for integers, `%s` for strings, `%f` for floats
- Never wrap `%s` in quotes — `prepare()` handles quoting
- For `LIKE`, use `$wpdb->esc_like()` to escape `%` and `_` wildcards
- For `IN` clauses, generate the correct number of placeholders dynamically

### Object Injection via `unserialize()` With User Input

WordPress uses serialized data in options and post meta. Calling `unserialize()` on untrusted input can trigger arbitrary object instantiation and magic method execution.

```php
<?php
// VULNERABLE: Deserializing user input
function process_import_unsafe() {
    $data = unserialize($_POST['import_data']);
    // Attacker can instantiate any autoloaded class with __wakeup() / __destruct()
    return $data;
}

// VULNERABLE: Deserializing data from an untrusted option without validation
function process_external_data_unsafe() {
    $raw = file_get_contents('php://input');
    $data = unserialize($raw);
    update_option('imported_data', $data);
}

// SECURE: Use json_decode for data interchange
function process_import_safe() {
    $data = json_decode(wp_unslash($_POST['import_data']), true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        return new WP_Error('invalid_json', 'Invalid import data');
    }
    return $data;
}

// SECURE: If unserialize is absolutely required, use allowed_classes
function process_legacy_import_safe() {
    $raw = wp_unslash($_POST['import_data']);
    $data = unserialize($raw, ['allowed_classes' => false]);
    return $data;
}
```

**Detection regex:** `unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)|unserialize\s*\(\s*\$`
**Checkpoint:** SA-WP-02
**Severity:** error

## Cross-Site Scripting (XSS)

### Unescaped Output in Templates and PHP Files

WordPress provides a comprehensive set of escaping functions. Outputting variables without escaping is the primary XSS vector in themes and plugins.

```php
<?php
// VULNERABLE: Direct echo without escaping
function render_user_name_unsafe($user) {
    echo '<span class="author">' . $user->display_name . '</span>';
}

// VULNERABLE: Unescaped attribute
function render_link_unsafe($url, $title) {
    echo '<a href="' . $url . '" title="' . $title . '">Link</a>';
}

// VULNERABLE: Unescaped in JavaScript context
function render_script_unsafe($value) {
    echo '<script>var config = "' . $value . '";</script>';
}

// SECURE: Use esc_html() for HTML content
function render_user_name_safe($user) {
    echo '<span class="author">' . esc_html($user->display_name) . '</span>';
}

// SECURE: Use esc_attr() for HTML attributes, esc_url() for URLs
function render_link_safe($url, $title) {
    echo '<a href="' . esc_url($url) . '" title="' . esc_attr($title) . '">Link</a>';
}

// SECURE: Use wp_json_encode() for JavaScript context
function render_script_safe($value) {
    echo '<script>var config = ' . wp_json_encode($value) . ';</script>';
}

// SECURE: Use wp_kses() for allowing specific HTML tags
function render_rich_content_safe($content) {
    $allowed = array(
        'strong' => array(),
        'em'     => array(),
        'a'      => array('href' => array(), 'title' => array()),
    );
    echo wp_kses($content, $allowed);
}
```

**Detection regex:** `echo\s+\$(?!.*esc_html|.*esc_attr|.*esc_url|.*wp_kses|.*absint|.*intval)`
**Checkpoint:** SA-WP-03
**Severity:** error

Escaping function reference:
| Function | Use For |
|----------|---------|
| `esc_html()` | Output between HTML tags |
| `esc_attr()` | Output inside HTML attributes |
| `esc_url()` | Output in `href`, `src`, or URL context |
| `esc_js()` | Output in inline JavaScript (prefer `wp_json_encode`) |
| `esc_textarea()` | Output inside `<textarea>` |
| `wp_kses()` | Allow specific HTML tags, strip everything else |
| `wp_kses_post()` | Allow post-safe HTML tags |
| `absint()` | Integer output (absolute value) |

## Authentication & Authorization

### REST API Endpoints Without Permission Callbacks

WordPress REST API routes registered without a `permission_callback` (or with one that always returns `true`) allow unauthenticated access to sensitive operations.

```php
<?php
// VULNERABLE: No permission_callback — defaults to public access
function register_api_routes_unsafe() {
    register_rest_route('myplugin/v1', '/users', array(
        'methods'  => 'GET',
        'callback' => 'get_all_users',
    ));
}

// VULNERABLE: permission_callback always returns true
function register_api_routes_unsafe2() {
    register_rest_route('myplugin/v1', '/delete-user', array(
        'methods'             => 'DELETE',
        'callback'            => 'delete_user_handler',
        'permission_callback' => '__return_true',
    ));
}

// SECURE: Proper capability check in permission_callback
function register_api_routes_safe() {
    register_rest_route('myplugin/v1', '/users', array(
        'methods'             => 'GET',
        'callback'            => 'get_all_users',
        'permission_callback' => function () {
            return current_user_can('list_users');
        },
    ));

    register_rest_route('myplugin/v1', '/delete-user', array(
        'methods'             => 'DELETE',
        'callback'            => 'delete_user_handler',
        'permission_callback' => function () {
            return current_user_can('delete_users');
        },
    ));
}

// SECURE: With nonce verification for authenticated requests from the frontend
function register_api_routes_with_nonce() {
    register_rest_route('myplugin/v1', '/settings', array(
        'methods'             => 'POST',
        'callback'            => 'update_settings_handler',
        'permission_callback' => function ($request) {
            return current_user_can('manage_options')
                && wp_verify_nonce($request->get_header('X-WP-Nonce'), 'wp_rest');
        },
    ));
}
```

**Detection regex:** `register_rest_route\s*\([^)]*(?!permission_callback)[^)]*\)|permission_callback.*__return_true`
**Checkpoint:** SA-WP-04
**Severity:** error

### Missing Capability Checks on Option and Meta Updates

Functions like `update_option()`, `update_post_meta()`, and `delete_option()` must be gated by capability checks. Otherwise, low-privilege users or unauthenticated AJAX handlers can modify site configuration.

```php
<?php
// VULNERABLE: AJAX handler without capability check
add_action('wp_ajax_update_settings', 'handle_update_settings_unsafe');
function handle_update_settings_unsafe() {
    // Any logged-in user can update options
    update_option('myplugin_setting', sanitize_text_field($_POST['value']));
    wp_send_json_success();
}

// VULNERABLE: No nonce and no capability check
add_action('wp_ajax_delete_post_meta', 'handle_delete_meta_unsafe');
function handle_delete_meta_unsafe() {
    delete_post_meta(intval($_POST['post_id']), sanitize_key($_POST['key']));
    wp_send_json_success();
}

// SECURE: Capability check + nonce verification
add_action('wp_ajax_update_settings', 'handle_update_settings_safe');
function handle_update_settings_safe() {
    if (!current_user_can('manage_options')) {
        wp_send_json_error('Unauthorized', 403);
    }

    check_ajax_referer('myplugin_settings_nonce', 'nonce');

    update_option('myplugin_setting', sanitize_text_field($_POST['value']));
    wp_send_json_success();
}

// SECURE: Object-level authorization for post meta
add_action('wp_ajax_delete_post_meta', 'handle_delete_meta_safe');
function handle_delete_meta_safe() {
    $post_id = intval($_POST['post_id']);

    if (!current_user_can('edit_post', $post_id)) {
        wp_send_json_error('Unauthorized', 403);
    }

    check_ajax_referer('myplugin_meta_nonce', 'nonce');

    delete_post_meta($post_id, sanitize_key($_POST['key']));
    wp_send_json_success();
}
```

**Detection regex:** `update_option\s*\(|update_post_meta\s*\(|delete_option\s*\(|delete_post_meta\s*\(`
**Checkpoint:** SA-WP-05
**Severity:** warning

## CSRF Protection

### Missing Nonce Validation

WordPress uses nonces (number-used-once tokens) for CSRF protection. Form submissions and AJAX requests without nonce verification allow cross-site request forgery.

```php
<?php
// VULNERABLE: Form processing without nonce check
function process_form_unsafe() {
    if (isset($_POST['submit'])) {
        update_option('plugin_setting', sanitize_text_field($_POST['setting']));
        echo '<div class="updated">Settings saved.</div>';
    }
}

// SECURE: Generate nonce in form, verify on submission
function render_form_safe() {
    ?>
    <form method="post" action="">
        <?php wp_nonce_field('myplugin_save_settings', 'myplugin_nonce'); ?>
        <input type="text" name="setting"
            value="<?php echo esc_attr(get_option('plugin_setting')); ?>" />
        <input type="submit" name="submit" value="Save" />
    </form>
    <?php
}

function process_form_safe() {
    if (!isset($_POST['submit'])) {
        return;
    }

    // Verify nonce — dies on failure
    if (!wp_verify_nonce($_POST['myplugin_nonce'], 'myplugin_save_settings')) {
        wp_die('Security check failed');
    }

    // Also check capability
    if (!current_user_can('manage_options')) {
        wp_die('Unauthorized');
    }

    update_option('plugin_setting', sanitize_text_field($_POST['setting']));
    echo '<div class="updated">Settings saved.</div>';
}

// SECURE: AJAX nonce pattern
add_action('wp_ajax_my_action', 'handle_ajax_safe');
function handle_ajax_safe() {
    check_ajax_referer('my_action_nonce', 'security');

    // Process request...
    wp_send_json_success();
}
```

**Detection regex:** `\$_POST\[.*\]\s*(?!.*wp_verify_nonce|.*check_ajax_referer|.*wp_nonce)`
**Checkpoint:** SA-WP-06
**Severity:** error

## File Upload Security

### File Uploads Without Proper Validation

WordPress provides `wp_handle_upload()` with built-in MIME checking and path normalization. Custom upload handlers that bypass these checks are vulnerable to arbitrary file upload attacks.

```php
<?php
// VULNERABLE: Direct move_uploaded_file without validation
function handle_upload_unsafe() {
    $target_dir = wp_upload_dir()['basedir'] . '/custom/';
    $target_file = $target_dir . basename($_FILES['upload']['name']);

    // No file type check, no size limit, no nonce
    move_uploaded_file($_FILES['upload']['tmp_name'], $target_file);

    echo 'File uploaded: ' . $target_file;
}

// VULNERABLE: Client-side extension check only
function handle_upload_extension_only() {
    $ext = pathinfo($_FILES['upload']['name'], PATHINFO_EXTENSION);
    if (in_array($ext, ['jpg', 'png', 'gif'])) {
        move_uploaded_file(
            $_FILES['upload']['tmp_name'],
            wp_upload_dir()['basedir'] . '/' . $_FILES['upload']['name']
        );
    }
}

// SECURE: Use wp_handle_upload() with proper overrides
function handle_upload_safe() {
    if (!current_user_can('upload_files')) {
        wp_die('Unauthorized');
    }

    check_admin_referer('my_file_upload');

    if (!function_exists('wp_handle_upload')) {
        require_once ABSPATH . 'wp-admin/includes/file.php';
    }

    $upload_overrides = array(
        'test_form' => false,
        'mimes'     => array(
            'jpg|jpeg' => 'image/jpeg',
            'png'      => 'image/png',
            'pdf'      => 'application/pdf',
        ),
    );

    $uploaded_file = wp_handle_upload($_FILES['upload'], $upload_overrides);

    if (isset($uploaded_file['error'])) {
        wp_die($uploaded_file['error']);
    }

    // File is now safe — use $uploaded_file['url'] and $uploaded_file['file']
    return $uploaded_file;
}

// SECURE: Validate with wp_check_filetype_and_ext()
function validate_file_type($file_path, $filename) {
    $check = wp_check_filetype_and_ext($file_path, $filename);

    if (!$check['type']) {
        return new WP_Error('invalid_type', 'File type not allowed');
    }

    return true;
}
```

**Detection regex:** `move_uploaded_file\s*\(|\$_FILES\s*\[.*\]\s*\[.tmp_name.\]`
**Checkpoint:** SA-WP-07
**Severity:** error

## Security Misconfiguration

### `wp-config.php` Hardening Issues

`wp-config.php` is the most security-sensitive file in a WordPress installation. Common misconfigurations include leaving debug mode on in production, using default table prefixes, and missing security salts.

```php
<?php
// VULNERABLE: Debug mode enabled in production
define('WP_DEBUG', true);
define('WP_DEBUG_DISPLAY', true);
define('WP_DEBUG_LOG', true);
// Exposes error messages, file paths, and SQL queries to users

// VULNERABLE: Default table prefix
$table_prefix = 'wp_';
// Makes SQL injection attacks easier — attacker knows table names

// VULNERABLE: Missing or default security salts
define('AUTH_KEY',         'put your unique phrase here');
define('SECURE_AUTH_KEY',  'put your unique phrase here');
// Default placeholder values provide no cryptographic security

// VULNERABLE: File editing enabled
define('DISALLOW_FILE_EDIT', false);
// Allows admin users to edit theme/plugin PHP files from the dashboard

// SECURE: Production-hardened wp-config.php
define('WP_DEBUG', false);
define('WP_DEBUG_DISPLAY', false);
define('WP_DEBUG_LOG', false);

$table_prefix = 'xk7m_';  // Randomized table prefix

// Generated with wp_generate_password() or WordPress salt API
define('AUTH_KEY',         'unique-random-string-here...');
define('SECURE_AUTH_KEY',  'unique-random-string-here...');
define('LOGGED_IN_KEY',    'unique-random-string-here...');
define('NONCE_KEY',        'unique-random-string-here...');
define('AUTH_SALT',        'unique-random-string-here...');
define('SECURE_AUTH_SALT', 'unique-random-string-here...');
define('LOGGED_IN_SALT',   'unique-random-string-here...');
define('NONCE_SALT',       'unique-random-string-here...');

// Disable file editing in dashboard
define('DISALLOW_FILE_EDIT', true);

// Force SSL for admin area
define('FORCE_SSL_ADMIN', true);

// Limit post revisions to reduce DB size and exposure
define('WP_POST_REVISIONS', 5);

// Disable automatic updates for plugins (use managed deployment)
define('AUTOMATIC_UPDATER_DISABLED', true);
```

**Detection regex:** `WP_DEBUG.*true|WP_DEBUG_DISPLAY.*true|DISALLOW_FILE_EDIT.*false`
**Checkpoint:** SA-WP-08
**Severity:** error

### Missing Direct File Access Protection

Every WordPress plugin and theme PHP file should prevent direct access. Without the `ABSPATH` check, files can be accessed directly by URL, potentially exposing errors or executing code outside the WordPress context.

```php
<?php
// VULNERABLE: No direct access protection
// File: wp-content/plugins/myplugin/includes/helper.php
function my_helper_function() {
    // This file can be accessed directly via URL
    // https://example.com/wp-content/plugins/myplugin/includes/helper.php
    return true;
}

// SECURE: Prevent direct file access
// File: wp-content/plugins/myplugin/includes/helper.php
if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly
}

function my_helper_function() {
    return true;
}

// SECURE: Alternative — die with message
defined('ABSPATH') || die('No direct access allowed');
```

**Detection regex:** `^<\?php\s*\n(?!.*defined\s*\(\s*['\"]ABSPATH['\"])`
**Checkpoint:** SA-WP-09
**Severity:** warning

### Default Table Prefix

Using the default `wp_` table prefix makes targeted SQL injection attacks easier because the attacker already knows the table names.

```php
<?php
// VULNERABLE: Default table prefix in wp-config.php
$table_prefix = 'wp_';

// SECURE: Custom table prefix
$table_prefix = 'mysite_x9k_';
```

**Detection regex:** `\$table_prefix\s*=\s*['\"]wp_['\"]`
**Checkpoint:** SA-WP-10
**Severity:** warning

## Data Exposure

### Sensitive Data in Debug Logs

When `WP_DEBUG_LOG` is enabled, errors and debug output are written to `wp-content/debug.log`. This file is often publicly accessible and can contain database credentials, file paths, and stack traces.

```php
<?php
// VULNERABLE: Logging sensitive data
error_log('DB password: ' . DB_PASSWORD);
error_log('User token: ' . $user_token);

// SECURE: Never log credentials or tokens
error_log('Authentication attempt for user ID: ' . $user_id);

// SECURE: Protect debug.log with .htaccess
// In wp-content/.htaccess:
// <Files debug.log>
//   Order allow,deny
//   Deny from all
// </Files>
```

**Detection regex:** `error_log\s*\(.*password|error_log\s*\(.*secret|error_log\s*\(.*token|error_log\s*\(.*key`
**Checkpoint:** SA-WP-11
**Severity:** warning

### Exposing WordPress Version and Login URL

Information disclosure through version numbers and default login URLs aids attackers in targeting known vulnerabilities.

```php
<?php
// SECURE: Remove version from head, feeds, and scripts
remove_action('wp_head', 'wp_generator');

function remove_version_from_scripts($src) {
    if (strpos($src, 'ver=')) {
        $src = remove_query_arg('ver', $src);
    }
    return $src;
}
add_filter('style_loader_src', 'remove_version_from_scripts');
add_filter('script_loader_src', 'remove_version_from_scripts');

// SECURE: Disable XML-RPC if not needed (prevents brute-force and DDoS)
add_filter('xmlrpc_enabled', '__return_false');

// SECURE: Limit login attempts (or use a plugin like Limit Login Attempts Reloaded)
// SECURE: Disable REST API user enumeration for unauthenticated users
add_filter('rest_authentication_errors', function ($result) {
    if (!is_user_logged_in()) {
        return new WP_Error(
            'rest_not_logged_in',
            'You are not currently logged in.',
            array('status' => 401)
        );
    }
    return $result;
});
```

**Detection regex:** `wp_generator|xmlrpc_enabled.*__return_true`
**Checkpoint:** SA-WP-12
**Severity:** warning

## Remediation Priority

| Finding | Severity | Remediation Timeline | Effort |
|---------|----------|---------------------|--------|
| SQL injection ($wpdb without prepare) | Critical | Immediate | Low |
| Object injection (unserialize) | Critical | Immediate | Medium |
| XSS (unescaped output) | High | Immediate | Low |
| REST API missing permission_callback | High | Immediate | Low |
| Missing capability checks | High | 1 week | Medium |
| CSRF (missing nonce verification) | High | 1 week | Low |
| Arbitrary file upload | Critical | Immediate | Medium |
| wp-config.php misconfiguration | High | 1 week | Low |
| Missing ABSPATH check | Medium | 1 month | Low |
| Default table prefix | Medium | 1 month (new installs) | Low |
| Debug log exposure | Medium | 1 week | Low |
| Version/info disclosure | Low | 1 month | Low |

## Related References

- `owasp-top10.md` — OWASP Top 10 mapping
- `php-security-features.md` — PHP-level security patterns
- `input-validation.md` — Input validation strategies
- `authentication-patterns.md` — Authentication and authorization patterns
- `xxe-prevention.md` — XXE prevention (relevant to XML-RPC)

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-03-31 | Initial release | CMS security references — Phase 3 |
