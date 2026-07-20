# Joomla Security Patterns

Security patterns, common misconfigurations, and detection regexes for Joomla applications (components, modules, plugins, and templates).

## Injection

### SQL Injection via Unescaped Input in JDatabaseQuery

Joomla provides `JDatabaseQuery` (Joomla 3) and the `DatabaseInterface` (Joomla 4+) with quoting and binding methods. Building queries with string concatenation of user input leads to SQL injection.

```php
<?php
// VULNERABLE: String concatenation in query (Joomla 3)
use Joomla\CMS\Factory;

class MyModelUnsafe extends \Joomla\CMS\MVC\Model\ListModel
{
    public function getItems()
    {
        $app = Factory::getApplication();
        $search = $app->input->getString('search');
        $db = Factory::getDbo();

        // Direct concatenation — SQL injection
        $query = $db->getQuery(true);
        $query->select('*')
            ->from('#__content')
            ->where("title LIKE '%" . $search . "%'");

        $db->setQuery($query);
        return $db->loadObjectList();
    }
}

// VULNERABLE: Using raw input in setQuery string (Joomla 4)
use Joomla\CMS\Factory;

class MyModelRawUnsafe
{
    public function findUser($username)
    {
        $db = Factory::getContainer()->get('DatabaseDriver');
        $db->setQuery("SELECT * FROM #__users WHERE username = '$username'");
        return $db->loadObject();
    }
}

// SECURE: Use quote() and quoteName() (Joomla 3)
class MyModelQuoted extends \Joomla\CMS\MVC\Model\ListModel
{
    public function getItems()
    {
        $app = Factory::getApplication();
        $search = $app->input->getString('search');
        $db = Factory::getDbo();

        $query = $db->getQuery(true);
        $query->select('*')
            ->from($db->quoteName('#__content'))
            ->where($db->quoteName('title') . ' LIKE ' . $db->quote('%' . $db->escape($search) . '%'));

        $db->setQuery($query);
        return $db->loadObjectList();
    }
}

// SECURE: Use bind() with prepared statements (Joomla 4+, preferred)
use Joomla\Database\DatabaseInterface;

class MyModelPrepared
{
    private DatabaseInterface $db;

    public function __construct(DatabaseInterface $db)
    {
        $this->db = $db;
    }

    public function findUser(string $username): ?object
    {
        $query = $this->db->getQuery(true);
        $query->select('*')
            ->from($this->db->quoteName('#__users'))
            ->where($this->db->quoteName('username') . ' = :username')
            ->bind(':username', $username);

        $this->db->setQuery($query);
        return $this->db->loadObject();
    }

    public function searchContent(string $search): array
    {
        $query = $this->db->getQuery(true);
        $search = '%' . $search . '%';
        $query->select('*')
            ->from($this->db->quoteName('#__content'))
            ->where($this->db->quoteName('title') . ' LIKE :search')
            ->bind(':search', $search);

        $this->db->setQuery($query);
        return $this->db->loadObjectList();
    }
}
```

**Detection regex:** `->where\s*\(.*["'].*\.\s*\$|setQuery\s*\(\s*["'].*\$|->where\s*\(\s*["'].*\$`
**Checkpoint:** SA-JOOMLA-01
**Severity:** error

### Input Filtering via JInput

Joomla's `JInput` (and `Joomla\CMS\Input\Input`) provides type-aware filtering. Using `->get()` without a filter or with the `RAW` filter passes unvalidated input.

```php
<?php
use Joomla\CMS\Factory;

// VULNERABLE: No filter specified — defaults to CMD filter but intention unclear
$app = Factory::getApplication();
$value = $app->input->get('user_input');

// VULNERABLE: RAW filter — no sanitization at all
$rawValue = $app->input->get('data', '', 'RAW');

// VULNERABLE: Using $_GET/$_POST directly — bypasses Joomla filtering
$directValue = $_GET['search'];

// SECURE: Use type-specific getter methods
$id       = $app->input->getInt('id');           // Integers only
$cmd      = $app->input->getCmd('action');        // Alphanumeric + hyphen/underscore
$word     = $app->input->getWord('category');     // Alphabetic only
$string   = $app->input->getString('title');      // HTML stripped, trimmed
$email    = $app->input->get('email', '', 'EMAIL'); // Valid email format
$path     = $app->input->getPath('filepath');     // Safe filesystem path
$username = $app->input->getUsername('username');  // Valid username chars

// SECURE: Use specific filter with get()
$filtered = $app->input->get('content', '', 'STRING');
$html     = $app->input->get('body', '', 'HTML');       // Basic HTML allowed
$safeHtml = $app->input->get('body', '', 'SAFE_HTML');  // Strict HTML filtering

// SECURE: Array input with filter
$ids = $app->input->get('ids', [], 'ARRAY');
$ids = array_map('intval', $ids);  // Additional type enforcement
```

**Detection regex:** `->get\s*\([^,)]+\s*,\s*[^,)]*\s*,\s*['\"]RAW['\"]|\$_GET\s*\[|\$_POST\s*\[|\$_REQUEST\s*\[`
**Checkpoint:** SA-JOOMLA-02
**Severity:** error

## Authentication & Authorization

### Missing ACL Checks in Controllers

Joomla's ACL system uses `JFactory::getUser()->authorise()` (Joomla 3) or the `Identity` service (Joomla 4+). Controllers and models that skip authorization checks allow privilege escalation.

```php
<?php
// VULNERABLE: Controller action without ACL check (Joomla 3)
use Joomla\CMS\MVC\Controller\BaseController;

class MyController extends BaseController
{
    public function delete()
    {
        $id = $this->input->getInt('id');
        $model = $this->getModel();
        // No authorization check — any user can delete
        $model->delete($id);
        $this->setRedirect('index.php?option=com_mycomponent');
    }
}

// VULNERABLE: No ACL check on admin view (Joomla 4)
namespace My\Component\Administrator\Controller;

use Joomla\CMS\MVC\Controller\BaseController;

class ItemController extends BaseController
{
    public function save()
    {
        // Missing: $this->checkToken() for CSRF
        // Missing: authorization check
        $data = $this->input->post->getArray();
        $model = $this->getModel();
        $model->save($data);
    }
}

// SECURE: ACL check before state-changing operations (Joomla 3)
use Joomla\CMS\Factory;
use Joomla\CMS\MVC\Controller\BaseController;

class MyControllerSafe extends BaseController
{
    public function delete()
    {
        // Verify CSRF token
        $this->checkToken();

        $user = Factory::getUser();

        if (!$user->authorise('core.delete', 'com_mycomponent')) {
            throw new \Exception('JERROR_ALERTNOAUTHOR', 403);
        }

        $id = $this->input->getInt('id');

        // Object-level permission check
        if (!$user->authorise('core.delete', 'com_mycomponent.item.' . $id)) {
            throw new \Exception('JERROR_ALERTNOAUTHOR', 403);
        }

        $model = $this->getModel();
        $model->delete($id);
        $this->setRedirect('index.php?option=com_mycomponent', 'Item deleted.');
    }
}

// SECURE: Joomla 4 with FormController (includes built-in token + ACL)
namespace My\Component\Administrator\Controller;

use Joomla\CMS\MVC\Controller\FormController;

class ItemController extends FormController
{
    // FormController automatically checks token and calls allowEdit/allowAdd
    // Override these for custom ACL logic:

    protected function allowAdd($data = [])
    {
        return $this->app->getIdentity()->authorise('core.create', 'com_mycomponent');
    }

    protected function allowEdit($data = [], $key = 'id')
    {
        $id = $data[$key] ?? 0;
        return $this->app->getIdentity()->authorise('core.edit', 'com_mycomponent.item.' . $id);
    }
}
```

**Detection regex:** `extends\s+BaseController[^{]*\{[^}]*function\s+(delete|save|publish|unpublish|trash)\s*\([^)]*\)\s*\{(?!.*authorise|.*checkToken)`
**Checkpoint:** SA-JOOMLA-03
**Severity:** error

### Component Routing Without ACL Checks

Joomla component routes (via `router.php` or the new `RouterView` system) that don't enforce permissions allow direct URL access to restricted views.

```php
<?php
// VULNERABLE: View accessible without permission check
// components/com_mycomponent/src/View/Admin/HtmlView.php
namespace My\Component\Site\View\Admin;

use Joomla\CMS\MVC\View\HtmlView as BaseHtmlView;

class HtmlView extends BaseHtmlView
{
    public function display($tpl = null)
    {
        // No permission check — admin view accessible from frontend
        $this->items = $this->get('Items');
        parent::display($tpl);
    }
}

// SECURE: Check permissions in view
namespace My\Component\Site\View\Admin;

use Joomla\CMS\Factory;
use Joomla\CMS\MVC\View\HtmlView as BaseHtmlView;

class HtmlView extends BaseHtmlView
{
    public function display($tpl = null)
    {
        $user = Factory::getApplication()->getIdentity();

        if (!$user->authorise('core.manage', 'com_mycomponent')) {
            throw new \Joomla\CMS\Access\Exception\NotAllowed(
                \Joomla\CMS\Language\Text::_('JERROR_ALERTNOAUTHOR'),
                403
            );
        }

        $this->items = $this->get('Items');
        parent::display($tpl);
    }
}

// SECURE: Use access.xml to define component permissions
// admin/access.xml:
// <?xml version="1.0" encoding="utf-8"?>
// <access component="com_mycomponent">
//   <section name="component">
//     <action name="core.admin" title="JACTION_ADMIN" />
//     <action name="core.manage" title="JACTION_MANAGE" />
//     <action name="core.create" title="JACTION_CREATE" />
//     <action name="core.delete" title="JACTION_DELETE" />
//     <action name="core.edit" title="JACTION_EDIT" />
//   </section>
// </access>
```

**Detection regex:** `class\s+HtmlView\s+extends\s+BaseHtmlView[^{]*\{[^}]*function\s+display\s*\([^)]*\)\s*\{(?!.*authorise)`
**Checkpoint:** SA-JOOMLA-04
**Severity:** warning

## Security Misconfiguration

### `configuration.php` Hardening

Joomla's `configuration.php` contains database credentials, secret keys, and runtime settings. Misconfigurations here directly impact security.

```php
<?php
// VULNERABLE: Common misconfigurations in configuration.php
class JConfig {
    // Error reporting enabled — exposes file paths and stack traces
    public $error_reporting = 'maximum';

    // Weak or empty secret
    public $secret = 'joomla';

    // FTP credentials stored in config (legacy)
    public $ftp_user = 'admin';
    public $ftp_pass = 'password123';

    // Debug mode on in production
    public $debug = 1;

    // Session handler using file on shared hosting
    public $session_handler = 'file';

    // Writable tmp/log dirs inside webroot
    public $tmp_path = '/var/www/html/tmp';
    public $log_path = '/var/www/html/logs';
}

// SECURE: Hardened configuration.php
class JConfig {
    // Disable error reporting in production
    public $error_reporting = 'none';

    // Strong random secret (generated during install)
    public $secret = 'a-long-random-string-of-at-least-32-characters';

    // No FTP credentials stored
    public $ftp_user = '';
    public $ftp_pass = '';

    // Debug off in production
    public $debug = 0;

    // Database session handler (more secure on shared hosting)
    public $session_handler = 'database';

    // tmp/log dirs outside webroot
    public $tmp_path = '/home/user/joomla-tmp';
    public $log_path = '/home/user/joomla-logs';

    // Force HTTPS
    public $force_ssl = 2;  // 2 = entire site

    // Enforce strong session settings
    public $lifetime = 15;       // Session timeout in minutes
    public $session_metadata = 1;

    // Database credentials from environment (Joomla 4+)
    public $host = '';  // Set via environment or secrets manager
    public $user = '';
    public $password = '';
}
```

**Detection regex:** `\$error_reporting\s*=\s*['\"]maximum['\"]|\$debug\s*=\s*1|\$secret\s*=\s*['\"]joomla['\"]|\$ftp_pass\s*=\s*['\"][^'\"]['\"]`
**Checkpoint:** SA-JOOMLA-05
**Severity:** error

## Remediation Priority

| Finding | Severity | Remediation Timeline | Effort |
|---------|----------|---------------------|--------|
| SQL injection (unescaped query input) | Critical | Immediate | Low |
| Input filtering bypass (RAW/$_GET) | High | Immediate | Low |
| Missing ACL checks in controllers | High | 1 week | Medium |
| Component routing without ACL | Medium | 1 week | Medium |
| configuration.php misconfiguration | High | 1 week | Low |

## Related References

- `owasp-top10.md` — OWASP Top 10 mapping
- `php-security-features.md` — PHP-level security patterns
- `input-validation.md` — Input validation strategies
- `authentication-patterns.md` — Authentication and authorization patterns

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-03-31 | Initial release | CMS security references — Phase 3 |
