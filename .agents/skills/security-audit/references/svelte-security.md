# Svelte / SvelteKit Security Patterns

Security patterns, common misconfigurations, and detection regexes for Svelte and SvelteKit applications. Svelte auto-escapes text interpolation in templates and SvelteKit ships built-in CSRF origin checks, but developers can bypass these protections via `{@html}`, dynamic `<svelte:element>`, `eval`, mis-scoped `$env` imports, leaky server `load()` returns, and disabled CSRF config.

---

## Cross-Site Scripting (XSS)

### SA-SVELTE-01: {@html} Raw HTML Injection

The `{@html ...}` tag injects raw, unescaped HTML into the DOM, bypassing Svelte's automatic escaping. When the expression contains user-controlled data, it becomes a direct XSS vector.

```svelte
<!-- VULNERABLE: user comment rendered as raw HTML -->
<script>
  export let comment;
</script>

<div>{@html comment}</div>

<!-- VULNERABLE: markdown converted to HTML without sanitization -->
<script>
  import { marked } from 'marked';
  export let markdown;
  $: html = marked(markdown);
</script>

<div>{@html html}</div>
```

```svelte
<!-- SECURE: sanitize before rendering raw HTML -->
<script>
  import DOMPurify from 'dompurify';
  export let comment;
  $: clean = DOMPurify.sanitize(comment);
</script>

<div>{@html clean}</div>

<!-- SECURE: render as auto-escaped text -->
<script>
  export let comment;
</script>

<div>{comment}</div>
```

**Detection regex:** `\{@html\s`
**Checkpoint:** SA-SVELTE-01
**Severity:** error

---

### SA-SVELTE-03: Dynamic <svelte:element this={...}>

`<svelte:element this={tag}>` renders an element whose tag name is chosen at runtime. If `tag` is user-controlled, an attacker can render dangerous elements such as `<script>`, `<iframe>`, or `<object>`, leading to XSS or content injection.

```svelte
<!-- VULNERABLE: tag name from untrusted CMS content -->
<script>
  export let tag;
</script>

<svelte:element this={tag}>
  <slot />
</svelte:element>
```

```svelte
<!-- SECURE: resolve the tag against an allowlist -->
<script>
  export let level = 1;
  const ALLOWED = { 1: 'h1', 2: 'h2', 3: 'h3' };
  $: heading = ALLOWED[level] ?? 'h2';
</script>

<svelte:element this={heading}>
  <slot />
</svelte:element>
```

Note: the regex matches `this={...}` bindings whose identifier looks user-derived (tag, tagName, blockType, kind, variant, name, etc.). Binding to a value that is clearly resolved from an allowlist (as in the secure example) avoids the match — but the underlying risk is the *source* of the value, so always allowlist runtime tag names regardless of variable naming.

**Detection regex:** `<svelte:element\b[^>]*\bthis=\{[^}]*\b(?:tag|tagName|type|element|el|node|props|data|params|input|userTag|component|block|blockType|kind|variant|name)\b`
**Checkpoint:** SA-SVELTE-03
**Severity:** error

---

## Injection

### SA-SVELTE-04: eval() / new Function() in Components

Using `eval()` or `new Function()` inside a component evaluates arbitrary strings as code. When the input reaches user data, this is a code-injection vector.

```svelte
<!-- VULNERABLE: eval on user expression -->
<script>
  export let expression;
  function run() {
    return eval(expression);
  }
</script>

<button on:click={run}>Run</button>
```

```svelte
<!-- SECURE: use a dedicated, restricted parser -->
<script>
  import { evaluate } from 'mathjs';
  export let expression;
  function run() {
    return evaluate(expression);
  }
</script>

<button on:click={run}>Run</button>
```

**Detection regex:** `\beval\s*\(|new\s+Function\s*\(`
**Checkpoint:** SA-SVELTE-04
**Severity:** error

---

## Sensitive Data Exposure

### SA-SVELTE-02: Private $env Imported Outside Server-Only Code

SvelteKit splits environment access into public and private modules. `$env/static/private` and `$env/dynamic/private` must only be imported from server-only modules (`*.server.ts`, `$lib/server/...`, hooks). Importing them in components or universal (`+page.ts`) load files risks bundling secrets into client-shipped code.

```ts
// VULNERABLE: private secret imported into a universal/client module
import { STRIPE_SECRET_KEY } from '$env/static/private';

export function createCharge(amount) {
  return fetch('https://api.stripe.com/v1/charges', {
    headers: { Authorization: `Bearer ${STRIPE_SECRET_KEY}` },
    method: 'POST',
  });
}
```

```ts
// SECURE: client code only references public env values
import { PUBLIC_STRIPE_KEY } from '$env/static/public';
import { env } from '$env/dynamic/public';

export function getPublishableKey() {
  return PUBLIC_STRIPE_KEY ?? env.PUBLIC_API_URL;
}
```

**Detection regex:** `from\s+['"]\$env/(?:static|dynamic)/private['"]`
**Checkpoint:** SA-SVELTE-02
**Severity:** error

---

### SA-SVELTE-06: Server load() Returning Sensitive Fields

The object returned by a server `load()` function is serialized and sent to the client (it becomes `data` in the page). Returning full database records or auth material exposes those fields in the browser payload.

```ts
// VULNERABLE: sensitive fields serialized to the client
import type { PageServerLoad } from './$types';
import { db } from '$lib/server/db';

export const load: PageServerLoad = async ({ params }) => {
  const user = await db.user.findUnique({ where: { id: params.id } });
  return {
    user,
    passwordHash: user.passwordHash,
    apiToken: user.apiToken
  };
};
```

```ts
// SECURE: select only display-safe fields / build a DTO
import type { PageServerLoad } from './$types';
import { db } from '$lib/server/db';

export const load: PageServerLoad = async ({ params }) => {
  const user = await db.user.findUnique({
    where: { id: params.id },
    select: { id: true, name: true, avatarUrl: true }
  });
  return { user };
};
```

**Detection regex:** `load[^=]*=\s*async[\s\S]*?return\s*\{[^}]*\b(?:passwordHash|password|apiToken|refreshToken|accessToken|secret|ssn|creditCard|privateKey)\b`
**Checkpoint:** SA-SVELTE-06
**Severity:** error

---

## Security Misconfiguration

### SA-SVELTE-05: CSRF Origin Check Disabled

SvelteKit protects form actions and POST/PUT/PATCH/DELETE endpoints with an Origin check by default. Setting `csrf.checkOrigin: false` in `svelte.config.js` removes this protection and exposes the app to cross-site request forgery.

```js
// VULNERABLE: CSRF origin check disabled
import adapter from '@sveltejs/adapter-auto';

const config = {
  kit: {
    adapter: adapter(),
    csrf: {
      checkOrigin: false
    }
  }
};

export default config;
```

```js
// SECURE: keep the built-in origin check enabled
import adapter from '@sveltejs/adapter-auto';

const config = {
  kit: {
    adapter: adapter(),
    csrf: {
      checkOrigin: true
    }
  }
};

export default config;
```

**Detection regex:** `checkOrigin\s*:\s*false`
**Checkpoint:** SA-SVELTE-05
**Severity:** error

---

## Remediation Priority

| Finding | Severity | Remediation Timeline | Effort |
|---------|----------|---------------------|--------|
| SA-SVELTE-01: {@html} raw HTML XSS | High | Immediate | Low |
| SA-SVELTE-02: private $env in client code | High | Immediate | Low |
| SA-SVELTE-03: dynamic <svelte:element this> | High | 1 week | Medium |
| SA-SVELTE-04: eval / new Function injection | Critical | Immediate | Low |
| SA-SVELTE-05: CSRF checkOrigin disabled | High | Immediate | Low |
| SA-SVELTE-06: server load() leaks sensitive data | Medium | 1 week | Medium |

## Related References

- `owasp-top10.md` — OWASP Top 10 mapping
- `javascript-typescript-security-features.md` — Language-level patterns
- `frontend-security.md` — General frontend security patterns
- `react-security.md` — React-specific patterns (similar XSS/data-exposure classes)
- `nextjs-security.md` — Comparable server/client boundary concerns

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-06-13 | Initial release | Svelte/SvelteKit slice |
