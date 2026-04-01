# Plan: Multi-Language & Framework Security References

> Source PRD: [evandervecht/security-audit-skill#3](https://github.com/evandervecht/security-audit-skill/issues/3)
> Design Spec: `docs/superpowers/specs/2026-03-31-multi-language-security-references-design.md`

## Architectural decisions

- **Two reference templates**: Language references organized by version (`{language}-security-features.md`), framework references organized by vulnerability category (`{framework}-security.md`). Both include a changelog table at the bottom.
- **JavaScript + TypeScript merged**: Single `javascript-typescript-security-features.md` with a dedicated TypeScript section for type-safety patterns.
- **Checkpoint naming**: `SA-{LANG}-{NN}` for languages (e.g., `SA-PY-01`), `SA-{FRAMEWORK}-{NN}` for frameworks (e.g., `SA-REACT-01`). 10-20 per language, 5-15 per framework.
- **Scanner architecture**: Dispatcher (`security-audit.sh`) auto-detects languages via indicator files and invokes per-language modules in `scripts/scanners/{language}.sh`.
- **SKILL.md detection mapping**: Table mapping indicator files (e.g., `requirements.txt` -> Python) to references, so the AI agent loads only relevant context.
- **Eval fixtures**: `evals/{name}/vulnerable/` (true positives) and `evals/{name}/safe/` (true negatives) per language/framework, validated in CI.
- **Changelog + version monitoring**: Each reference has a changelog table. A GitHub Action monitors release feeds and opens issues when new versions ship.
- **Content scope**: 15-25KB per language reference, 10-20KB per framework reference. Top 10-15 vulnerability patterns per language.

---

## Phase 1: Infrastructure & Templates

**User stories**: #16, #17, #21, #22

### What to build

The foundational infrastructure that all subsequent phases depend on. Create the modular scanner dispatcher that auto-detects which languages/frameworks are present in a target project by checking for indicator files (`package.json`, `requirements.txt`, `go.mod`, `Cargo.toml`, etc.) and invokes only the relevant scanner modules. Extract the existing PHP scanning logic from `security-audit.sh` into `scripts/scanners/php.sh` as the first scanner module, proving the pattern works end-to-end.

Create blank reference templates (one for language, one for framework) that document the exact structure, sections, and conventions contributors must follow. Add a `CONTRIBUTING-REFERENCES.md` guide covering the checkpoint naming convention (`SA-{LANG}-{NN}`), the quality checklist (every pattern needs vulnerable code, secure code, detection regex, eval fixture), and how to add a new scanner module.

Update `SKILL.md` with the language/framework detection mapping table. Extend `validate_checkpoints.py` to validate the new checkpoint namespace prefixes. Set up the `evals/` directory structure with a test runner that validates detection regexes against fixture files.

### Acceptance criteria

- [ ] Dispatcher script detects languages/frameworks via indicator files and invokes matching scanner modules
- [ ] Existing PHP scanner logic extracted to `scripts/scanners/php.sh` without breaking existing functionality
- [ ] Blank language reference template and framework reference template exist and are documented
- [ ] `CONTRIBUTING-REFERENCES.md` covers naming conventions, quality checklist, and contribution workflow
- [ ] `SKILL.md` updated with detection mapping table
- [ ] `validate_checkpoints.py` validates new checkpoint namespace prefixes (e.g., `SA-PY-*`, `SA-JS-*`)
- [ ] Eval test runner validates regexes against fixture files in `evals/{name}/vulnerable/` and `evals/{name}/safe/`
- [ ] CI pipeline runs eval fixture validation
- [ ] All existing tests still pass

---

## Phase 2: Refactor `framework-security.md`

**User stories**: (prerequisite — establishes consistency for all framework references)

### What to build

Split the existing `framework-security.md` (41KB, bundling TYPO3/Symfony/Laravel) into three separate files: `typo3-security.md`, `symfony-security.md`, and `laravel-security.md`. This is a mechanical content split — no rewrites, no new content. Each resulting file follows the new framework reference template structure (organized by vulnerability category with remediation priority tables). Add a changelog table to each.

Update any cross-references in `SKILL.md`, `checkpoints.yaml`, and other references that point to `framework-security.md`. Remove the original bundled file. Update the detection mapping in `SKILL.md` so each framework maps to its own reference.

### Acceptance criteria

- [ ] `typo3-security.md`, `symfony-security.md`, `laravel-security.md` exist as separate files
- [ ] `framework-security.md` is removed
- [ ] All content from the original file is preserved (no content lost)
- [ ] Each file has a changelog table
- [ ] All cross-references updated (SKILL.md, checkpoints, other references)
- [ ] Detection mapping updated: `composer.json` with `typo3/*` -> `typo3-security.md`, etc.
- [ ] Existing checkpoints still reference the correct files

---

## Phase 3: JavaScript/TypeScript + Node.js Language References

**User stories**: #2, #14, #16, #18

### What to build

Create `javascript-typescript-security-features.md` covering both JS and TS security patterns: prototype pollution, unsafe `eval()`/`Function()`, DOM XSS sources/sinks, `postMessage` origin validation, `innerHTML`/`outerHTML`, regex DoS, deserialization (`JSON.parse` with reviver pitfalls), module import risks, and a TypeScript section covering `any` vs `unknown`, type assertion abuse, branded types for input validation, and `satisfies` for config safety. Organize by ES version where features are version-specific (ES2020+).

Create `nodejs-security-features.md` covering `child_process`/`execSync` injection, `fs` path traversal, `vm`/`vm2` sandbox escape, `Buffer` misuse, `require()` and dynamic imports, event loop blocking, HTTP header injection, stream backpressure, and Node.js version-specific features (e.g., Permission Model in Node 20+, `--experimental-policy` deprecation).

Add corresponding checkpoints (`SA-JS-01` through `SA-JS-20`, `SA-NODE-01` through `SA-NODE-15`) to `checkpoints.yaml`. Create scanner modules `scripts/scanners/javascript.sh` and `scripts/scanners/nodejs.sh`. Create eval fixtures with vulnerable and safe code samples for every detection regex.

### Acceptance criteria

- [ ] `javascript-typescript-security-features.md` is 15-25KB with vulnerable/secure code examples and detection regexes for every pattern
- [ ] TypeScript-specific section covers type safety patterns
- [ ] `nodejs-security-features.md` is 15-25KB with Node.js-specific vulnerability patterns
- [ ] 15-20 checkpoints each for JS/TS and Node.js added to `checkpoints.yaml`
- [ ] Scanner modules `javascript.sh` and `nodejs.sh` work with the dispatcher
- [ ] Eval fixtures exist for every detection regex (vulnerable + safe samples)
- [ ] All eval fixture tests pass in CI
- [ ] Detection mapping in SKILL.md updated for `package.json` -> JS/TS + Node.js references

---

## Phase 4: Python Language Reference

**User stories**: #1, #16, #18

### What to build

Create `python-security-features.md` covering: `pickle`/`shelve`/`marshal` insecure deserialization, `eval()`/`exec()`/`compile()` injection, SSTI in Jinja2/Mako, `subprocess`/`os.system` command injection, `yaml.load()` vs `yaml.safe_load()`, SQL injection across ORMs (raw queries, f-string interpolation), `xml.etree` XXE, path traversal (`os.path.join` bypass), JWT handling pitfalls, `hashlib` weak algorithms, `__import__`/`importlib` abuse, `tempfile` race conditions, and Python version-specific features (3.9-3.13: `tomllib`, `warnings.deprecated`, type parameter syntax, `pathlib` improvements).

Add checkpoints `SA-PY-01` through `SA-PY-20`. Create `scripts/scanners/python.sh`. Create eval fixtures.

### Acceptance criteria

- [ ] `python-security-features.md` is 15-25KB with version-organized security features
- [ ] 15-20 checkpoints added to `checkpoints.yaml` with `SA-PY-*` prefix
- [ ] Scanner module `python.sh` works with the dispatcher
- [ ] Eval fixtures exist for every detection regex
- [ ] All eval fixture tests pass
- [ ] Detection mapping updated for `requirements.txt`/`pyproject.toml`/`setup.py`

---

## Phase 5: Java + C#/.NET Language References

**User stories**: #8, #10, #16, #18

### What to build

Create `java-security-features.md` covering: insecure deserialization (`ObjectInputStream`, `XMLDecoder`), JNDI injection (Log4Shell pattern), reflection abuse (`Class.forName`, `Method.invoke`), SQL injection in JDBC, XML external entities, `Runtime.exec` command injection, path traversal, weak cryptography (`MD5`, `SHA1`, `DES`), insecure random (`java.util.Random`), SSRF patterns, and Java version-specific features (11-21: records for immutable data, sealed classes, pattern matching, text blocks for safe SQL).

Create `csharp-security-features.md` covering: `BinaryFormatter`/`NetDataContractSerializer` deserialization, SQL injection in Entity Framework raw queries, LDAP injection, XML external entities (`XmlDocument` vs `XmlReader`), `Process.Start` command injection, path traversal, CORS misconfiguration, `Convert.FromBase64String` edge cases, and C# version-specific features (9-12: records, file-scoped namespaces, `required` modifier, raw string literals).

Add checkpoints `SA-JAVA-01` through `SA-JAVA-15` and `SA-CS-01` through `SA-CS-15`. Create scanner modules and eval fixtures for both.

### Acceptance criteria

- [ ] `java-security-features.md` is 15-25KB
- [ ] `csharp-security-features.md` is 15-25KB
- [ ] 10-15 checkpoints each added to `checkpoints.yaml`
- [ ] Scanner modules `java.sh` and `csharp.sh` work with dispatcher
- [ ] Eval fixtures for both languages, all tests pass
- [ ] Detection mapping updated for `.java`/`pom.xml`/`build.gradle` and `*.cs`/`*.csproj`

---

## Phase 6: Go + Rust Language References

**User stories**: #11, #12, #16, #18

### What to build

Create `go-security-features.md` covering: goroutine race conditions (`-race` detector patterns), `unsafe` pointer usage, `text/template` vs `html/template` injection, SQL injection in `database/sql` (string concatenation vs parameterized), command injection via `os/exec`, path traversal (`filepath.Join` bypass with `..`), HTTP header injection, SSRF via `http.Get`, insecure TLS configuration, `crypto/rand` vs `math/rand`, integer overflow, and Go version-specific features (1.18-1.22: generics for type-safe validation, `log/slog` for structured security logging, range-over-func).

Create `rust-security-features.md` covering: `unsafe` blocks and their audit patterns, FFI boundary issues, `panic` in library code, `unwrap()`/`expect()` in production paths, integer overflow (debug vs release behavior), use-after-free via raw pointers, SQL injection in Diesel/sqlx, command injection via `std::process::Command`, path traversal, `serde` deserialization pitfalls, timing side-channel in comparisons, and Rust edition-specific features.

Add checkpoints, scanner modules, and eval fixtures for both.

### Acceptance criteria

- [ ] `go-security-features.md` is 15-25KB
- [ ] `rust-security-features.md` is 15-25KB
- [ ] 10-15 checkpoints each added to `checkpoints.yaml`
- [ ] Scanner modules `go.sh` and `rust.sh` work with dispatcher
- [ ] Eval fixtures for both languages, all tests pass
- [ ] Detection mapping updated for `go.mod` and `Cargo.toml`

---

## Phase 7: Ruby Language Reference

**User stories**: #13, #16, #18

### What to build

Create `ruby-security-features.md` covering: `eval`/`send`/`public_send` injection, `system`/`exec`/backtick command injection, `Marshal.load` insecure deserialization, YAML deserialization (`YAML.load` vs `YAML.safe_load`), ERB template injection, SQL injection (raw SQL, `find_by_sql`, string interpolation in queries), `html_safe`/`raw` XSS, mass assignment, `open-uri` SSRF, `Kernel.open` pipe injection, path traversal, weak cryptography, and Ruby version-specific features (3.0-3.3: pattern matching, `Data` class, YJIT security implications).

Add checkpoints `SA-RB-01` through `SA-RB-15`. Create `scripts/scanners/ruby.sh` and eval fixtures.

### Acceptance criteria

- [ ] `ruby-security-features.md` is 15-25KB
- [ ] 10-15 checkpoints added to `checkpoints.yaml`
- [ ] Scanner module `ruby.sh` works with dispatcher
- [ ] Eval fixtures for all detection regexes, all tests pass
- [ ] Detection mapping updated for `Gemfile`/`*.rb`

---

## Phase 8: Tier 1 Frontend Frameworks (React, Next.js, Vue, Angular, Nuxt)

**User stories**: #3, #4, #5, #6, #29

### What to build

Create five framework reference files, each organized by vulnerability category:

**`react-security.md`**: `dangerouslySetInnerHTML` XSS, JSX expression injection, `href="javascript:"` in links, `ref` leaking DOM access, insecure state management (sensitive data in state/context), `eval` in event handlers, server component vs client component data exposure, third-party component risks.

**`nextjs-security.md`**: Server Action validation (no auth in client-callable actions), API route auth bypass, middleware/proxy auth patterns, `getServerSideProps` data exposure, environment variable leakage (`NEXT_PUBLIC_*`), image optimization SSRF, open redirect via rewrites, cache poisoning, server component data serialization.

**`vue-security.md`**: `v-html` XSS, template expression injection, insecure directive usage, client-side auth bypass (route guards), `eval` in computed properties, Vuex/Pinia state exposure, SSR hydration mismatch data leak, third-party plugin risks.

**`angular-security.md`**: `bypassSecurityTrustHtml/Script/Url/ResourceUrl` misuse, template injection, DomSanitizer bypass, `innerHTML` binding, route guard bypass, `eval` in expressions, HTTP interceptor misconfiguration, zone.js context leaks.

**`nuxt-security.md`**: Server route auth bypass, `useAsyncData`/`useFetch` data exposure, middleware auth patterns, `runtimeConfig` vs `appConfig` secrets leakage, SSR-specific XSS, Nitro server handler security, plugin execution order risks.

Add checkpoints (`SA-REACT-*`, `SA-NEXT-*`, `SA-VUE-*`, `SA-ANG-*`, `SA-NUXT-*`), 5-15 per framework. Create eval fixtures.

### Acceptance criteria

- [ ] Five framework reference files, each 10-20KB
- [ ] 5-15 checkpoints per framework added to `checkpoints.yaml`
- [ ] Eval fixtures for all framework detection regexes
- [ ] All eval fixture tests pass
- [ ] Detection mapping updated (e.g., `package.json` with `react` -> `react-security.md`)

---

## Phase 9: Tier 1 Backend Frameworks — Python & Java/.NET (Django, Flask, FastAPI, Spring, .NET, Blazor)

**User stories**: #7, #9, #10, #30

### What to build

Create six framework reference files:

**`django-security.md`**: ORM injection (raw queries, `extra()`), CSRF misconfiguration, `mark_safe`/`|safe` XSS, `pickle` session backend, `DEBUG=True` in production, secret key exposure, file upload validation, admin site exposure, `@csrf_exempt` misuse.

**`flask-security.md`**: Jinja2 SSTI, `request.args` injection, `send_file`/`send_from_directory` path traversal, session cookie tampering (client-side sessions), `debug=True` in production, CORS misconfiguration, `flask-login` session fixation, SQLAlchemy raw query injection.

**`fastapi-security.md`**: Pydantic validation bypass, dependency injection auth patterns, CORS middleware misconfiguration, `Response` header injection, file upload handling, OAuth2 implementation pitfalls, background task data exposure, WebSocket auth.

**`spring-security.md`**: Spring Security misconfiguration (`permitAll` overreach), SpEL injection, actuator endpoint exposure, CSRF configuration, `@PreAuthorize` bypass, mass assignment via `@ModelAttribute`, Thymeleaf SSTI, Jackson deserialization, `RestTemplate` SSRF.

**`dotnet-security.md`**: ASP.NET Core middleware ordering (auth before routing), Entity Framework raw SQL, Razor view XSS, `[AllowAnonymous]` overreach, CORS policy misconfiguration, anti-forgery token misuse, `IDataProtector` key rotation, SignalR auth.

**`blazor-security.md`**: WebAssembly client-side auth bypass, server-side Blazor state management, JS interop injection, `[Authorize]` attribute bypass, component lifecycle data exposure, render mode security implications.

Add checkpoints and eval fixtures for all six frameworks.

### Acceptance criteria

- [ ] Six framework reference files, each 10-20KB
- [ ] 5-15 checkpoints per framework added to `checkpoints.yaml`
- [ ] Eval fixtures for all detection regexes
- [ ] All eval fixture tests pass
- [ ] Detection mapping updated for each framework's indicator patterns

---

## Phase 10: Tier 1 Backend Frameworks — Go, Ruby, Node.js (Gin, Rails, Express, NestJS)

**User stories**: #11, #13, #15, #31

### What to build

Create four framework reference files:

**`gin-security.md`**: Middleware ordering, `c.Bind` mass assignment, `c.HTML` template injection, CORS middleware misconfiguration, `c.File`/`c.FileAttachment` path traversal, panic recovery middleware, trusted proxy configuration, rate limiting patterns.

**`rails-security.md`**: Mass assignment (`permit`/`require`), `html_safe`/`raw` XSS, `find_by_sql` injection, CSRF token configuration, `send_file`/`send_data` path traversal, `render inline:` template injection, Active Storage file validation, Action Cable auth, `protect_from_forgery` ordering.

**`express-security.md`**: Middleware ordering (helmet, CORS, auth), `req.params`/`req.query` injection, `res.sendFile` path traversal, session configuration (secure cookies, session store), rate limiting, input validation (express-validator patterns), `eval` in route handlers, error handler information disclosure.

**`nestjs-security.md`**: Guard ordering and precedence, DTO validation (class-validator), interceptor data transformation, pipe validation bypass, `@Public` decorator misuse, WebSocket gateway auth, microservice transport security, GraphQL resolver auth.

Add checkpoints and eval fixtures for all four frameworks.

### Acceptance criteria

- [ ] Four framework reference files, each 10-20KB
- [ ] 5-15 checkpoints per framework added to `checkpoints.yaml`
- [ ] Eval fixtures for all detection regexes
- [ ] All eval fixture tests pass
- [ ] Detection mapping updated for each framework

---

## Phase 11: Eval Test Fixtures & CI Integration

**User stories**: #18, #22

### What to build

Review and harden the eval test infrastructure built incrementally in Phases 3-10. Ensure comprehensive coverage: every single detection regex across all language and framework checkpoints has at least one true-positive and one true-negative fixture. Add edge cases: patterns that look similar to vulnerabilities but are safe (e.g., `eval` in a comment, `pickle` in a variable name).

Extend CI to run the full eval suite on every PR. Add a CI step that validates checkpoint-to-reference consistency: every checkpoint must reference a pattern documented in its corresponding reference file. Add a CI step that validates the detection mapping in SKILL.md is complete (every reference file has at least one indicator mapping).

### Acceptance criteria

- [ ] Every checkpoint across all languages/frameworks has at least one true-positive and one true-negative fixture
- [ ] Edge case fixtures added (comments, variable names, string literals that contain pattern keywords)
- [ ] CI runs full eval suite on every PR
- [ ] CI validates checkpoint-to-reference consistency
- [ ] CI validates SKILL.md detection mapping completeness
- [ ] Zero false positives in safe fixtures, zero false negatives in vulnerable fixtures

---

## Phase 12: Changelog & Version Monitoring

**User stories**: #19, #20

### What to build

Add a GitHub Action workflow (`.github/workflows/version-monitor.yml`) that runs on a weekly cron schedule. It checks release feeds for all covered languages and frameworks: Python (python.org), Node.js (nodejs.org), Go (go.dev), Rust (releases.rs), Java (jdk.java.net), .NET (dotnet.microsoft.com), Ruby (ruby-lang.org), and major framework release feeds (Next.js, Django, Spring, Rails, etc.).

When a new major or minor version is detected, the workflow opens a GitHub issue tagged `reference-update` with the version number, release notes link, and a checklist of actions: review changelog for security-relevant features, update the language/framework reference, add new checkpoints if needed, update eval fixtures. The issue is assigned to the repository maintainer.

Verify all existing reference files have changelog tables (added in Phases 2-10). Add a CI check that validates changelog table presence and format in all reference files.

### Acceptance criteria

- [ ] `version-monitor.yml` workflow runs weekly and checks all covered language/framework releases
- [ ] New version detection opens a structured GitHub issue with checklist
- [ ] Issues are tagged `reference-update`
- [ ] All reference files have changelog tables
- [ ] CI validates changelog table presence and format

---

## Phase 13: Tier 2+3 Languages & Frameworks

**User stories**: #23, #24, #25, #26, #27, #28

### What to build

Create language references for: Kotlin, Swift, Dart, Elixir, Scala, Perl, Lua, R, and Shell/Bash. Create framework references for: Ktor, Vapor, iOS (UIKit/SwiftUI security patterns), Flutter, Phoenix, Play, Actix, and Axum.

Each follows the established templates and patterns from Phases 3-10. Add corresponding checkpoints, scanner modules, and eval fixtures for each. Update the detection mapping in SKILL.md and the version monitor workflow to cover the new languages/frameworks.

### Acceptance criteria

- [ ] 9 language reference files, each 15-25KB
- [ ] 8 framework reference files, each 10-20KB
- [ ] Checkpoints for all new languages/frameworks
- [ ] Scanner modules for all new languages
- [ ] Eval fixtures for all detection regexes, all tests pass
- [ ] Detection mapping in SKILL.md updated
- [ ] Version monitor covers new languages/frameworks
