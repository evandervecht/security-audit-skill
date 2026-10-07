# Stack Detection

When auditing a project, load only the references relevant to the detected stack. Check for these indicator files, then load the listed references from `references/`.

| Indicator | Language/Framework | References to Load |
|-----------|-------------------|-------------------|
| `composer.json`, `*.php` | PHP | `php-security-features.md` |
| `composer.json` with `typo3/*` | TYPO3 | `typo3-security.md` |
| `composer.json` with `symfony/*` | Symfony | `symfony-security.md` |
| `composer.json` with `laravel/*` | Laravel | `laravel-security.md` |
| `package.json` | JavaScript/TypeScript | `javascript-typescript-security-features.md`, `frontend-security.md` |
| `package.json` with `express`/`fastify`/`koa`/`nestjs` | Node.js | `nodejs-security-features.md` |
| `package.json` with `react` | React | `react-security.md` |
| `package.json` with `next` | Next.js | `nextjs-security.md` |
| `package.json` with `vue` | Vue | `vue-security.md` |
| `package.json` with `@angular/core` | Angular | `angular-security.md` |
| `package.json` with `nuxt` | Nuxt | `nuxt-security.md` |
| `requirements.txt`, `pyproject.toml`, `setup.py`, `Pipfile` | Python | `python-security-features.md` |
| Python with `django` | Django | `django-security.md` |
| Python with `flask` | Flask | `flask-security.md` |
| Python with `fastapi` | FastAPI | `fastapi-security.md` |
| `pom.xml`, `build.gradle` | Java | `java-security-features.md` |
| Java with `spring` | Spring | `spring-security.md` |
| `*.csproj`, `*.sln` | C#/.NET | `csharp-security-features.md`, `dotnet-security.md` |
| .NET with `Blazor` | Blazor | `blazor-security.md` |
| `go.mod` | Go | `go-security-features.md` |
| Go with `gin-gonic` | Gin | `gin-security.md` |
| `Cargo.toml` | Rust | `rust-security-features.md` |
| `Gemfile` | Ruby | `ruby-security-features.md` |
| Ruby with `rails` | Rails | `rails-security.md` |
| `Dockerfile`, `docker-compose.yml` | Docker | `iac-security.md` |
| `*.tf` | Terraform | `iac-security.md` |
| `*.graphql`/`*.gql`, `apollo-server` | graphql | `graphql-security.md` |
| `*.yaml` with `apiVersion:`+`kind:`, `kustomization.yaml`, `Chart.yaml` | kube | `kubernetes-security.md` |
| `.github/workflows/*.yml`, `.github/actions/*/action.yml` | GitHub Actions | `github-actions-security.md` |
| `package.json` with `svelte`/`@sveltejs/kit`, `*.svelte`, `svelte.config.js` | Svelte | `svelte-security.md` |
| `mix.exs`, `*.ex`/`*.exs`, `*.heex` | elixir | `elixir-phoenix-security.md` |
| `build.gradle.kts`, `settings.gradle.kts`, `*.kt` | Kotlin | `kotlin-security-features.md` |
| Gradle/Maven build with `io.ktor` | Ktor | `ktor-security.md` |
| `Package.swift`, `*.xcodeproj`, `*.swift` | Swift | `swift-security-features.md` |
| `Package.swift` with `vapor` | Vapor | `vapor-security.md` |
| `build.sbt`, `*.scala` | Scala | `scala-security-features.md` |
| `build.sbt` with `PlayScala`/`org.playframework` | Play | `play-security.md` |
| `pubspec.yaml`, `*.dart` | Dart | `dart-security-features.md` |
| `pubspec.yaml` with `flutter` | Flutter | `flutter-security.md` |
| `*.sh`, `*.bash` | Shell | `shell-security-features.md` |
| `Cargo.toml` with `actix-web` | Actix | `actix-security.md` |
| `Cargo.toml` with `axum` | Axum | `axum-security.md` |

Always load `owasp-top10.md` and `cwe-top25.md` regardless of stack. `scripts/security-audit-dispatcher.sh` uses the same indicators to pick scanner modules.
