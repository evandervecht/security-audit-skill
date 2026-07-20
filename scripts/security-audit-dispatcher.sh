#!/bin/bash
# Security Audit Dispatcher
# Auto-detects languages/frameworks in a project and invokes relevant scanner modules.
#
# Usage: ./scripts/security-audit-dispatcher.sh /path/to/project
#
# The dispatcher checks for indicator files (package.json, requirements.txt, go.mod, etc.)
# and runs only the scanner modules relevant to the detected stack.

set -e

PROJECT_DIR="${1:-.}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCANNERS_DIR="$SCRIPT_DIR/scanners"

TOTAL_ERRORS=0
TOTAL_WARNINGS=0
SCANNERS_RUN=0

echo "=== Security Audit Dispatcher ==="
echo "Project: $PROJECT_DIR"
echo ""

# Detect languages/frameworks and collect scanner list
DETECTED_SCANNERS=()

# PHP: composer.json or *.php files
if [[ -f "$PROJECT_DIR/composer.json" ]] || find "$PROJECT_DIR" -maxdepth 3 -name "*.php" -print -quit 2>/dev/null | grep -q .; then
    DETECTED_SCANNERS+=("php")
fi

# Python: requirements.txt, pyproject.toml, setup.py, Pipfile
if [[ -f "$PROJECT_DIR/requirements.txt" ]] || [[ -f "$PROJECT_DIR/pyproject.toml" ]] || [[ -f "$PROJECT_DIR/setup.py" ]] || [[ -f "$PROJECT_DIR/Pipfile" ]]; then
    DETECTED_SCANNERS+=("python")
fi

# JavaScript/TypeScript: package.json
if [[ -f "$PROJECT_DIR/package.json" ]]; then
    DETECTED_SCANNERS+=("javascript")
fi

# Node.js: package.json with server-side indicators
if [[ -f "$PROJECT_DIR/package.json" ]]; then
    if grep -q '"express"\|"fastify"\|"koa"\|"hapi"\|"nestjs"\|"node"\|"server"' "$PROJECT_DIR/package.json" 2>/dev/null; then
        DETECTED_SCANNERS+=("nodejs")
    fi
fi

# Java: pom.xml, build.gradle, *.java files
if [[ -f "$PROJECT_DIR/pom.xml" ]] || [[ -f "$PROJECT_DIR/build.gradle" ]] || [[ -f "$PROJECT_DIR/build.gradle.kts" ]]; then
    DETECTED_SCANNERS+=("java")
fi

# C#/.NET: *.csproj, *.sln
if find "$PROJECT_DIR" -maxdepth 2 \( -name "*.csproj" -o -name "*.sln" \) -print -quit 2>/dev/null | grep -q .; then
    DETECTED_SCANNERS+=("csharp")
fi

# Go: go.mod
if [[ -f "$PROJECT_DIR/go.mod" ]]; then
    DETECTED_SCANNERS+=("go")
fi

# Rust: Cargo.toml
if [[ -f "$PROJECT_DIR/Cargo.toml" ]]; then
    DETECTED_SCANNERS+=("rust")
fi

# Ruby: Gemfile
if [[ -f "$PROJECT_DIR/Gemfile" ]]; then
    DETECTED_SCANNERS+=("ruby")
fi

# Kotlin: Gradle Kotlin DSL or *.kt sources
if [[ -f "$PROJECT_DIR/build.gradle.kts" ]] || [[ -f "$PROJECT_DIR/settings.gradle.kts" ]] \
    || find "$PROJECT_DIR" -maxdepth 3 -name "*.kt" -not -path "*/build/*" -print -quit 2>/dev/null | grep -q .; then
    DETECTED_SCANNERS+=("kotlin")
fi

# Ktor: Gradle/Maven build referencing io.ktor
if grep -q "io\.ktor" "$PROJECT_DIR/build.gradle.kts" "$PROJECT_DIR/build.gradle" "$PROJECT_DIR/pom.xml" 2>/dev/null; then
    DETECTED_SCANNERS+=("ktor")
fi

# Swift: Package.swift, Xcode project, or *.swift sources
if [[ -f "$PROJECT_DIR/Package.swift" ]] \
    || find "$PROJECT_DIR" -maxdepth 3 \( -name "*.xcodeproj" -o -name "*.swift" \) -print -quit 2>/dev/null | grep -q .; then
    DETECTED_SCANNERS+=("swift")
fi

# Vapor: Package.swift depending on vapor
if [[ -f "$PROJECT_DIR/Package.swift" ]] && grep -qi "vapor" "$PROJECT_DIR/Package.swift" 2>/dev/null; then
    DETECTED_SCANNERS+=("vapor")
fi

# Scala: build.sbt or *.scala sources
if [[ -f "$PROJECT_DIR/build.sbt" ]] \
    || find "$PROJECT_DIR" -maxdepth 3 -name "*.scala" -not -path "*/target/*" -print -quit 2>/dev/null | grep -q .; then
    DETECTED_SCANNERS+=("scala")
fi

# Play Framework: sbt build enabling Play or depending on Play artifacts
if grep -Eq "PlayScala|PlayJava|com\.typesafe\.play|org\.playframework" \
    "$PROJECT_DIR/build.sbt" "$PROJECT_DIR/project/plugins.sbt" 2>/dev/null; then
    DETECTED_SCANNERS+=("play")
fi

# Dart/Flutter: pubspec.yaml or *.dart sources
if [[ -f "$PROJECT_DIR/pubspec.yaml" ]] \
    || find "$PROJECT_DIR" -maxdepth 3 -name "*.dart" -print -quit 2>/dev/null | grep -q .; then
    DETECTED_SCANNERS+=("dart")
fi

# Shell: *.sh / *.bash scripts
if find "$PROJECT_DIR" -maxdepth 3 \( -name "*.sh" -o -name "*.bash" \) -not -path "*/.git/*" -print -quit 2>/dev/null | grep -q .; then
    DETECTED_SCANNERS+=("shell")
fi

# Rust web frameworks (Actix/Axum): Cargo.toml with actix-web or axum
if [[ -f "$PROJECT_DIR/Cargo.toml" ]] && grep -Eq "actix-web|axum" "$PROJECT_DIR/Cargo.toml" 2>/dev/null; then
    DETECTED_SCANNERS+=("rust-web")
fi

# Android: AndroidManifest.xml or Android Gradle plugin
if find "$PROJECT_DIR" -maxdepth 4 -name "AndroidManifest.xml" -print -quit 2>/dev/null | grep -q . \
    || grep -q "com\.android" "$PROJECT_DIR/build.gradle" "$PROJECT_DIR/build.gradle.kts" 2>/dev/null; then
    DETECTED_SCANNERS+=("android")
fi

# iOS: Podfile, Info.plist, or Xcode project/workspace
if [[ -f "$PROJECT_DIR/Podfile" ]] \
    || find "$PROJECT_DIR" -maxdepth 3 \( -name "Info.plist" -o -name "*.xcodeproj" -o -name "*.xcworkspace" \) -print -quit 2>/dev/null | grep -q .; then
    DETECTED_SCANNERS+=("ios")
fi

# AWS: Terraform aws provider/resources, CloudFormation, or serverless config
if grep -rlE 'provider[[:space:]]+"aws"|resource[[:space:]]+"aws_' "$PROJECT_DIR" --include='*.tf' 2>/dev/null | grep -q . \
    || find "$PROJECT_DIR" -maxdepth 3 \( -name "serverless.yml" -o -name "template.yaml" -o -name "template.yml" \) -print -quit 2>/dev/null | grep -q .; then
    DETECTED_SCANNERS+=("aws")
fi

# GCP: Terraform google provider/resources or App Engine config
if grep -rlE 'provider[[:space:]]+"google"|resource[[:space:]]+"google_' "$PROJECT_DIR" --include='*.tf' 2>/dev/null | grep -q . \
    || [[ -f "$PROJECT_DIR/app.yaml" ]]; then
    DETECTED_SCANNERS+=("gcp")
fi

# Azure: Terraform azurerm provider/resources or Bicep templates
if grep -rlE 'provider[[:space:]]+"azurerm"|resource[[:space:]]+"azurerm_' "$PROJECT_DIR" --include='*.tf' 2>/dev/null | grep -q . \
    || find "$PROJECT_DIR" -maxdepth 3 -name "*.bicep" -print -quit 2>/dev/null | grep -q .; then
    DETECTED_SCANNERS+=("azure")
fi

# WordPress: wp-config.php, wp-content/, or plugin/theme headers
if [[ -f "$PROJECT_DIR/wp-config.php" ]] || [[ -d "$PROJECT_DIR/wp-content" ]] \
    || grep -rq "Plugin Name:" "$PROJECT_DIR" --include='*.php' 2>/dev/null; then
    DETECTED_SCANNERS+=("wordpress")
fi

# Drupal: *.info.yml manifests or drupal/* composer dependency
if find "$PROJECT_DIR" -maxdepth 3 -name "*.info.yml" -print -quit 2>/dev/null | grep -q . \
    || { [[ -f "$PROJECT_DIR/composer.json" ]] && grep -q "drupal/" "$PROJECT_DIR/composer.json" 2>/dev/null; }; then
    DETECTED_SCANNERS+=("drupal")
fi

# Joomla: joomla/* composer dependency or extension manifest XML
if { [[ -f "$PROJECT_DIR/composer.json" ]] && grep -q "joomla/" "$PROJECT_DIR/composer.json" 2>/dev/null; } \
    || grep -rq "<extension" "$PROJECT_DIR" --include='*.xml' 2>/dev/null; then
    DETECTED_SCANNERS+=("joomla")
fi


# graphql (expansion)
# GraphQL: *.graphql/*.gql schema files, or graphql/apollo-server dependency
if ls "$PROJECT_DIR"/*.graphql "$PROJECT_DIR"/*.gql >/dev/null 2>&1 \
    || [[ -f "$PROJECT_DIR/schema.graphql" ]] \
    || find "$PROJECT_DIR" -maxdepth 3 \( -name '*.graphql' -o -name '*.gql' \) -print -quit 2>/dev/null | grep -q . \
    || { [[ -f "$PROJECT_DIR/package.json" ]] && grep -Eq '"(graphql|apollo-server|@apollo/server|@apollo/server-[a-z-]+|graphql-yoga|type-graphql)"' "$PROJECT_DIR/package.json" 2>/dev/null; }; then
    DETECTED_SCANNERS+=("graphql")
fi

# kube (expansion)
# Kubernetes: manifests with apiVersion+kind, k8s/manifests dirs, kustomization.yaml, or Helm Chart.yaml
if [[ -d "$PROJECT_DIR/k8s" ]] || [[ -d "$PROJECT_DIR/kubernetes" ]] || [[ -d "$PROJECT_DIR/manifests" ]] \
    || [[ -f "$PROJECT_DIR/kustomization.yaml" ]] || [[ -f "$PROJECT_DIR/Chart.yaml" ]] \
    || grep -rlE '^apiVersion:' "$PROJECT_DIR" --include='*.yaml' --include='*.yml' 2>/dev/null \
         | xargs -I{} grep -lE '^kind:[[:space:]]*(Deployment|Pod|StatefulSet|DaemonSet|Job|CronJob|ReplicaSet|Secret|Service|Ingress)' {} 2>/dev/null \
         | grep -q .; then
    DETECTED_SCANNERS+=("kube")
fi

# svelte (expansion)
# Svelte / SvelteKit: *.svelte files, svelte.config.js, or package.json referencing svelte/@sveltejs/kit
if find "$PROJECT_DIR" -maxdepth 3 -name "*.svelte" -print -quit 2>/dev/null | grep -q . \
    || [[ -f "$PROJECT_DIR/svelte.config.js" ]] || [[ -f "$PROJECT_DIR/svelte.config.ts" ]] \
    || { [[ -f "$PROJECT_DIR/package.json" ]] && grep -q '"svelte"\|"@sveltejs/kit"' "$PROJECT_DIR/package.json" 2>/dev/null; }; then
    DETECTED_SCANNERS+=("svelte")
fi

# elixir (expansion)

# Elixir/Phoenix: mix.exs, *.ex/*.exs sources, or *.heex templates
if [[ -f "$PROJECT_DIR/mix.exs" ]] || \
   [[ -n "$(find "$PROJECT_DIR" -maxdepth 4 -name '*.ex' -o -name '*.exs' -o -name '*.heex' 2>/dev/null | head -1)" ]]; then
    DETECTED_SCANNERS+=("elixir")
fi

if [[ ${#DETECTED_SCANNERS[@]} -eq 0 ]]; then
    echo "No supported languages/frameworks detected."
    echo "Looked for: composer.json, package.json, requirements.txt, pyproject.toml,"
    echo "  go.mod, Cargo.toml, Gemfile, pom.xml, build.gradle, *.csproj,"
    echo "  build.gradle.kts, Package.swift, build.sbt, pubspec.yaml, *.sh,"
    echo "  AndroidManifest.xml, Podfile, *.tf, wp-config.php, *.info.yml"
    exit 0
fi

echo "Detected languages/frameworks: ${DETECTED_SCANNERS[*]}"
echo ""

# Run each detected scanner
for scanner in "${DETECTED_SCANNERS[@]}"; do
    SCANNER_SCRIPT="$SCANNERS_DIR/${scanner}.sh"
    if [[ -f "$SCANNER_SCRIPT" ]]; then
        echo "========================================"
        echo "Running $scanner scanner..."
        echo "========================================"
        set +e
        bash "$SCANNER_SCRIPT" "$PROJECT_DIR"
        SCANNER_EXIT=$?
        set -e
        TOTAL_ERRORS=$((TOTAL_ERRORS + SCANNER_EXIT))
        SCANNERS_RUN=$((SCANNERS_RUN + 1))
        echo ""
    else
        echo "Scanner module not yet available: $scanner (skipping)"
        echo "  To add: create $SCANNERS_DIR/${scanner}.sh"
        echo ""
    fi
done

# Always run secrets scanner regardless of detected languages
echo "========================================"
echo "Running secrets scanner..."
echo "========================================"
SECRETS_SCRIPT="$SCANNERS_DIR/secrets.sh"
if [[ -f "$SECRETS_SCRIPT" ]]; then
    set +e
    bash "$SECRETS_SCRIPT" "$PROJECT_DIR"
    SCANNER_EXIT=$?
    set -e
    TOTAL_ERRORS=$((TOTAL_ERRORS + SCANNER_EXIT))
    SCANNERS_RUN=$((SCANNERS_RUN + 1))
    echo ""
fi

# === Summary ===
echo "========================================"
echo "=== Dispatcher Summary ==="
echo "Scanners run: $SCANNERS_RUN"
echo "Total errors: $TOTAL_ERRORS"
echo "========================================"

if [[ $TOTAL_ERRORS -gt 0 ]]; then
    echo "Security audit FAILED with $TOTAL_ERRORS error(s)"
    exit 1
else
    echo "Security audit PASSED"
    exit 0
fi
