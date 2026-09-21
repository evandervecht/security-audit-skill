import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import type { LanguageMapping } from "./types.js";

const LANGUAGE_MAPPINGS: LanguageMapping[] = [
  {
    indicators: ["composer.json"],
    language: "php",
    references: ["php-security-features.md"],
    checkpointPrefixes: ["SA-"],
    fileGlobs: ["**/*.php"],
  },
  {
    indicators: ["package.json"],
    language: "javascript",
    references: ["javascript-typescript-security-features.md", "frontend-security.md"],
    checkpointPrefixes: ["SA-JS-"],
    fileGlobs: ["**/*.{js,ts,jsx,tsx,mjs,cjs}"],
  },
  {
    indicators: ["package.json"],
    language: "nodejs",
    references: ["nodejs-security-features.md"],
    checkpointPrefixes: ["SA-NODE-"],
    fileGlobs: ["**/*.{js,ts,mjs,cjs}"],
  },
  {
    indicators: ["requirements.txt", "pyproject.toml", "setup.py", "Pipfile"],
    language: "python",
    references: ["python-security-features.md"],
    checkpointPrefixes: ["SA-PY-"],
    fileGlobs: ["**/*.py"],
  },
  {
    indicators: ["pom.xml", "build.gradle", "build.gradle.kts"],
    language: "java",
    references: ["java-security-features.md"],
    checkpointPrefixes: ["SA-JAVA-"],
    fileGlobs: ["**/*.java"],
  },
  {
    indicators: [],
    language: "csharp",
    references: ["csharp-security-features.md"],
    checkpointPrefixes: ["SA-CS-"],
    fileGlobs: ["**/*.cs"],
  },
  {
    indicators: ["go.mod"],
    language: "go",
    references: ["go-security-features.md"],
    checkpointPrefixes: ["SA-GO-"],
    fileGlobs: ["**/*.go"],
  },
  {
    indicators: ["Cargo.toml"],
    language: "rust",
    references: ["rust-security-features.md"],
    checkpointPrefixes: ["SA-RS-"],
    fileGlobs: ["**/*.rs"],
  },
  {
    indicators: ["Gemfile"],
    language: "ruby",
    references: ["ruby-security-features.md"],
    checkpointPrefixes: ["SA-RB-"],
    fileGlobs: ["**/*.rb"],
  },
  {
    indicators: ["Dockerfile", "docker-compose.yml", "docker-compose.yaml"],
    language: "docker",
    references: ["iac-security.md"],
    checkpointPrefixes: ["SA-IAC-"],
    fileGlobs: ["**/Dockerfile*", "**/docker-compose*.{yml,yaml}"],
  },
  {
    indicators: [".github/workflows"],
    language: "github-actions",
    references: ["github-actions-security.md"],
    checkpointPrefixes: ["SA-GHA-"],
    fileGlobs: ["**/.github/**/*.{yml,yaml}"],
  },
  {
    indicators: ["AndroidManifest.xml"],
    language: "android",
    references: ["android-sdk-security.md"],
    checkpointPrefixes: ["SA-ANDROID-"],
    fileGlobs: ["**/AndroidManifest.xml", "**/*.{kt,java}", "**/*.gradle"],
  },
  {
    indicators: ["Info.plist"],
    language: "ios",
    references: ["ios-sdk-security.md"],
    checkpointPrefixes: ["SA-IOS-"],
    fileGlobs: ["**/Info.plist", "**/*.swift", "**/*.m"],
  },
  {
    indicators: ["build.gradle.kts", "settings.gradle.kts"],
    language: "kotlin",
    references: ["kotlin-security-features.md"],
    checkpointPrefixes: ["SA-KT-"],
    fileGlobs: ["**/*.kt", "**/*.kts"],
  },
  {
    indicators: ["Package.swift"],
    language: "swift",
    references: ["swift-security-features.md"],
    checkpointPrefixes: ["SA-SWIFT-"],
    fileGlobs: ["**/*.swift"],
  },
  {
    indicators: ["build.sbt"],
    language: "scala",
    references: ["scala-security-features.md"],
    checkpointPrefixes: ["SA-SCALA-"],
    fileGlobs: ["**/*.scala"],
  },
  {
    indicators: ["pubspec.yaml"],
    language: "dart",
    references: ["dart-security-features.md"],
    checkpointPrefixes: ["SA-DART-"],
    fileGlobs: ["**/*.dart"],
  },
];

// Framework detection requires reading package.json/composer.json content
const FRAMEWORK_DETECTORS: Array<{
  check: (projectPath: string) => boolean;
  language: string;
  references: string[];
  checkpointPrefixes: string[];
}> = [
  {
    check: (p) => packageJsonContains(p, "react"),
    language: "react",
    references: ["react-security.md"],
    checkpointPrefixes: ["SA-REACT-"],
  },
  {
    check: (p) => packageJsonContains(p, "next"),
    language: "nextjs",
    references: ["nextjs-security.md"],
    checkpointPrefixes: ["SA-NEXT-"],
  },
  {
    check: (p) => packageJsonContains(p, "vue"),
    language: "vue",
    references: ["vue-security.md"],
    checkpointPrefixes: ["SA-VUE-"],
  },
  {
    check: (p) => packageJsonContains(p, "@angular/core"),
    language: "angular",
    references: ["angular-security.md"],
    checkpointPrefixes: ["SA-ANG-"],
  },
  {
    check: (p) => packageJsonContains(p, "nuxt"),
    language: "nuxt",
    references: ["nuxt-security.md"],
    checkpointPrefixes: ["SA-NUXT-"],
  },
  {
    check: (p) => packageJsonContains(p, "express"),
    language: "express",
    references: ["express-security.md"],
    checkpointPrefixes: ["SA-EXPRESS-"],
  },
  {
    check: (p) => packageJsonContains(p, "@nestjs/core"),
    language: "nestjs",
    references: ["nestjs-security.md"],
    checkpointPrefixes: ["SA-NEST-"],
  },
  {
    check: (p) => pythonDependsOn(p, "django"),
    language: "django",
    references: ["django-security.md"],
    checkpointPrefixes: ["SA-DJANGO-"],
  },
  {
    check: (p) => pythonDependsOn(p, "flask"),
    language: "flask",
    references: ["flask-security.md"],
    checkpointPrefixes: ["SA-FLASK-"],
  },
  {
    check: (p) => pythonDependsOn(p, "fastapi"),
    language: "fastapi",
    references: ["fastapi-security.md"],
    checkpointPrefixes: ["SA-FASTAPI-"],
  },
  {
    check: (p) => composerContains(p, "laravel/framework"),
    language: "laravel",
    references: ["laravel-security.md"],
    checkpointPrefixes: ["SA-"],
  },
  {
    check: (p) => composerContains(p, "symfony/"),
    language: "symfony",
    references: ["symfony-security.md"],
    checkpointPrefixes: ["SA-"],
  },
  {
    check: (p) => composerContains(p, "typo3/"),
    language: "typo3",
    references: ["typo3-security.md"],
    checkpointPrefixes: ["SA-"],
  },
  {
    check: (p) => existsSync(join(p, "wp-config.php")) || existsSync(join(p, "wp-content")),
    language: "wordpress",
    references: ["wordpress-security.md"],
    checkpointPrefixes: ["SA-WP-"],
  },
  {
    check: (p) =>
      ["build.gradle", "build.gradle.kts", "pom.xml"].some((f) => fileContains(p, f, "io.ktor")),
    language: "ktor",
    references: ["ktor-security.md"],
    checkpointPrefixes: ["SA-KTOR-"],
  },
  {
    check: (p) => fileContains(p, "Cargo.toml", "actix-web"),
    language: "actix",
    references: ["actix-security.md"],
    checkpointPrefixes: ["SA-ACTIX-"],
  },
  {
    check: (p) => fileContains(p, "Cargo.toml", "axum"),
    language: "axum",
    references: ["axum-security.md"],
    checkpointPrefixes: ["SA-AXUM-"],
  },
  {
    check: (p) => fileContains(p, "Package.swift", "vapor"),
    language: "vapor",
    references: ["vapor-security.md"],
    checkpointPrefixes: ["SA-VAPOR-"],
  },
  {
    check: (p) =>
      fileContains(p, "build.sbt", "playscala") ||
      fileContains(p, "build.sbt", "playjava") ||
      fileContains(p, "build.sbt", "com.typesafe.play") ||
      fileContains(p, "build.sbt", "org.playframework") ||
      fileContains(p, join("project", "plugins.sbt"), "play"),
    language: "play",
    references: ["play-security.md"],
    checkpointPrefixes: ["SA-PLAY-"],
  },
  {
    check: (p) => fileContains(p, "pubspec.yaml", "flutter"),
    language: "flutter",
    references: ["flutter-security.md"],
    checkpointPrefixes: ["SA-FLUTTER-"],
  },
];

function fileContains(projectPath: string, file: string, needle: string): boolean {
  try {
    const content = readFileSync(join(projectPath, file), "utf-8").toLowerCase();
    return content.includes(needle.toLowerCase());
  } catch {
    return false;
  }
}

function packageJsonContains(projectPath: string, dep: string): boolean {
  try {
    const content = readFileSync(join(projectPath, "package.json"), "utf-8");
    return content.includes(`"${dep}"`);
  } catch {
    return false;
  }
}

function pythonDependsOn(projectPath: string, pkg: string): boolean {
  for (const file of ["requirements.txt", "pyproject.toml", "Pipfile"]) {
    try {
      const content = readFileSync(join(projectPath, file), "utf-8");
      if (content.toLowerCase().includes(pkg)) return true;
    } catch {
      continue;
    }
  }
  return false;
}

function composerContains(projectPath: string, pkg: string): boolean {
  try {
    const content = readFileSync(join(projectPath, "composer.json"), "utf-8");
    return content.includes(pkg);
  } catch {
    return false;
  }
}

export interface DetectedStack {
  languages: string[];
  references: string[];
  checkpointPrefixes: string[];
  fileGlobs: string[];
}

export function detectLanguages(projectPath: string): DetectedStack {
  const languages: string[] = [];
  const references: string[] = ["owasp-top10.md", "cwe-top25.md", "cve-database.md"];
  const checkpointPrefixes: string[] = ["SA-"];
  const fileGlobs: string[] = [];

  // Check indicator files
  for (const mapping of LANGUAGE_MAPPINGS) {
    const hasIndicator =
      mapping.indicators.length === 0
        ? false
        : mapping.indicators.some((ind) => existsSync(join(projectPath, ind)));

    if (hasIndicator) {
      languages.push(mapping.language);
      references.push(...mapping.references);
      checkpointPrefixes.push(...mapping.checkpointPrefixes);
      fileGlobs.push(...mapping.fileGlobs);
    }
  }

  // Check for .csproj files (special case — need directory listing)
  try {
    const rootFiles = readdirSync(projectPath);
    if (rootFiles.some((f) => f.endsWith(".csproj") || f.endsWith(".sln"))) {
      const csMapping = LANGUAGE_MAPPINGS.find((m) => m.language === "csharp")!;
      languages.push("csharp");
      references.push(...csMapping.references);
      checkpointPrefixes.push(...csMapping.checkpointPrefixes);
      fileGlobs.push(...csMapping.fileGlobs);
    }
  } catch {
    // ignore
  }

  // Check frameworks
  for (const detector of FRAMEWORK_DETECTORS) {
    if (detector.check(projectPath)) {
      languages.push(detector.language);
      references.push(...detector.references);
      checkpointPrefixes.push(...detector.checkpointPrefixes);
    }
  }

  // Check for shell scripts (special case — need directory listing)
  try {
    const rootFiles = readdirSync(projectPath);
    if (rootFiles.some((f) => f.endsWith(".sh") || f.endsWith(".bash"))) {
      languages.push("shell");
      references.push("shell-security-features.md");
      checkpointPrefixes.push("SA-SH-");
      fileGlobs.push("**/*.sh", "**/*.bash");
    }
  } catch {
    // ignore
  }

  // Check for Terraform files
  try {
    const rootFiles = readdirSync(projectPath);
    if (rootFiles.some((f) => f.endsWith(".tf"))) {
      languages.push("terraform");
      references.push("iac-security.md", "aws-security.md", "gcp-security.md", "azure-security.md");
      checkpointPrefixes.push("SA-AWS-", "SA-GCP-", "SA-AZURE-");
      fileGlobs.push("**/*.tf", "**/*.json", "**/*.bicep");
    }
  } catch {
    // ignore
  }

  return {
    languages: [...new Set(languages)],
    references: [...new Set(references)],
    checkpointPrefixes: [...new Set(checkpointPrefixes)],
    fileGlobs: [...new Set(fileGlobs)],
  };
}
