import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";

export function getReference(
  skillRoot: string,
  referenceName: string,
): string | null {
  const refPath = join(skillRoot, "skills/security-audit/references", referenceName);
  try {
    return readFileSync(refPath, "utf-8");
  } catch {
    return null;
  }
}

export function listReferences(skillRoot: string): string[] {
  const refDir = join(skillRoot, "skills/security-audit/references");
  if (!existsSync(refDir)) return [];
  return readdirSync(refDir).filter((f) => f.endsWith(".md")).sort();
}

export function explainFinding(
  skillRoot: string,
  checkpointId: string,
): { checkpoint: string; reference: string | null } | null {
  // Map checkpoint prefix to reference file
  const prefixToRef: Record<string, string> = {
    "SA-JS-": "javascript-typescript-security-features.md",
    "SA-NODE-": "nodejs-security-features.md",
    "SA-PY-": "python-security-features.md",
    "SA-JAVA-": "java-security-features.md",
    "SA-CS-": "csharp-security-features.md",
    "SA-GO-": "go-security-features.md",
    "SA-RS-": "rust-security-features.md",
    "SA-RB-": "ruby-security-features.md",
    "SA-REACT-": "react-security.md",
    "SA-NEXT-": "nextjs-security.md",
    "SA-VUE-": "vue-security.md",
    "SA-ANG-": "angular-security.md",
    "SA-NUXT-": "nuxt-security.md",
    "SA-DJANGO-": "django-security.md",
    "SA-FLASK-": "flask-security.md",
    "SA-FASTAPI-": "fastapi-security.md",
    "SA-SPRING-": "spring-security.md",
    "SA-DOTNET-": "dotnet-security.md",
    "SA-BLAZOR-": "blazor-security.md",
    "SA-GIN-": "gin-security.md",
    "SA-RAILS-": "rails-security.md",
    "SA-EXPRESS-": "express-security.md",
    "SA-NEST-": "nestjs-security.md",
    "SA-AWS-": "aws-security.md",
    "SA-GCP-": "gcp-security.md",
    "SA-AZURE-": "azure-security.md",
    "SA-WP-": "wordpress-security.md",
    "SA-DRUPAL-": "drupal-security.md",
    "SA-JOOMLA-": "joomla-security.md",
    "SA-ANDROID-": "android-sdk-security.md",
    "SA-IOS-": "ios-sdk-security.md",
  };

  // Find matching reference
  let refFile: string | null = null;
  for (const [prefix, file] of Object.entries(prefixToRef)) {
    if (checkpointId.startsWith(prefix)) {
      refFile = file;
      break;
    }
  }

  // Default to PHP reference for legacy SA-NN checkpoints
  if (!refFile && checkpointId.match(/^SA-\d/)) {
    refFile = "php-security-features.md";
  }

  const reference = refFile ? getReference(skillRoot, refFile) : null;

  return {
    checkpoint: checkpointId,
    reference,
  };
}
