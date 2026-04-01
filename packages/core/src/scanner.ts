import { readFileSync } from "node:fs";
import { glob } from "glob";
import { join, relative } from "node:path";
import type { Checkpoint, Finding, ScanResult } from "./types.js";
import { loadCheckpoints, getRelevantCheckpoints } from "./checkpoint-loader.js";
import { detectLanguages } from "./language-detector.js";

const IGNORE_PATTERNS = [
  "**/node_modules/**",
  "**/vendor/**",
  "**/dist/**",
  "**/build/**",
  "**/.git/**",
  "**/target/**",
  "**/.next/**",
  "**/coverage/**",
];

// Map checkpoint target globs to standard glob patterns
function resolveTargetGlob(target: string): string {
  // Checkpoint targets like "**/*.{js,ts}" are already glob-compatible
  return target;
}

function scanFileContent(
  filePath: string,
  content: string,
  checkpoints: Checkpoint[],
): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split("\n");

  for (const cp of checkpoints) {
    if (!cp.pattern) continue;

    let regex: RegExp;
    try {
      regex = new RegExp(cp.pattern);
    } catch {
      continue; // Skip invalid regex
    }

    for (let i = 0; i < lines.length; i++) {
      const match = regex.exec(lines[i]);
      if (match) {
        findings.push({
          checkpointId: cp.id,
          severity: cp.severity,
          message: cp.desc,
          file: filePath,
          line: i + 1,
          column: match.index + 1,
          matchedText: match[0],
        });
      }
    }
  }

  return findings;
}

export async function scanProject(
  projectPath: string,
  skillRoot: string,
): Promise<ScanResult> {
  const startTime = Date.now();
  const checkpointsPath = join(skillRoot, "skills/security-audit/checkpoints.yaml");

  // Detect languages
  const stack = detectLanguages(projectPath);

  // Load relevant checkpoints
  const data = loadCheckpoints(checkpointsPath);
  const checkpoints = getRelevantCheckpoints(data, stack.checkpointPrefixes);

  // Group checkpoints by their target glob
  const checkpointsByTarget = new Map<string, Checkpoint[]>();
  for (const cp of checkpoints) {
    const target = cp.target;
    if (!checkpointsByTarget.has(target)) {
      checkpointsByTarget.set(target, []);
    }
    checkpointsByTarget.get(target)!.push(cp);
  }

  const allFindings: Finding[] = [];
  let filesScanned = 0;

  // For each target glob, find matching files and scan them
  for (const [target, cps] of checkpointsByTarget) {
    const pattern = resolveTargetGlob(target);
    const files = await glob(pattern, {
      cwd: projectPath,
      ignore: IGNORE_PATTERNS,
      nodir: true,
      absolute: false,
    });

    for (const file of files) {
      const fullPath = join(projectPath, file);
      try {
        const content = readFileSync(fullPath, "utf-8");
        filesScanned++;
        const findings = scanFileContent(file, content, cps);
        allFindings.push(...findings);
      } catch {
        // Skip unreadable files (binary, permissions, etc.)
      }
    }
  }

  return {
    projectPath,
    detectedLanguages: stack.languages,
    findings: allFindings,
    checkpointsRun: checkpoints.length,
    filesScanned,
    duration: Date.now() - startTime,
  };
}

export async function scanFile(
  filePath: string,
  skillRoot: string,
): Promise<Finding[]> {
  const checkpointsPath = join(skillRoot, "skills/security-audit/checkpoints.yaml");
  const data = loadCheckpoints(checkpointsPath);

  // Find checkpoints whose target glob matches this file
  const matchingCheckpoints = data.mechanical.filter((cp) => {
    if (!cp.pattern) return false;
    // Simple extension matching from target glob
    const targetExts = extractExtensions(cp.target);
    const fileExt = filePath.split(".").pop() || "";
    return targetExts.length === 0 || targetExts.includes(fileExt);
  });

  try {
    const content = readFileSync(filePath, "utf-8");
    return scanFileContent(relative(process.cwd(), filePath), content, matchingCheckpoints);
  } catch {
    return [];
  }
}

function extractExtensions(target: string): string[] {
  // Extract extensions from patterns like "**/*.{js,ts,jsx,tsx}"
  const match = target.match(/\*\.(\{[^}]+\}|\w+)$/);
  if (!match) return [];
  const extPart = match[1];
  if (extPart.startsWith("{")) {
    return extPart.slice(1, -1).split(",");
  }
  return [extPart];
}
