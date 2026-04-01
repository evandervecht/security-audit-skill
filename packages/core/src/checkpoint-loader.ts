import { readFileSync } from "node:fs";
import { parse } from "yaml";
import type { Checkpoint, CheckpointData } from "./types.js";

let cachedData: CheckpointData | null = null;
let cachedPath: string | null = null;

export function loadCheckpoints(checkpointsPath: string): CheckpointData {
  if (cachedPath === checkpointsPath && cachedData) {
    return cachedData;
  }

  const content = readFileSync(checkpointsPath, "utf-8");
  const data = parse(content) as CheckpointData;
  cachedData = data;
  cachedPath = checkpointsPath;
  return data;
}

export function getRelevantCheckpoints(
  data: CheckpointData,
  prefixes: string[],
): Checkpoint[] {
  return data.mechanical.filter((cp) => {
    if (!cp.pattern) return false;
    return prefixes.some((prefix) => cp.id.startsWith(prefix));
  });
}
