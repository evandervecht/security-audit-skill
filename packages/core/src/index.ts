export { scanProject, scanFile } from "./scanner.js";
export { scanLive } from "./live-scanner.js";
export type { LiveScanResult } from "./live-scanner.js";
export { enrichWithCves, lookupCvesForCheckpoint, queryNvd, queryOsv } from "./cve-feed.js";
export type { CveMatch, CveEnrichmentResult } from "./cve-feed.js";
export { detectLanguages } from "./language-detector.js";
export { loadCheckpoints, getRelevantCheckpoints } from "./checkpoint-loader.js";
export { getReference, listReferences, explainFinding } from "./references.js";
export type {
  Checkpoint,
  CheckpointData,
  Finding,
  ScanResult,
  LanguageMapping,
} from "./types.js";
export type { DetectedStack } from "./language-detector.js";
