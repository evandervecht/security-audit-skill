export { scanProject, scanFile } from "./scanner.js";
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
