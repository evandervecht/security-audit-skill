export interface Checkpoint {
  id: string;
  type: string;
  target: string;
  pattern?: string;
  severity: "error" | "warning" | "info";
  desc: string;
}

export interface CheckpointData {
  version: number;
  skill_id: string;
  mechanical: Checkpoint[];
  llm_reviews: Checkpoint[];
}

export interface Finding {
  checkpointId: string;
  severity: "error" | "warning" | "info";
  message: string;
  file: string;
  line: number;
  column: number;
  matchedText: string;
  referenceFile?: string;
}

export interface ScanResult {
  projectPath: string;
  detectedLanguages: string[];
  findings: Finding[];
  checkpointsRun: number;
  filesScanned: number;
  duration: number;
}

export interface LanguageMapping {
  indicators: string[];
  language: string;
  references: string[];
  checkpointPrefixes: string[];
  fileGlobs: string[];
}
