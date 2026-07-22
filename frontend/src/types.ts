export type Role = "admin" | "analyst" | "reviewer";
export type JobStatus = "queued" | "running" | "awaiting_review" | "approved" | "rejected" | "failed";
export type Verdict = "benign" | "suspicious" | "malicious" | "inconclusive";

export interface User {
  id: string;
  username: string;
  full_name: string;
  role: Role;
  is_active: boolean;
}

export interface CaseRecord {
  id: string;
  reference: string;
  title: string;
  description: string;
  classification: string;
  status: "open" | "sealed" | "closed";
  created_by_id: string;
  created_at: string;
  updated_at: string;
}

export interface Evidence {
  id: string;
  case_id: string;
  label: string;
  original_filename: string;
  kind: "file" | "raw_image" | "ewf_image" | "archive";
  status: "ingested" | "verified" | "compromised" | "analyzing" | "analyzed";
  size_bytes: number;
  sha256: string;
  sha1: string;
  md5: string;
  acquisition_notes: string;
  source_identifier: string | null;
  created_at: string;
}

export interface Finding {
  id: string;
  artifact_id: string | null;
  agent: string;
  category: string;
  severity: number;
  title: string;
  description: string;
  confidence: number | null;
  details: Record<string, unknown>;
  created_at: string;
}

export interface Artifact {
  id: string;
  evidence_id: string;
  relative_path: string;
  size_bytes: number;
  mime_type: string;
  sha256: string;
  sha1: string;
  md5: string;
  extracted_metadata: Record<string, unknown>;
  ground_truth_label: "benign" | "malicious" | null;
  created_at: string;
}

export interface Review {
  id: string;
  reviewer_id: string;
  decision: "approve" | "reject" | "needs_more_analysis";
  comments: string;
  created_at: string;
}

export interface Job {
  id: string;
  evidence_id: string;
  requested_by_id: string;
  status: JobStatus;
  pipeline_version: string;
  risk_score: number | null;
  verdict: Verdict | null;
  summary: Record<string, unknown>;
  error_message: string | null;
  requested_at: string;
  started_at: string | null;
  finished_at: string | null;
  findings?: Finding[];
  review?: Review | null;
}

export interface DashboardStats {
  open_cases: number;
  evidence_count: number;
  queued_jobs: number;
  awaiting_review: number;
  malicious_jobs: number;
  sandbox_configured: boolean;
  model_active: boolean;
}

export interface ModelVersion {
  id: string;
  version: string;
  algorithm: string;
  metrics: Record<string, unknown>;
  training_manifest_hash: string;
  is_active: boolean;
  created_at: string;
}
