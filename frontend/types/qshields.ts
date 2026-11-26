export type OSFamily = "linux" | "windows" | "macos";

export type ScriptLanguage = "bash" | "powershell" | "zsh_bsd";

export type AuthProvider = "LOCAL" | "LDAP";

export type AuthMode = "AUTO" | "LOCAL" | "LDAP";

export type UserRole = "OPERATOR" | "APPROVER" | "ADMIN";

export type EndpointStatus = "ACTIVE" | "DISCONNECTED" | "PENDING";

export type IsolationStatus = "NORMAL" | "ISOLATING" | "ISOLATED";

export type FindingSource = "CVE" | "SCA_CIS";

export type SeverityLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export type FindingStatus = "OPEN" | "IN_PROGRESS" | "RESOLVED" | "MANUAL_REQUIRED";

export type ExecutionActionType = "REMEDIATE" | "ROLLBACK";

export type JobStatus =
  | "DRAFT"
  | "PENDING_APPROVAL"
  | "APPROVED"
  | "REJECTED"
  | "EXECUTING"
  | "SUCCESS"
  | "FAILED"
  | "ROLLED_BACK";

export interface UserProfile {
  id: string;
  username: string;
  email: string | null;
  full_name: string;
  auth_provider: AuthProvider;
  ldap_dn: string | null;
  role: UserRole;
  is_active: boolean;
  last_login_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface LoginRequest {
  username: string;
  password: string;
  auth_mode: AuthMode;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  user: UserProfile;
}

export interface SeveritySummary {
  CRITICAL: number;
  HIGH: number;
  MEDIUM: number;
  LOW: number;
  total_open: number;
}

export interface FindingItem {
  id: string;
  endpoint_id: string;
  source_type: FindingSource;
  external_id: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  status: FindingStatus;
  remediation_hint: string | null;
  raw_payload: Record<string, unknown> | null;
  detected_at: string;
  resolved_at: string | null;
}

export interface EndpointItem {
  id: string;
  wazuh_agent_id: string;
  hostname: string;
  ip_address: string | null;
  os_family: OSFamily;
  os_name: string;
  os_version: string;
  architecture: string | null;
  agent_version: string | null;
  status: EndpointStatus;
  compliance_score: number | null;
  isolation_status: IsolationStatus;
  last_seen_at: string | null;
  created_at: string;
  updated_at: string;
  open_findings_count: number;
}

export interface EndpointDetail extends EndpointItem {
  findings_summary: SeveritySummary;
  findings: FindingItem[];
}

export interface SyncResult {
  mode: string;
  endpoints_synced: number;
  endpoints_created: number;
  endpoints_updated: number;
  findings_synced: number;
  findings_created: number;
  findings_updated: number;
  synced_at: string;
}

export interface DashboardSummary {
  total_endpoints: number;
  endpoints_by_os: Record<OSFamily, number>;
  open_findings_total: number;
  open_findings_by_severity: Record<SeverityLevel, number>;
  average_compliance_score: number | null;
}

export interface RemediationJob {
  id: string;
  endpoint_id: string;
  finding_id: string;
  target_os: OSFamily;
  script_language: ScriptLanguage;
  remediation_script: string;
  rollback_script: string;
  ai_explanation: string;
  risk_level: string;
  requires_reboot: boolean;
  requires_manual_mdm: boolean;
  backup_path: string;
  backup_targets: string[];
  has_pre_backup: boolean;
  status: JobStatus;
  linter_status: string;
  linter_report: Record<string, unknown> | null;
  is_canary: boolean;
  requested_by_id: string;
  approved_by_id: string | null;
  rejection_reason: string | null;
  created_at: string;
  approved_at: string | null;
}

export interface ApproveJobRequest {
  execute_immediately?: boolean;
}

export interface RejectJobRequest {
  rejection_reason: string;
}

export interface ExecutionLogItem {
  id: string;
  job_id: string;
  action_type: ExecutionActionType;
  triggered_by_id: string;
  exit_code: number | null;
  stdout: string | null;
  stderr: string | null;
  executed_at: string;
}

export interface EndpointBrief {
  id: string;
  wazuh_agent_id: string;
  hostname: string;
  ip_address: string | null;
  os_family: OSFamily;
  os_name: string;
  os_version: string;
  status: EndpointStatus;
}

export interface FindingBrief {
  id: string;
  source_type: FindingSource;
  external_id: string;
  title: string;
  severity: SeverityLevel;
  status: FindingStatus;
}

export interface RemediationJobDetail extends RemediationJob {
  endpoint?: EndpointBrief | null;
  finding?: FindingBrief | null;
  execution_logs: ExecutionLogItem[];
}
