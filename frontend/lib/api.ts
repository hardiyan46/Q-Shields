import { clearAuthSession, getAccessToken } from "@/lib/auth";
import type {
  ApproveJobRequest,
  DashboardSummary,
  EndpointDetail,
  EndpointItem,
  EndpointStatus,
  ExecutionLogItem,
  FindingItem,
  FindingSource,
  FindingStatus,
  JobStatus,
  LoginRequest,
  OSFamily,
  RejectJobRequest,
  RemediationJob,
  RemediationJobDetail,
  SeverityLevel,
  SyncResult,
  TokenResponse,
  UserProfile,
} from "@/types/qshields";

const API_BASE_URL = (
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"
).replace(/\/+$/, "");

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

interface ApiFetchOptions extends RequestInit {
  skipAuthRedirect?: boolean;
}

async function apiFetch<T>(
  path: string,
  options: ApiFetchOptions = {}
): Promise<T> {
  const { skipAuthRedirect = false, headers: customHeaders, ...rest } = options;
  const headers = new Headers(customHeaders);

  if (rest.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const token = getAccessToken();
  if (token && !headers.has("Authorization")) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...rest,
    headers,
  });

  if (response.status === 401 && !skipAuthRedirect) {
    clearAuthSession();
    if (typeof window !== "undefined" && window.location.pathname !== "/login") {
      window.location.href = "/login";
    }
    throw new ApiError(401, "Sesi berakhir atau token tidak valid. Silakan login kembali.");
  }

  if (!response.ok) {
    let detailMessage = `Permintaan gagal (HTTP ${response.status})`;
    try {
      const errBody = (await response.json()) as { detail?: string | Array<{ msg?: string }> };
      if (typeof errBody.detail === "string") {
        detailMessage = errBody.detail;
      } else if (Array.isArray(errBody.detail) && errBody.detail[0]?.msg) {
        detailMessage = errBody.detail[0].msg;
      }
    } catch {
      // Ignore JSON parse error and keep HTTP status message
    }
    throw new ApiError(response.status, detailMessage);
  }

  return (await response.json()) as T;
}

export async function loginUser(payload: LoginRequest): Promise<TokenResponse> {
  return apiFetch<TokenResponse>("/api/auth/login", {
    method: "POST",
    body: JSON.stringify(payload),
    skipAuthRedirect: true,
  });
}

export async function fetchCurrentUser(): Promise<UserProfile> {
  return apiFetch<UserProfile>("/api/auth/me");
}

export async function syncWazuhData(): Promise<SyncResult> {
  return apiFetch<SyncResult>("/api/sync/wazuh", {
    method: "POST",
  });
}

export async function fetchDashboardSummary(): Promise<DashboardSummary> {
  return apiFetch<DashboardSummary>("/api/dashboard/summary");
}

export interface EndpointQueryParams {
  os_family?: OSFamily;
  status?: EndpointStatus;
  search?: string;
  skip?: number;
  limit?: number;
}

export async function fetchEndpoints(
  params: EndpointQueryParams = {}
): Promise<EndpointItem[]> {
  const qs = new URLSearchParams();
  if (params.os_family) qs.set("os_family", params.os_family);
  if (params.status) qs.set("status", params.status);
  if (params.search) qs.set("search", params.search);
  if (typeof params.skip === "number") qs.set("skip", String(params.skip));
  if (typeof params.limit === "number") qs.set("limit", String(params.limit));

  const query = qs.toString();
  return apiFetch<EndpointItem[]>(`/api/endpoints${query ? `?${query}` : ""}`);
}

export async function fetchEndpointDetail(
  endpointId: string
): Promise<EndpointDetail> {
  return apiFetch<EndpointDetail>(`/api/endpoints/${endpointId}`);
}

export interface FindingQueryParams {
  endpoint_id?: string;
  os_family?: OSFamily;
  source_type?: FindingSource;
  severity?: SeverityLevel;
  status?: FindingStatus;
  search?: string;
  skip?: number;
  limit?: number;
}

export async function fetchFindings(
  params: FindingQueryParams = {}
): Promise<FindingItem[]> {
  const qs = new URLSearchParams();
  if (params.endpoint_id) qs.set("endpoint_id", params.endpoint_id);
  if (params.os_family) qs.set("os_family", params.os_family);
  if (params.source_type) qs.set("source_type", params.source_type);
  if (params.severity) qs.set("severity", params.severity);
  if (params.status) qs.set("status", params.status);
  if (params.search) qs.set("search", params.search);
  if (typeof params.skip === "number") qs.set("skip", String(params.skip));
  if (typeof params.limit === "number") qs.set("limit", String(params.limit));

  const query = qs.toString();
  return apiFetch<FindingItem[]>(`/api/findings${query ? `?${query}` : ""}`);
}

export async function generateRemediation(
  findingId: string
): Promise<RemediationJob> {
  return apiFetch<RemediationJob>(
    `/api/findings/${findingId}/generate-remediation`,
    { method: "POST" }
  );
}

export interface RemediationQueryParams {
  status?: JobStatus;
  target_os?: OSFamily;
  skip?: number;
  limit?: number;
}

export async function fetchRemediations(
  params: RemediationQueryParams = {}
): Promise<RemediationJob[]> {
  const qs = new URLSearchParams();
  if (params.status) qs.set("status", params.status);
  if (params.target_os) qs.set("target_os", params.target_os);
  if (typeof params.skip === "number") qs.set("skip", String(params.skip));
  if (typeof params.limit === "number") qs.set("limit", String(params.limit));

  const query = qs.toString();
  return apiFetch<RemediationJob[]>(`/api/remediations${query ? `?${query}` : ""}`);
}

export async function fetchRemediationDetail(
  jobId: string
): Promise<RemediationJob> {
  return apiFetch<RemediationJob>(`/api/remediations/${jobId}`);
}

export async function fetchApprovalQueue(
  params: { skip?: number; limit?: number } = {}
): Promise<RemediationJobDetail[]> {
  const qs = new URLSearchParams();
  if (typeof params.skip === "number") qs.set("skip", String(params.skip));
  if (typeof params.limit === "number") qs.set("limit", String(params.limit));

  const query = qs.toString();
  return apiFetch<RemediationJobDetail[]>(
    `/api/approvals/queue${query ? `?${query}` : ""}`
  );
}

export async function fetchRemediationLogs(
  jobId: string
): Promise<ExecutionLogItem[]> {
  return apiFetch<ExecutionLogItem[]>(`/api/remediations/${jobId}/logs`);
}

export async function approveRemediationJob(
  jobId: string,
  payload: ApproveJobRequest = { execute_immediately: true }
): Promise<RemediationJobDetail> {
  return apiFetch<RemediationJobDetail>(`/api/remediations/${jobId}/approve`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function rejectRemediationJob(
  jobId: string,
  payload: RejectJobRequest
): Promise<RemediationJobDetail> {
  return apiFetch<RemediationJobDetail>(`/api/remediations/${jobId}/reject`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function executeRemediationJob(
  jobId: string
): Promise<RemediationJobDetail> {
  return apiFetch<RemediationJobDetail>(`/api/remediations/${jobId}/execute`, {
    method: "POST",
  });
}

export async function rollbackRemediationJob(
  jobId: string
): Promise<RemediationJobDetail> {
  return apiFetch<RemediationJobDetail>(`/api/remediations/${jobId}/rollback`, {
    method: "POST",
  });
}
