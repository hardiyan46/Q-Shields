"use client";

import { Suspense, useCallback, useEffect, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import {
  AlertTriangle,
  CheckCircle2,
  ClipboardCheck,
  Eye,
  Lock,
  RefreshCw,
} from "lucide-react";

import { AppNavbar } from "@/components/app-navbar";
import { RemediationReviewDialog } from "@/components/remediation-review-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  ApiError,
  fetchApprovalQueue,
  fetchCurrentUser,
  fetchEndpoints,
  fetchFindings,
  fetchRemediations,
} from "@/lib/api";
import { getAccessToken, getStoredUser, setAuthSession } from "@/lib/auth";
import type {
  EndpointItem,
  FindingItem,
  JobStatus,
  OSFamily,
  RemediationJob,
  RemediationJobDetail,
  ScriptLanguage,
  UserProfile,
} from "@/types/qshields";

function osBadgeClass(osFamily: OSFamily): string {
  if (osFamily === "linux") return "border-amber-300 bg-amber-50 text-amber-800";
  if (osFamily === "windows") return "border-sky-300 bg-sky-50 text-sky-800";
  return "border-slate-300 bg-slate-100 text-slate-800";
}

function statusBadgeClass(status: JobStatus): string {
  switch (status) {
    case "PENDING_APPROVAL":
      return "border-amber-300 bg-amber-50 text-amber-800";
    case "APPROVED":
      return "border-blue-300 bg-blue-50 text-blue-800";
    case "EXECUTING":
      return "border-indigo-300 bg-indigo-50 text-indigo-800";
    case "SUCCESS":
      return "border-emerald-300 bg-emerald-50 text-emerald-800";
    case "FAILED":
      return "border-red-300 bg-red-50 text-red-800";
    case "REJECTED":
      return "border-slate-300 bg-slate-100 text-slate-700";
    case "ROLLED_BACK":
      return "border-purple-300 bg-purple-50 text-purple-800";
    default:
      return "border-slate-200 bg-slate-50 text-slate-700";
  }
}

function riskBadgeClass(risk: string): string {
  const upper = risk.toUpperCase();
  if (upper === "HIGH" || upper === "CRITICAL") {
    return "border-red-300 bg-red-50 text-red-800";
  }
  if (upper === "MEDIUM") {
    return "border-amber-300 bg-amber-50 text-amber-800";
  }
  return "border-blue-300 bg-blue-50 text-blue-800";
}

function formatScriptLanguage(lang: ScriptLanguage): string {
  if (lang === "zsh_bsd") return "macos_shell (zsh_bsd)";
  return lang;
}

type QueueRow = RemediationJob & Partial<Pick<RemediationJobDetail, "endpoint" | "finding">>;

function ApprovalsPageContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const queryJobId = searchParams.get("jobId");

  const [authChecked, setAuthChecked] = useState(false);
  const [user, setUser] = useState<UserProfile | null>(null);
  const [pendingCount, setPendingCount] = useState(0);

  const [activeTab, setActiveTab] = useState<"pending" | "history">("pending");
  const [historyStatusFilter, setHistoryStatusFilter] = useState<"ALL" | JobStatus>("ALL");
  const [historyOsFilter, setHistoryOsFilter] = useState<"ALL" | OSFamily>("ALL");

  const [pendingJobs, setPendingJobs] = useState<QueueRow[]>([]);
  const [historyJobs, setHistoryJobs] = useState<RemediationJob[]>([]);
  const [endpoints, setEndpoints] = useState<EndpointItem[]>([]);
  const [findings, setFindings] = useState<FindingItem[]>([]);

  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const [reviewOpen, setReviewOpen] = useState(false);
  const [selectedJob, setSelectedJob] = useState<QueueRow | null>(null);
  const [selectedJobId, setSelectedJobId] = useState<string | null>(null);

  const endpointMap = useMemo(() => {
    const map = new Map<string, EndpointItem>();
    for (const ep of endpoints) map.set(ep.id, ep);
    return map;
  }, [endpoints]);

  const findingMap = useMemo(() => {
    const map = new Map<string, FindingItem>();
    for (const f of findings) map.set(f.id, f);
    return map;
  }, [findings]);

  const loadJobs = useCallback(
    async (currentUser: UserProfile) => {
      const canAccessApprovalsQueue =
        currentUser.role === "APPROVER" || currentUser.role === "ADMIN";

      const [pendingList, historyList, epList, findingList] = await Promise.all([
        canAccessApprovalsQueue
          ? fetchApprovalQueue({ limit: 100 })
          : fetchRemediations({ status: "PENDING_APPROVAL", limit: 100 }),
        fetchRemediations({
          status: historyStatusFilter === "ALL" ? undefined : historyStatusFilter,
          target_os: historyOsFilter === "ALL" ? undefined : historyOsFilter,
          limit: 100,
        }),
        fetchEndpoints({ limit: 200 }),
        fetchFindings({ limit: 200 }),
      ]);

      setPendingJobs(pendingList);
      setPendingCount(pendingList.length);
      setHistoryJobs(historyList);
      setEndpoints(epList);
      setFindings(findingList);
    },
    [historyStatusFilter, historyOsFilter]
  );

  // Auth bootstrap
  useEffect(() => {
    const token = getAccessToken();
    if (!token) {
      router.replace("/login");
      return;
    }

    const cached = getStoredUser();
    if (cached) setUser(cached);

    let cancelled = false;
    async function init() {
      try {
        const me = await fetchCurrentUser();
        if (cancelled) return;
        setUser(me);
        if (token) setAuthSession(token, me);
        setAuthChecked(true);
        await loadJobs(me);
      } catch (err) {
        if (!cancelled && err instanceof ApiError && err.status !== 401) {
          setErrorMsg(err.message);
        }
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    }

    void init();
    return () => {
      cancelled = true;
    };
  }, [router, loadJobs]);

  // Reload history tab when filters change
  useEffect(() => {
    if (!authChecked || !user) return;
    void loadJobs(user).catch((err: unknown) => {
      if (err instanceof ApiError) setErrorMsg(err.message);
    });
  }, [authChecked, user, loadJobs]);

  // Auto-open review modal if ?jobId=<uuid> is present in URL
  useEffect(() => {
    if (!authChecked || !queryJobId) return;
    setSelectedJobId(queryJobId);
    const match =
      pendingJobs.find((j) => j.id === queryJobId) ??
      historyJobs.find((j) => j.id === queryJobId) ??
      null;
    setSelectedJob(match);
    setReviewOpen(true);
  }, [authChecked, queryJobId, pendingJobs, historyJobs]);

  async function handleRefresh() {
    if (!user) return;
    setIsRefreshing(true);
    setErrorMsg(null);
    try {
      await loadJobs(user);
    } catch (err) {
      setErrorMsg(err instanceof ApiError ? err.message : "Gagal memuat ulang daftar job.");
    } finally {
      setIsRefreshing(false);
    }
  }

  function handleOpenReview(job: QueueRow) {
    setSelectedJob(job);
    setSelectedJobId(job.id);
    setReviewOpen(true);
  }

  async function handleActionCompleted(message: string) {
    setSuccessMsg(message);
    if (user) {
      await loadJobs(user);
    }
  }

  if (!authChecked && isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <RefreshCw className="h-4 w-4 animate-spin" />
          Memuat Approval Queue...
        </div>
      </div>
    );
  }

  const displayedJobs: QueueRow[] =
    activeTab === "pending" ? pendingJobs : historyJobs;

  return (
    <div className="min-h-screen bg-slate-50">
      <AppNavbar
        user={user}
        pendingCount={pendingCount}
        rightSlot={
          <Button
            size="sm"
            variant="outline"
            onClick={() => void handleRefresh()}
            disabled={isRefreshing}
          >
            <RefreshCw className={`h-4 w-4 ${isRefreshing ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        }
      />

      <main className="mx-auto max-w-7xl space-y-6 px-4 py-6 sm:px-6">
        {errorMsg && (
          <div
            role="alert"
            className="flex items-start justify-between gap-3 rounded-lg border border-red-200 bg-red-50 p-3.5 text-sm text-red-800"
          >
            <div className="flex items-start gap-2">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
              <span>{errorMsg}</span>
            </div>
            <button
              type="button"
              onClick={() => setErrorMsg(null)}
              className="text-xs font-semibold underline"
            >
              Tutup
            </button>
          </div>
        )}

        {successMsg && (
          <div className="flex items-center justify-between gap-3 rounded-lg border border-emerald-200 bg-emerald-50 p-3.5 text-sm text-emerald-800">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 shrink-0" />
              <span>{successMsg}</span>
            </div>
            <button
              type="button"
              onClick={() => setSuccessMsg(null)}
              className="text-xs font-semibold underline"
            >
              Tutup
            </button>
          </div>
        )}

        {user?.role === "OPERATOR" && (
          <div className="flex items-center gap-2 rounded-lg border border-amber-200 bg-amber-50 p-3 text-xs text-amber-900">
            <Lock className="h-4 w-4 shrink-0" />
            <span>
              Mode Read-Only: Anda login sebagai <strong>OPERATOR</strong>. Aksi Approve,
              Reject, Execute, dan Rollback membutuhkan role <strong>APPROVER</strong> atau{" "}
              <strong>ADMIN</strong>.
            </span>
          </div>
        )}

        <Card>
          <CardHeader className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <ClipboardCheck className="h-5 w-5 text-blue-600" />
                Approval Queue &amp; Remediation Jobs
              </CardTitle>
              <CardDescription>
                Tinjau pre-change backup, skrip remediasi, rollback script, dan log eksekusi
                sebelum menyetujui perubahan ke endpoint.
              </CardDescription>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <Tabs
                value={activeTab}
                onValueChange={(v) => setActiveTab(v as "pending" | "history")}
              >
                <TabsList>
                  <TabsTrigger value="pending">
                    Pending Approval ({pendingJobs.length})
                  </TabsTrigger>
                  <TabsTrigger value="history">All Jobs &amp; History</TabsTrigger>
                </TabsList>
              </Tabs>

              {activeTab === "history" && (
                <>
                  <Select
                    value={historyStatusFilter}
                    onValueChange={(v) => setHistoryStatusFilter(v as "ALL" | JobStatus)}
                  >
                    <SelectTrigger className="w-44">
                      <SelectValue placeholder="Filter Status" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="ALL">Semua Status</SelectItem>
                      <SelectItem value="PENDING_APPROVAL">PENDING_APPROVAL</SelectItem>
                      <SelectItem value="APPROVED">APPROVED</SelectItem>
                      <SelectItem value="EXECUTING">EXECUTING</SelectItem>
                      <SelectItem value="SUCCESS">SUCCESS</SelectItem>
                      <SelectItem value="FAILED">FAILED</SelectItem>
                      <SelectItem value="REJECTED">REJECTED</SelectItem>
                      <SelectItem value="ROLLED_BACK">ROLLED_BACK</SelectItem>
                    </SelectContent>
                  </Select>

                  <Select
                    value={historyOsFilter}
                    onValueChange={(v) => setHistoryOsFilter(v as "ALL" | OSFamily)}
                  >
                    <SelectTrigger className="w-36">
                      <SelectValue placeholder="Target OS" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="ALL">Semua OS</SelectItem>
                      <SelectItem value="linux">linux</SelectItem>
                      <SelectItem value="windows">windows</SelectItem>
                      <SelectItem value="macos">macos</SelectItem>
                    </SelectContent>
                  </Select>
                </>
              )}
            </div>
          </CardHeader>

          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Job ID</TableHead>
                  <TableHead>Target Endpoint</TableHead>
                  <TableHead>Temuan (CVE / CIS)</TableHead>
                  <TableHead>Script</TableHead>
                  <TableHead>Risk</TableHead>
                  <TableHead>Pre-Backup</TableHead>
                  <TableHead>Flags</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Aksi</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {displayedJobs.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={9} className="py-10 text-center text-muted-foreground">
                      {activeTab === "pending"
                        ? "Tidak ada job yang menunggu persetujuan."
                        : "Tidak ada riwayat job yang cocok dengan filter."}
                    </TableCell>
                  </TableRow>
                ) : (
                  displayedJobs.map((job) => {
                    const ep = job.endpoint ?? endpointMap.get(job.endpoint_id);
                    const finding = job.finding ?? findingMap.get(job.finding_id);
                    return (
                      <TableRow key={job.id}>
                        <TableCell className="font-mono text-xs font-semibold">
                          {job.id.slice(0, 8)}
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-1.5">
                            <span className="font-medium text-slate-900">
                              {ep?.hostname ?? job.endpoint_id.slice(0, 8)}
                            </span>
                            <Badge variant="outline" className={osBadgeClass(job.target_os)}>
                              {job.target_os}
                            </Badge>
                          </div>
                        </TableCell>
                        <TableCell className="max-w-xs">
                          <div className="font-mono text-xs font-semibold">
                            {finding?.external_id ?? job.finding_id.slice(0, 8)}
                          </div>
                          {finding?.title && (
                            <p className="line-clamp-1 text-xs text-muted-foreground">
                              {finding.title}
                            </p>
                          )}
                        </TableCell>
                        <TableCell className="text-xs font-mono">
                          {formatScriptLanguage(job.script_language)}
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className={riskBadgeClass(job.risk_level)}>
                            {job.risk_level}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          {job.has_pre_backup ? (
                            <Badge
                              variant="outline"
                              className="border-emerald-300 bg-emerald-50 text-emerald-800"
                            >
                              <CheckCircle2 className="mr-1 h-3 w-3" />
                              Verified
                            </Badge>
                          ) : (
                            <Badge variant="destructive">
                              <Lock className="mr-1 h-3 w-3" />
                              Missing
                            </Badge>
                          )}
                        </TableCell>
                        <TableCell>
                          <div className="flex flex-wrap gap-1">
                            {job.requires_reboot && (
                              <Badge
                                variant="outline"
                                className="border-amber-300 bg-amber-50 text-amber-800"
                              >
                                Reboot
                              </Badge>
                            )}
                            {job.requires_manual_mdm && (
                              <Badge variant="destructive">SIP/MDM</Badge>
                            )}
                            {!job.requires_reboot && !job.requires_manual_mdm && (
                              <span className="text-xs text-muted-foreground">—</span>
                            )}
                          </div>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className={statusBadgeClass(job.status)}>
                            {job.status}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-right">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => handleOpenReview(job)}
                          >
                            <Eye className="h-3.5 w-3.5" />
                            Review Script
                          </Button>
                        </TableCell>
                      </TableRow>
                    );
                  })
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </main>

      <RemediationReviewDialog
        open={reviewOpen}
        jobId={selectedJobId}
        userRole={user?.role ?? "OPERATOR"}
        endpointMap={endpointMap}
        findingMap={findingMap}
        initialEndpoint={selectedJob?.endpoint}
        initialFinding={selectedJob?.finding}
        onOpenChange={(isOpen) => {
          setReviewOpen(isOpen);
          if (!isOpen && queryJobId) {
            router.replace("/approvals");
          }
        }}
        onActionCompleted={handleActionCompleted}
      />
    </div>
  );
}

export default function ApprovalsPage() {
  return (
    <Suspense
      fallback={
        <div className="flex min-h-screen items-center justify-center bg-background">
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <RefreshCw className="h-4 w-4 animate-spin" />
            Memuat Approval Queue...
          </div>
        </div>
      }
    >
      <ApprovalsPageContent />
    </Suspense>
  );
}
