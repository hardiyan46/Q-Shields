"use client";

import { useEffect, useState } from "react";
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  Copy,
  HardDrive,
  Lock,
  Play,
  RefreshCw,
  RotateCcw,
  ShieldAlert,
  XCircle,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import {
  ApiError,
  approveRemediationJob,
  executeRemediationJob,
  fetchRemediationDetail,
  fetchRemediationLogs,
  rejectRemediationJob,
  rollbackRemediationJob,
} from "@/lib/api";
import type {
  EndpointBrief,
  EndpointItem,
  ExecutionLogItem,
  FindingBrief,
  FindingItem,
  JobStatus,
  OSFamily,
  RemediationJob,
  UserRole,
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

interface RemediationReviewDialogProps {
  open: boolean;
  jobId: string | null;
  userRole: UserRole;
  endpointMap: Map<string, EndpointItem>;
  findingMap: Map<string, FindingItem>;
  initialEndpoint?: EndpointBrief | null;
  initialFinding?: FindingBrief | null;
  onOpenChange: (open: boolean) => void;
  onActionCompleted: (message: string) => Promise<void> | void;
}

export function RemediationReviewDialog({
  open,
  jobId,
  userRole,
  endpointMap,
  findingMap,
  initialEndpoint,
  initialFinding,
  onOpenChange,
  onActionCompleted,
}: RemediationReviewDialogProps) {
  const [job, setJob] = useState<RemediationJob | null>(null);
  const [logs, setLogs] = useState<ExecutionLogItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [actionBusy, setActionBusy] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const [copiedKey, setCopiedKey] = useState<"remediation" | "rollback" | null>(null);

  // Reject form & confirmation dialogs
  const [showRejectBox, setShowRejectBox] = useState(false);
  const [rejectionReason, setRejectionReason] = useState("");
  const [confirmAction, setConfirmAction] = useState<
    "approve_execute" | "execute" | "rollback" | null
  >(null);

  useEffect(() => {
    if (!open || !jobId) {
      return;
    }

    let cancelled = false;
    setLoading(true);
    setErrorMsg(null);
    setShowRejectBox(false);
    setRejectionReason("");
    setConfirmAction(null);

    async function loadDetails(targetJobId: string) {
      try {
        const [jobData, logData] = await Promise.all([
          fetchRemediationDetail(targetJobId),
          fetchRemediationLogs(targetJobId),
        ]);
        if (cancelled) return;
        setJob(jobData);
        setLogs(logData);
      } catch (err) {
        if (!cancelled) {
          setErrorMsg(
            err instanceof ApiError ? err.message : "Gagal memuat detail skrip job."
          );
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    void loadDetails(jobId);
    return () => {
      cancelled = true;
    };
  }, [open, jobId]);

  async function handleCopy(kind: "remediation" | "rollback", text: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(kind);
      setTimeout(() => setCopiedKey(null), 1800);
    } catch {
      setErrorMsg("Clipboard tidak tersedia pada browser ini.");
    }
  }

  async function handleApproveAndExecute() {
    if (!job) return;
    setActionBusy(true);
    setErrorMsg(null);
    try {
      const updated = await approveRemediationJob(job.id, {
        execute_immediately: true,
      });
      setJob(updated);
      setLogs(updated.execution_logs);
      setConfirmAction(null);
      await onActionCompleted(
        `Job ${job.id.slice(0, 8)} disetujui dan dieksekusi (status: ${updated.status}).`
      );
    } catch (err) {
      setErrorMsg(
        err instanceof ApiError ? err.message : "Gagal menyetujui/mengeksekusi job."
      );
      setConfirmAction(null);
    } finally {
      setActionBusy(false);
    }
  }

  async function handleExecuteOnly() {
    if (!job) return;
    setActionBusy(true);
    setErrorMsg(null);
    try {
      const updated = await executeRemediationJob(job.id);
      setJob(updated);
      setLogs(updated.execution_logs);
      setConfirmAction(null);
      await onActionCompleted(
        `Job ${job.id.slice(0, 8)} selesai dieksekusi (status: ${updated.status}).`
      );
    } catch (err) {
      setErrorMsg(err instanceof ApiError ? err.message : "Gagal mengeksekusi job.");
      setConfirmAction(null);
    } finally {
      setActionBusy(false);
    }
  }

  async function handleRollback() {
    if (!job) return;
    setActionBusy(true);
    setErrorMsg(null);
    try {
      const updated = await rollbackRemediationJob(job.id);
      setJob(updated);
      setLogs(updated.execution_logs);
      setConfirmAction(null);
      await onActionCompleted(
        `Rollback job ${job.id.slice(0, 8)} berhasil dijalankan (status: ${updated.status}).`
      );
    } catch (err) {
      setErrorMsg(err instanceof ApiError ? err.message : "Gagal menjalankan rollback.");
      setConfirmAction(null);
    } finally {
      setActionBusy(false);
    }
  }

  async function handleRejectSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!job) return;
    const trimmed = rejectionReason.trim();
    if (trimmed.length < 5) {
      setErrorMsg("Alasan penolakan wajib diisi minimal 5 karakter.");
      return;
    }

    setActionBusy(true);
    setErrorMsg(null);
    try {
      const updated = await rejectRemediationJob(job.id, {
        rejection_reason: trimmed,
      });
      setJob(updated);
      setShowRejectBox(false);
      await onActionCompleted(
        `Job ${job.id.slice(0, 8)} ditolak (status: ${updated.status}).`
      );
    } catch (err) {
      setErrorMsg(err instanceof ApiError ? err.message : "Gagal menolak job.");
    } finally {
      setActionBusy(false);
    }
  }

  const resolvedEndpoint =
    initialEndpoint ?? (job ? endpointMap.get(job.endpoint_id) : undefined);
  const resolvedFinding =
    initialFinding ?? (job ? findingMap.get(job.finding_id) : undefined);

  const canApproveOrExecute = userRole === "APPROVER" || userRole === "ADMIN";
  const isApproveAllowed =
    canApproveOrExecute &&
    job?.status === "PENDING_APPROVAL" &&
    job.has_pre_backup === true &&
    job.requires_manual_mdm === false;

  const isRollbackAllowed =
    canApproveOrExecute &&
    (job?.status === "SUCCESS" || job?.status === "FAILED") &&
    job.has_pre_backup === true;

  return (
    <>
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="max-w-4xl">
          <DialogHeader>
            <DialogTitle className="flex flex-wrap items-center gap-2">
              <span>Review Skrip Remediasi</span>
              {job && (
                <>
                  <Badge variant="outline" className={osBadgeClass(job.target_os)}>
                    {job.target_os}
                  </Badge>
                  <Badge variant="outline" className={statusBadgeClass(job.status)}>
                    {job.status}
                  </Badge>
                  <Badge variant="secondary">{job.script_language}</Badge>
                </>
              )}
            </DialogTitle>
            <DialogDescription>
              {job
                ? `Job ${job.id} • Target: ${
                    resolvedEndpoint?.hostname ?? job.endpoint_id
                  } • Temuan: ${resolvedFinding?.external_id ?? job.finding_id}`
                : "Memuat detail remediation job..."}
            </DialogDescription>
          </DialogHeader>

          {loading ? (
            <div className="flex items-center justify-center py-12 text-sm text-muted-foreground">
              <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
              Memuat skrip dan riwayat eksekusi...
            </div>
          ) : job ? (
            <div className="space-y-4">
              {errorMsg && (
                <div
                  role="alert"
                  className="flex items-start gap-2 rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-800"
                >
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                  <span>{errorMsg}</span>
                </div>
              )}

              {/* Safety & Pre-Change Backup Banner */}
              <div className="space-y-2 rounded-lg border bg-slate-50 p-3.5 text-sm">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2 font-semibold text-slate-800">
                    <HardDrive className="h-4 w-4 text-blue-600" />
                    Pre-Change Backup &amp; Safety Guard
                  </div>
                  <div className="flex flex-wrap items-center gap-1.5">
                    {job.has_pre_backup ? (
                      <Badge
                        variant="outline"
                        className="border-emerald-300 bg-emerald-50 text-emerald-800"
                      >
                        <CheckCircle2 className="mr-1 h-3 w-3" />
                        Pre-Backup Verified
                      </Badge>
                    ) : (
                      <Badge variant="destructive">
                        <Lock className="mr-1 h-3 w-3" />
                        No Verified Pre-Backup
                      </Badge>
                    )}
                    {job.requires_reboot && (
                      <Badge variant="outline" className="border-amber-300 bg-amber-50 text-amber-800">
                        Requires Reboot
                      </Badge>
                    )}
                    {job.requires_manual_mdm && (
                      <Badge variant="destructive">Requires Manual / MDM</Badge>
                    )}
                  </div>
                </div>

                <div className="text-xs text-slate-700">
                  <span className="font-medium">Backup Path:</span>{" "}
                  <code className="rounded bg-white px-1.5 py-0.5 border">{job.backup_path}</code>
                </div>
                <div className="flex flex-wrap items-center gap-1.5 text-xs text-slate-700">
                  <span className="font-medium">Backup Targets:</span>
                  {job.backup_targets.length === 0 ? (
                    <span className="text-muted-foreground">(kosong)</span>
                  ) : (
                    job.backup_targets.map((target) => (
                      <code key={target} className="rounded border bg-white px-1.5 py-0.5">
                        {target}
                      </code>
                    ))
                  )}
                </div>

                {!job.has_pre_backup && !job.requires_manual_mdm && (
                  <div className="flex items-start gap-2 rounded-md border border-red-300 bg-red-50 p-2.5 text-xs text-red-800">
                    <Lock className="mt-0.5 h-4 w-4 shrink-0" />
                    <span>
                      <strong>Approval Terkunci:</strong> Skrip ini belum memiliki prosedur{" "}
                      <em>pre-change backup</em> yang tervalidasi (<code>has_pre_backup=false</code>).
                      Tombol Approve dinonaktifkan demi keamanan sistem.
                    </span>
                  </div>
                )}

                {job.requires_manual_mdm && (
                  <div className="flex items-start gap-2 rounded-md border border-amber-300 bg-amber-50 p-2.5 text-xs text-amber-900">
                    <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
                    <span>
                      <strong>Diblokir Kebijakan OS / MDM:</strong> Temuan pada <code>macos</code>{" "}
                      ini dilindungi Apple SIP, TCC, atau profil MDM sehingga remediasi otomatis
                      diblokir. Tombol Approve terkunci — terapkan secara manual atau melalui MDM.
                    </span>
                  </div>
                )}

                {job.status === "REJECTED" && job.rejection_reason && (
                  <div className="rounded-md border border-slate-300 bg-white p-2.5 text-xs text-slate-700">
                    <strong>Alasan Penolakan:</strong> {job.rejection_reason}
                  </div>
                )}
              </div>

              {/* 3 Tabs: Remediation Script, Rollback Script, Execution Logs */}
              <Tabs defaultValue="remediation">
                <TabsList className="grid w-full grid-cols-3">
                  <TabsTrigger value="remediation">Remediation Script</TabsTrigger>
                  <TabsTrigger value="rollback">Rollback Script</TabsTrigger>
                  <TabsTrigger value="logs">
                    Execution Logs ({logs.length})
                  </TabsTrigger>
                </TabsList>

                <TabsContent value="remediation" className="space-y-3">
                  <div className="rounded-md border bg-blue-50/70 p-3 text-xs text-slate-800">
                    <strong className="block mb-1 text-blue-900">Penjelasan AI:</strong>
                    {job.ai_explanation}
                  </div>

                  <div className="relative">
                    <div className="mb-1.5 flex items-center justify-between">
                      <span className="text-xs font-medium text-muted-foreground">
                        Dialect: {job.script_language} ({job.target_os})
                      </span>
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        onClick={() => void handleCopy("remediation", job.remediation_script)}
                      >
                        {copiedKey === "remediation" ? (
                          <>
                            <Check className="h-3.5 w-3.5 text-emerald-600" />
                            Copied
                          </>
                        ) : (
                          <>
                            <Copy className="h-3.5 w-3.5" />
                            Copy
                          </>
                        )}
                      </Button>
                    </div>
                    <pre className="max-h-72 overflow-auto rounded-lg border bg-slate-950 p-4 font-mono text-xs text-slate-100">
                      <code>{job.remediation_script}</code>
                    </pre>
                  </div>
                </TabsContent>

                <TabsContent value="rollback" className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-muted-foreground">
                      Merujuk ke: <code>{job.backup_path}</code>
                    </span>
                    <Button
                      type="button"
                      size="sm"
                      variant="outline"
                      onClick={() => void handleCopy("rollback", job.rollback_script)}
                    >
                      {copiedKey === "rollback" ? (
                        <>
                          <Check className="h-3.5 w-3.5 text-emerald-600" />
                          Copied
                        </>
                      ) : (
                        <>
                          <Copy className="h-3.5 w-3.5" />
                          Copy
                        </>
                      )}
                    </Button>
                  </div>
                  <pre className="max-h-72 overflow-auto rounded-lg border bg-slate-950 p-4 font-mono text-xs text-slate-100">
                    <code>{job.rollback_script}</code>
                  </pre>
                </TabsContent>

                <TabsContent value="logs" className="space-y-3">
                  {logs.length === 0 ? (
                    <div className="rounded-md border border-dashed py-8 text-center text-xs text-muted-foreground">
                      Belum ada riwayat eksekusi atau rollback untuk job ini.
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {logs.map((entry) => (
                        <div key={entry.id} className="rounded-lg border bg-white p-3 text-xs space-y-2">
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <div className="flex items-center gap-2">
                              <Badge variant="secondary">{entry.action_type}</Badge>
                              <Badge
                                variant="outline"
                                className={
                                  entry.exit_code === 0
                                    ? "border-emerald-300 bg-emerald-50 text-emerald-800"
                                    : "border-red-300 bg-red-50 text-red-800"
                                }
                              >
                                exit_code: {entry.exit_code ?? "—"}
                              </Badge>
                            </div>
                            <div className="text-muted-foreground">
                              {new Date(entry.executed_at).toLocaleString()} • Triggered by{" "}
                              <code>{entry.triggered_by_id.slice(0, 8)}</code>
                            </div>
                          </div>
                          {entry.stdout && (
                            <pre className="max-h-40 overflow-auto rounded bg-slate-950 p-2.5 font-mono text-[11px] text-emerald-300">
                              {entry.stdout}
                            </pre>
                          )}
                          {entry.stderr && (
                            <pre className="max-h-32 overflow-auto rounded bg-red-950 p-2.5 font-mono text-[11px] text-red-200">
                              {entry.stderr}
                            </pre>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </TabsContent>
              </Tabs>

              {/* Rejection Reason Inline Form */}
              {showRejectBox && canApproveOrExecute && job.status === "PENDING_APPROVAL" && (
                <form
                  onSubmit={handleRejectSubmit}
                  className="space-y-2 rounded-lg border border-red-200 bg-red-50/50 p-3"
                >
                  <Label htmlFor="rejection-reason">
                    Alasan Penolakan (wajib, minimal 5 karakter)
                  </Label>
                  <Textarea
                    id="rejection-reason"
                    placeholder="Jelaskan alasan skrip ditolak agar operator dapat memperbaikinya..."
                    value={rejectionReason}
                    onChange={(e) => setRejectionReason(e.target.value)}
                    disabled={actionBusy}
                    required
                  />
                  <div className="flex justify-end gap-2">
                    <Button
                      type="button"
                      size="sm"
                      variant="outline"
                      onClick={() => setShowRejectBox(false)}
                      disabled={actionBusy}
                    >
                      Batal
                    </Button>
                    <Button type="submit" size="sm" variant="destructive" disabled={actionBusy}>
                      {actionBusy ? "Menolak..." : "Konfirmasi Reject"}
                    </Button>
                  </div>
                </form>
              )}

              {/* RBAC Action Footer */}
              <div className="flex flex-wrap items-center justify-between gap-3 border-t pt-4">
                {!canApproveOrExecute ? (
                  <p className="flex items-center gap-1.5 text-xs font-medium text-amber-800">
                    <Lock className="h-3.5 w-3.5" />
                    Membutuhkan role <strong>APPROVER</strong> atau <strong>ADMIN</strong> untuk
                    menyetujui, mengeksekusi, atau melakukan rollback.
                  </p>
                ) : (
                  <span className="text-xs text-muted-foreground">
                    Role aktif: <strong>{userRole}</strong>
                  </span>
                )}

                <div className="flex flex-wrap items-center gap-2">
                  {job.status === "PENDING_APPROVAL" && (
                    <>
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        disabled={!canApproveOrExecute || actionBusy}
                        onClick={() => setShowRejectBox((prev) => !prev)}
                      >
                        <XCircle className="h-4 w-4 text-red-600" />
                        Reject
                      </Button>

                      <Button
                        type="button"
                        size="sm"
                        disabled={!isApproveAllowed || actionBusy}
                        onClick={() => setConfirmAction("approve_execute")}
                      >
                        <CheckCircle2 className="h-4 w-4" />
                        Approve &amp; Execute
                      </Button>
                    </>
                  )}

                  {job.status === "APPROVED" && (
                    <Button
                      type="button"
                      size="sm"
                      disabled={!canApproveOrExecute || !job.has_pre_backup || actionBusy}
                      onClick={() => setConfirmAction("execute")}
                    >
                      <Play className="h-4 w-4" />
                      Execute Now
                    </Button>
                  )}

                  {(job.status === "SUCCESS" || job.status === "FAILED") && (
                    <Button
                      type="button"
                      size="sm"
                      variant="destructive"
                      disabled={!isRollbackAllowed || actionBusy}
                      onClick={() => setConfirmAction("rollback")}
                    >
                      <RotateCcw className="h-4 w-4" />
                      Rollback Now
                    </Button>
                  )}
                </div>
              </div>
            </div>
          ) : null}
        </DialogContent>
      </Dialog>

      {/* Action Confirmation Modal */}
      <Dialog
        open={confirmAction !== null}
        onOpenChange={(isOpen) => {
          if (!isOpen && !actionBusy) setConfirmAction(null);
        }}
      >
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-amber-600" />
              {confirmAction === "approve_execute" && "Konfirmasi Approve & Execute"}
              {confirmAction === "execute" && "Konfirmasi Eksekusi Job"}
              {confirmAction === "rollback" && "Peringatan: Konfirmasi Rollback"}
            </DialogTitle>
            <DialogDescription>
              {confirmAction === "approve_execute" &&
                `Skrip akan disetujui dan langsung dijalankan pada endpoint target (${
                  resolvedEndpoint?.hostname ?? job?.target_os ?? ""
                }) setelah pre-change backup ke ${job?.backup_path ?? ""}.`}
              {confirmAction === "execute" &&
                "Skrip yang telah disetujui akan segera dijalankan pada endpoint target."}
              {confirmAction === "rollback" &&
                `Sistem akan menjalankan rollback_script untuk memulihkan endpoint ke kondisi semula menggunakan backup di ${
                  job?.backup_path ?? ""
                }. Status finding akan kembali menjadi OPEN.`}
            </DialogDescription>
          </DialogHeader>

          <div className="flex justify-end gap-2 pt-2">
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={actionBusy}
              onClick={() => setConfirmAction(null)}
            >
              Batal
            </Button>
            <Button
              type="button"
              size="sm"
              variant={confirmAction === "rollback" ? "destructive" : "default"}
              disabled={actionBusy}
              onClick={() => {
                if (confirmAction === "approve_execute") void handleApproveAndExecute();
                if (confirmAction === "execute") void handleExecuteOnly();
                if (confirmAction === "rollback") void handleRollback();
              }}
            >
              {actionBusy ? "Memproses..." : "Ya, Lanjutkan"}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}
