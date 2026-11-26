"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Cpu,
  Laptop,
  RefreshCw,
  Search,
  Server,
  ShieldAlert,
  Sparkles,
  Terminal,
} from "lucide-react";

import { AppNavbar } from "@/components/app-navbar";
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
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
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
  fetchCurrentUser,
  fetchDashboardSummary,
  fetchEndpointDetail,
  fetchEndpoints,
  fetchFindings,
  fetchRemediations,
  generateRemediation,
  syncWazuhData,
} from "@/lib/api";
import {
  getAccessToken,
  getStoredUser,
  setAuthSession,
} from "@/lib/auth";
import type {
  DashboardSummary,
  EndpointDetail,
  EndpointItem,
  EndpointStatus,
  FindingItem,
  FindingSource,
  OSFamily,
  RemediationJob,
  SeverityLevel,
  SyncResult,
  UserProfile,
} from "@/types/qshields";

function osBadgeClass(osFamily: OSFamily): string {
  if (osFamily === "linux") return "border-amber-300 bg-amber-50 text-amber-800";
  if (osFamily === "windows") return "border-sky-300 bg-sky-50 text-sky-800";
  return "border-slate-300 bg-slate-100 text-slate-800";
}

function severityBadgeClass(severity: SeverityLevel): string {
  switch (severity) {
    case "CRITICAL":
      return "border-red-300 bg-red-100 text-red-800";
    case "HIGH":
      return "border-orange-300 bg-orange-100 text-orange-800";
    case "MEDIUM":
      return "border-yellow-300 bg-yellow-100 text-yellow-800";
    case "LOW":
      return "border-blue-300 bg-blue-100 text-blue-800";
  }
}

function endpointStatusClass(status: EndpointStatus): string {
  if (status === "ACTIVE") return "border-emerald-300 bg-emerald-50 text-emerald-700";
  if (status === "PENDING") return "border-amber-300 bg-amber-50 text-amber-700";
  return "border-red-300 bg-red-50 text-red-700";
}

export default function DashboardPage() {
  const router = useRouter();
  const [authChecked, setAuthChecked] = useState(false);
  const [user, setUser] = useState<UserProfile | null>(null);
  const [pendingCount, setPendingCount] = useState(0);

  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [allEndpoints, setAllEndpoints] = useState<EndpointItem[]>([]);
  const [endpoints, setEndpoints] = useState<EndpointItem[]>([]);
  const [findings, setFindings] = useState<FindingItem[]>([]);

  // Endpoint filters
  const [endpointOsFilter, setEndpointOsFilter] = useState<"ALL" | OSFamily>("ALL");
  const [endpointStatusFilter, setEndpointStatusFilter] = useState<"ALL" | EndpointStatus>("ALL");
  const [endpointSearch, setEndpointSearch] = useState("");

  // Finding filters
  const [findingSourceTab, setFindingSourceTab] = useState<"ALL" | FindingSource>("ALL");
  const [findingSeverityFilter, setFindingSeverityFilter] = useState<"ALL" | SeverityLevel>("ALL");
  const [findingOsFilter, setFindingOsFilter] = useState<"ALL" | OSFamily>("ALL");

  // UI states
  const [isLoadingData, setIsLoadingData] = useState(true);
  const [isSyncing, setIsSyncing] = useState(false);
  const [generatingFindingId, setGeneratingFindingId] = useState<string | null>(null);
  const [bannerError, setBannerError] = useState<string | null>(null);
  const [syncNotice, setSyncNotice] = useState<SyncResult | null>(null);
  const [generatedJobNotice, setGeneratedJobNotice] = useState<RemediationJob | null>(null);

  // Endpoint Detail Modal
  const [detailOpen, setDetailOpen] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);
  const [selectedEndpoint, setSelectedEndpoint] = useState<EndpointDetail | null>(null);

  const endpointMap = useMemo(() => {
    const map = new Map<string, EndpointItem>();
    for (const ep of allEndpoints) {
      map.set(ep.id, ep);
    }
    return map;
  }, [allEndpoints]);

  const loadDashboardOverview = useCallback(async () => {
    const [summaryData, allEpData, pendingJobs] = await Promise.all([
      fetchDashboardSummary(),
      fetchEndpoints({ limit: 200 }),
      fetchRemediations({ status: "PENDING_APPROVAL", limit: 200 }),
    ]);
    setSummary(summaryData);
    setAllEndpoints(allEpData);
    setPendingCount(pendingJobs.length);
  }, []);

  const loadFilteredEndpoints = useCallback(async () => {
    const data = await fetchEndpoints({
      os_family: endpointOsFilter === "ALL" ? undefined : endpointOsFilter,
      status: endpointStatusFilter === "ALL" ? undefined : endpointStatusFilter,
      search: endpointSearch.trim() || undefined,
      limit: 100,
    });
    setEndpoints(data);
  }, [endpointOsFilter, endpointStatusFilter, endpointSearch]);

  const loadFilteredFindings = useCallback(async () => {
    const data = await fetchFindings({
      source_type: findingSourceTab === "ALL" ? undefined : findingSourceTab,
      severity: findingSeverityFilter === "ALL" ? undefined : findingSeverityFilter,
      os_family: findingOsFilter === "ALL" ? undefined : findingOsFilter,
      limit: 100,
    });
    setFindings(data);
  }, [findingSourceTab, findingSeverityFilter, findingOsFilter]);

  // Initial auth guard & data bootstrap
  useEffect(() => {
    const token = getAccessToken();
    if (!token) {
      router.replace("/login");
      return;
    }

    const cachedUser = getStoredUser();
    if (cachedUser) {
      setUser(cachedUser);
    }

    let cancelled = false;
    async function bootstrap() {
      try {
        const me = await fetchCurrentUser();
        if (cancelled) return;
        setUser(me);
        if (token) {
          setAuthSession(token, me);
        }
        setAuthChecked(true);
        await Promise.all([
          loadDashboardOverview(),
          loadFilteredEndpoints(),
          loadFilteredFindings(),
        ]);
      } catch (err) {
        if (!cancelled && err instanceof ApiError && err.status !== 401) {
          setBannerError(err.message);
        }
      } finally {
        if (!cancelled) {
          setIsLoadingData(false);
        }
      }
    }

    void bootstrap();
    return () => {
      cancelled = true;
    };
  }, [router, loadDashboardOverview, loadFilteredEndpoints, loadFilteredFindings]);

  // Re-fetch endpoints when filters change
  useEffect(() => {
    if (!authChecked) return;
    void loadFilteredEndpoints().catch((err: unknown) => {
      if (err instanceof ApiError) setBannerError(err.message);
    });
  }, [authChecked, loadFilteredEndpoints]);

  // Re-fetch findings when filters change
  useEffect(() => {
    if (!authChecked) return;
    void loadFilteredFindings().catch((err: unknown) => {
      if (err instanceof ApiError) setBannerError(err.message);
    });
  }, [authChecked, loadFilteredFindings]);

  async function handleSyncWazuh() {
    setBannerError(null);
    setSyncNotice(null);
    setIsSyncing(true);
    try {
      const res = await syncWazuhData();
      setSyncNotice(res);
      await Promise.all([
        loadDashboardOverview(),
        loadFilteredEndpoints(),
        loadFilteredFindings(),
      ]);
    } catch (err) {
      setBannerError(
        err instanceof ApiError ? err.message : "Gagal melakukan sinkronisasi Wazuh."
      );
    } finally {
      setIsSyncing(false);
    }
  }

  async function handleOpenEndpointDetail(endpointId: string) {
    setDetailOpen(true);
    setDetailLoading(true);
    setSelectedEndpoint(null);
    try {
      const detail = await fetchEndpointDetail(endpointId);
      setSelectedEndpoint(detail);
    } catch (err) {
      setBannerError(
        err instanceof ApiError ? err.message : "Gagal memuat detail endpoint."
      );
      setDetailOpen(false);
    } finally {
      setDetailLoading(false);
    }
  }

  async function handleGenerateRemediation(findingId: string) {
    setBannerError(null);
    setGeneratedJobNotice(null);
    setGeneratingFindingId(findingId);
    try {
      const job = await generateRemediation(findingId);
      setGeneratedJobNotice(job);
      await Promise.all([loadDashboardOverview(), loadFilteredFindings()]);
    } catch (err) {
      setBannerError(
        err instanceof ApiError
          ? err.message
          : "Gagal menjalankan AI Remediation Generator."
      );
    } finally {
      setGeneratingFindingId(null);
    }
  }

  if (!authChecked && isLoadingData) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <RefreshCw className="h-4 w-4 animate-spin" />
          Memuat sesi Q-Shields...
        </div>
      </div>
    );
  }

  const canGenerateRemediation = user?.role === "OPERATOR" || user?.role === "ADMIN";

  return (
    <div className="min-h-screen bg-slate-50">
      <AppNavbar
        user={user}
        pendingCount={pendingCount}
        rightSlot={
          <Button size="sm" onClick={handleSyncWazuh} disabled={isSyncing}>
            <RefreshCw className={`h-4 w-4 ${isSyncing ? "animate-spin" : ""}`} />
            {isSyncing ? "Syncing..." : "Sync Wazuh Now"}
          </Button>
        }
      />

      <main className="mx-auto max-w-7xl space-y-6 px-4 py-6 sm:px-6">
        {/* Notifications / Errors */}
        {bannerError && (
          <div
            role="alert"
            className="flex items-start justify-between gap-3 rounded-lg border border-red-200 bg-red-50 p-3.5 text-sm text-red-800"
          >
            <div className="flex items-start gap-2">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
              <span>{bannerError}</span>
            </div>
            <button
              type="button"
              onClick={() => setBannerError(null)}
              className="text-xs font-semibold underline"
            >
              Tutup
            </button>
          </div>
        )}

        {syncNotice && (
          <div className="flex items-center justify-between gap-3 rounded-lg border border-emerald-200 bg-emerald-50 p-3.5 text-sm text-emerald-800">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 shrink-0" />
              <span>
                Sinkronisasi Wazuh ({syncNotice.mode}) selesai:{" "}
                <strong>{syncNotice.endpoints_synced}</strong> endpoint &amp;{" "}
                <strong>{syncNotice.findings_synced}</strong> temuan disinkronkan.
              </span>
            </div>
            <button
              type="button"
              onClick={() => setSyncNotice(null)}
              className="text-xs font-semibold underline"
            >
              Tutup
            </button>
          </div>
        )}

        {generatedJobNotice && (
          <div className="flex flex-col gap-2 rounded-lg border border-blue-200 bg-blue-50 p-4 text-sm text-blue-900">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2 font-semibold">
                <Sparkles className="h-4 w-4 text-blue-600" />
                Draft Remediasi AI Berhasil Dibuat ({generatedJobNotice.status})
              </div>
              <div className="flex items-center gap-3">
                <Button size="sm" asChild>
                  <Link href={`/approvals?jobId=${generatedJobNotice.id}`}>
                    Review di Approval Queue
                    <ArrowRight className="h-3.5 w-3.5" />
                  </Link>
                </Button>
                <button
                  type="button"
                  onClick={() => setGeneratedJobNotice(null)}
                  className="text-xs font-semibold underline"
                >
                  Tutup
                </button>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <span>Job ID: <code>{generatedJobNotice.id}</code></span>
              <Badge variant="outline" className={osBadgeClass(generatedJobNotice.target_os)}>
                {generatedJobNotice.target_os}
              </Badge>
              <Badge variant="outline">
                has_pre_backup: {String(generatedJobNotice.has_pre_backup)}
              </Badge>
              {generatedJobNotice.requires_manual_mdm && (
                <Badge variant="destructive">requires_manual_mdm: true (SIP/MDM)</Badge>
              )}
            </div>
            <p className="text-xs text-blue-800">
              Backup Path: <code>{generatedJobNotice.backup_path}</code> —{" "}
              {generatedJobNotice.ai_explanation}
            </p>
          </div>
        )}

        {/* Summary Cards */}
        <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Card>
            <CardHeader className="pb-2">
              <CardDescription className="flex items-center justify-between">
                <span>Total Endpoints</span>
                <Server className="h-4 w-4 text-muted-foreground" />
              </CardDescription>
              <CardTitle className="text-2xl">{summary?.total_endpoints ?? 0}</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-wrap gap-1.5">
              <Badge variant="outline" className={osBadgeClass("linux")}>
                linux: {summary?.endpoints_by_os?.linux ?? 0}
              </Badge>
              <Badge variant="outline" className={osBadgeClass("windows")}>
                windows: {summary?.endpoints_by_os?.windows ?? 0}
              </Badge>
              <Badge variant="outline" className={osBadgeClass("macos")}>
                macos: {summary?.endpoints_by_os?.macos ?? 0}
              </Badge>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardDescription className="flex items-center justify-between">
                <span>Open Findings</span>
                <ShieldAlert className="h-4 w-4 text-muted-foreground" />
              </CardDescription>
              <CardTitle className="text-2xl">{summary?.open_findings_total ?? 0}</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-wrap gap-1.5">
              <Badge variant="outline" className={severityBadgeClass("CRITICAL")}>
                CRIT: {summary?.open_findings_by_severity?.CRITICAL ?? 0}
              </Badge>
              <Badge variant="outline" className={severityBadgeClass("HIGH")}>
                HIGH: {summary?.open_findings_by_severity?.HIGH ?? 0}
              </Badge>
              <Badge variant="outline" className={severityBadgeClass("MEDIUM")}>
                MED: {summary?.open_findings_by_severity?.MEDIUM ?? 0}
              </Badge>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardDescription className="flex items-center justify-between">
                <span>Critical &amp; High Open</span>
                <AlertTriangle className="h-4 w-4 text-red-500" />
              </CardDescription>
              <CardTitle className="text-2xl text-red-600">
                {(summary?.open_findings_by_severity?.CRITICAL ?? 0) +
                  (summary?.open_findings_by_severity?.HIGH ?? 0)}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-xs text-muted-foreground">
                Prioritas remediasi CVE &amp; CIS Benchmark tertinggi
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardDescription className="flex items-center justify-between">
                <span>Avg Compliance Score</span>
                <Cpu className="h-4 w-4 text-muted-foreground" />
              </CardDescription>
              <CardTitle className="text-2xl">
                {summary?.average_compliance_score !== null &&
                summary?.average_compliance_score !== undefined
                  ? `${summary.average_compliance_score}%`
                  : "—"}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-xs text-muted-foreground">
                Rata-rata skor kepatuhan SCA / CIS Benchmark
              </p>
            </CardContent>
          </Card>
        </section>

        {/* Endpoints Table */}
        <Card>
          <CardHeader className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Laptop className="h-5 w-5 text-blue-600" />
                Endpoints Inventory
              </CardTitle>
              <CardDescription>
                Klik baris endpoint untuk melihat detail sistem operasi dan daftar temuannya.
              </CardDescription>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <div className="relative w-56">
                <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Cari hostname / IP..."
                  value={endpointSearch}
                  onChange={(e) => setEndpointSearch(e.target.value)}
                  className="pl-8"
                />
              </div>

              <Select
                value={endpointOsFilter}
                onValueChange={(v) => setEndpointOsFilter(v as "ALL" | OSFamily)}
              >
                <SelectTrigger className="w-36">
                  <SelectValue placeholder="OS Family" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ALL">Semua OS</SelectItem>
                  <SelectItem value="linux">linux</SelectItem>
                  <SelectItem value="windows">windows</SelectItem>
                  <SelectItem value="macos">macos</SelectItem>
                </SelectContent>
              </Select>

              <Select
                value={endpointStatusFilter}
                onValueChange={(v) => setEndpointStatusFilter(v as "ALL" | EndpointStatus)}
              >
                <SelectTrigger className="w-40">
                  <SelectValue placeholder="Status" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ALL">Semua Status</SelectItem>
                  <SelectItem value="ACTIVE">ACTIVE</SelectItem>
                  <SelectItem value="DISCONNECTED">DISCONNECTED</SelectItem>
                  <SelectItem value="PENDING">PENDING</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </CardHeader>

          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Hostname</TableHead>
                  <TableHead>IP Address</TableHead>
                  <TableHead>OS Family</TableHead>
                  <TableHead>OS Version</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Compliance</TableHead>
                  <TableHead className="text-right">Open Findings</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {endpoints.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="py-8 text-center text-muted-foreground">
                      Belum ada data endpoint. Klik <strong>Sync Wazuh Now</strong> untuk memuat data.
                    </TableCell>
                  </TableRow>
                ) : (
                  endpoints.map((ep) => (
                    <TableRow
                      key={ep.id}
                      onClick={() => void handleOpenEndpointDetail(ep.id)}
                      className="cursor-pointer"
                    >
                      <TableCell className="font-medium text-slate-900">
                        <div>{ep.hostname}</div>
                        <div className="text-xs text-muted-foreground">Agent #{ep.wazuh_agent_id}</div>
                      </TableCell>
                      <TableCell className="font-mono text-xs">{ep.ip_address ?? "—"}</TableCell>
                      <TableCell>
                        <Badge variant="outline" className={osBadgeClass(ep.os_family)}>
                          {ep.os_family}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-sm">
                        {ep.os_name} {ep.os_version}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className={endpointStatusClass(ep.status)}>
                          {ep.status}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {ep.compliance_score !== null ? `${ep.compliance_score}%` : "—"}
                      </TableCell>
                      <TableCell className="text-right font-semibold">
                        {ep.open_findings_count}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        {/* Findings Explorer (CVE & SCA_CIS) */}
        <Card>
          <CardHeader className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Terminal className="h-5 w-5 text-blue-600" />
                Temuan CVE &amp; Hardening (CIS Benchmark)
              </CardTitle>
              <CardDescription>
                Filter berdasarkan tipe temuan, severity, dan OS, lalu buat draf remediasi AI.
              </CardDescription>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <Tabs
                value={findingSourceTab}
                onValueChange={(v) => setFindingSourceTab(v as "ALL" | FindingSource)}
              >
                <TabsList>
                  <TabsTrigger value="ALL">ALL</TabsTrigger>
                  <TabsTrigger value="CVE">CVE</TabsTrigger>
                  <TabsTrigger value="SCA_CIS">SCA_CIS</TabsTrigger>
                </TabsList>
              </Tabs>

              <Select
                value={findingSeverityFilter}
                onValueChange={(v) => setFindingSeverityFilter(v as "ALL" | SeverityLevel)}
              >
                <SelectTrigger className="w-36">
                  <SelectValue placeholder="Severity" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ALL">Semua Severity</SelectItem>
                  <SelectItem value="CRITICAL">CRITICAL</SelectItem>
                  <SelectItem value="HIGH">HIGH</SelectItem>
                  <SelectItem value="MEDIUM">MEDIUM</SelectItem>
                  <SelectItem value="LOW">LOW</SelectItem>
                </SelectContent>
              </Select>

              <Select
                value={findingOsFilter}
                onValueChange={(v) => setFindingOsFilter(v as "ALL" | OSFamily)}
              >
                <SelectTrigger className="w-36">
                  <SelectValue placeholder="OS Family" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ALL">Semua OS</SelectItem>
                  <SelectItem value="linux">linux</SelectItem>
                  <SelectItem value="windows">windows</SelectItem>
                  <SelectItem value="macos">macos</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </CardHeader>

          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>External ID</TableHead>
                  <TableHead>Temuan</TableHead>
                  <TableHead>Target Endpoint</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Aksi</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {findings.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="py-8 text-center text-muted-foreground">
                      Tidak ada temuan yang cocok dengan filter saat ini.
                    </TableCell>
                  </TableRow>
                ) : (
                  findings.map((finding) => {
                    const targetEp = endpointMap.get(finding.endpoint_id);
                    const isGenerating = generatingFindingId === finding.id;
                    return (
                      <TableRow key={finding.id}>
                        <TableCell className="font-mono text-xs font-semibold">
                          {finding.external_id}
                        </TableCell>
                        <TableCell className="max-w-md">
                          <div className="font-medium text-slate-900">{finding.title}</div>
                          {finding.remediation_hint && (
                            <p className="mt-0.5 line-clamp-2 text-xs text-muted-foreground">
                              {finding.remediation_hint}
                            </p>
                          )}
                        </TableCell>
                        <TableCell>
                          {targetEp ? (
                            <div className="flex items-center gap-1.5">
                              <span className="text-sm font-medium">{targetEp.hostname}</span>
                              <Badge variant="outline" className={osBadgeClass(targetEp.os_family)}>
                                {targetEp.os_family}
                              </Badge>
                            </div>
                          ) : (
                            <span className="font-mono text-xs text-muted-foreground">
                              {finding.endpoint_id.slice(0, 8)}
                            </span>
                          )}
                        </TableCell>
                        <TableCell>
                          <Badge variant="secondary">{finding.source_type}</Badge>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className={severityBadgeClass(finding.severity)}>
                            {finding.severity}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline">{finding.status}</Badge>
                        </TableCell>
                        <TableCell className="text-right">
                          <Button
                            size="sm"
                            variant="outline"
                            disabled={
                              !canGenerateRemediation ||
                              isGenerating ||
                              finding.status === "RESOLVED"
                            }
                            title={
                              !canGenerateRemediation
                                ? "Hanya OPERATOR atau ADMIN yang dapat membuat draf remediasi"
                                : undefined
                            }
                            onClick={() => void handleGenerateRemediation(finding.id)}
                          >
                            <Sparkles className="h-3.5 w-3.5 text-blue-600" />
                            {isGenerating ? "Generating..." : "Generate Remediation"}
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

      {/* Endpoint Detail Modal */}
      <Dialog open={detailOpen} onOpenChange={setDetailOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              {selectedEndpoint ? (
                <>
                  <span>{selectedEndpoint.hostname}</span>
                  <Badge variant="outline" className={osBadgeClass(selectedEndpoint.os_family)}>
                    {selectedEndpoint.os_family}
                  </Badge>
                </>
              ) : (
                "Detail Endpoint"
              )}
            </DialogTitle>
            <DialogDescription>
              {selectedEndpoint
                ? `${selectedEndpoint.os_name} ${selectedEndpoint.os_version} • IP ${
                    selectedEndpoint.ip_address ?? "—"
                  } • Agent #${selectedEndpoint.wazuh_agent_id}`
                : "Memuat informasi endpoint..."}
            </DialogDescription>
          </DialogHeader>

          {detailLoading ? (
            <div className="flex items-center justify-center py-10 text-sm text-muted-foreground">
              <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
              Mengambil detail temuan endpoint...
            </div>
          ) : selectedEndpoint ? (
            <div className="space-y-4">
              <div className="flex flex-wrap gap-2">
                <Badge variant="outline" className={severityBadgeClass("CRITICAL")}>
                  CRITICAL: {selectedEndpoint.findings_summary.CRITICAL}
                </Badge>
                <Badge variant="outline" className={severityBadgeClass("HIGH")}>
                  HIGH: {selectedEndpoint.findings_summary.HIGH}
                </Badge>
                <Badge variant="outline" className={severityBadgeClass("MEDIUM")}>
                  MEDIUM: {selectedEndpoint.findings_summary.MEDIUM}
                </Badge>
                <Badge variant="outline" className={severityBadgeClass("LOW")}>
                  LOW: {selectedEndpoint.findings_summary.LOW}
                </Badge>
              </div>

              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>ID</TableHead>
                    <TableHead>Source</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Judul</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {selectedEndpoint.findings.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={5} className="text-center text-muted-foreground">
                        Tidak ada temuan pada endpoint ini.
                      </TableCell>
                    </TableRow>
                  ) : (
                    selectedEndpoint.findings.map((f) => (
                      <TableRow key={f.id}>
                        <TableCell className="font-mono text-xs">{f.external_id}</TableCell>
                        <TableCell>
                          <Badge variant="secondary">{f.source_type}</Badge>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className={severityBadgeClass(f.severity)}>
                            {f.severity}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline">{f.status}</Badge>
                        </TableCell>
                        <TableCell className="text-sm">{f.title}</TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </div>
          ) : null}
        </DialogContent>
      </Dialog>
    </div>
  );
}
