"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { ClipboardCheck, LayoutDashboard, LogOut, Shield } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { clearAuthSession } from "@/lib/auth";
import { cn } from "@/lib/utils";
import type { UserProfile } from "@/types/qshields";

function roleBadgeClass(role: UserProfile["role"]): string {
  if (role === "ADMIN") return "border-purple-300 bg-purple-100 text-purple-800";
  if (role === "APPROVER") return "border-emerald-300 bg-emerald-100 text-emerald-800";
  return "border-blue-300 bg-blue-100 text-blue-800";
}

interface AppNavbarProps {
  user: UserProfile | null;
  pendingCount: number;
  rightSlot?: React.ReactNode;
}

export function AppNavbar({ user, pendingCount, rightSlot }: AppNavbarProps) {
  const pathname = usePathname();
  const router = useRouter();

  function handleLogout() {
    clearAuthSession();
    router.replace("/login");
  }

  return (
    <header className="sticky top-0 z-30 border-b bg-white/95 backdrop-blur-sm">
      <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-4 py-3 sm:px-6">
        <div className="flex flex-wrap items-center gap-6">
          <Link href="/" className="flex items-center gap-2.5">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-600 text-white">
              <Shield className="h-5 w-5" />
            </div>
            <div>
              <span className="block text-base font-bold leading-tight text-slate-900">
                Q-Shields
              </span>
              <span className="block text-[11px] text-muted-foreground">
                Security &amp; AI Remediation
              </span>
            </div>
          </Link>

          <nav className="flex items-center gap-1">
            <Link
              href="/"
              className={cn(
                "inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium transition-colors",
                pathname === "/"
                  ? "bg-blue-50 text-blue-700"
                  : "text-slate-600 hover:bg-slate-100 hover:text-slate-900"
              )}
            >
              <LayoutDashboard className="h-4 w-4" />
              Dashboard
            </Link>

            <Link
              href="/approvals"
              className={cn(
                "inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium transition-colors",
                pathname.startsWith("/approvals")
                  ? "bg-blue-50 text-blue-700"
                  : "text-slate-600 hover:bg-slate-100 hover:text-slate-900"
              )}
            >
              <ClipboardCheck className="h-4 w-4" />
              Approval Queue
              <Badge
                variant={pendingCount > 0 ? "default" : "secondary"}
                className="ml-1 px-1.5 py-0 text-[11px]"
              >
                {pendingCount}
              </Badge>
            </Link>
          </nav>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {rightSlot}

          {user && (
            <div className="flex items-center gap-2 rounded-md border bg-slate-50 px-3 py-1.5 text-sm">
              <span className="font-medium text-slate-800">
                {user.full_name || user.username}
              </span>
              <Badge variant="outline" className="text-[11px]">
                {user.auth_provider}
              </Badge>
              <Badge variant="outline" className={roleBadgeClass(user.role)}>
                {user.role}
              </Badge>
            </div>
          )}

          <Button variant="outline" size="sm" onClick={handleLogout}>
            <LogOut className="h-4 w-4" />
            Logout
          </Button>
        </div>
      </div>
    </header>
  );
}
