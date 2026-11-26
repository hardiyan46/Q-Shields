"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { AlertCircle, Lock, Server, ShieldCheck } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ApiError, loginUser } from "@/lib/api";
import { getAccessToken, setAuthSession } from "@/lib/auth";
import type { AuthMode } from "@/types/qshields";

const AUTH_MODE_DESCRIPTIONS: Record<AuthMode, string> = {
  AUTO: "Cek akun lokal PostgreSQL terlebih dahulu, lalu lanjut ke Domain Controller / LDAP jika aktif.",
  LOCAL: "Login menggunakan akun lokal yang tersimpan di database PostgreSQL Q-Shields.",
  LDAP: "Login menggunakan kredensial Domain Controller / Active Directory perusahaan (tanpa simpan password LDAP).",
};

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [authMode, setAuthMode] = useState<AuthMode>("AUTO");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (getAccessToken()) {
      router.replace("/");
    }
  }, [router]);

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setErrorMessage(null);

    if (!username.trim() || !password) {
      setErrorMessage("Username dan password wajib diisi.");
      return;
    }

    setIsSubmitting(true);
    try {
      const response = await loginUser({
        username: username.trim(),
        password,
        auth_mode: authMode,
      });
      setAuthSession(response.access_token, response.user);
      router.replace("/");
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 503) {
          setErrorMessage(
            `Server Domain Controller / LDAP tidak dapat dijangkau: ${err.message}`
          );
        } else {
          setErrorMessage(err.message);
        }
      } else {
        setErrorMessage(
          "Tidak dapat terhubung ke Q-Shields Backend API. Pastikan container backend berjalan."
        );
      }
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-slate-950 px-4 py-12">
      <div className="w-full max-w-md space-y-6">
        <div className="flex flex-col items-center space-y-2 text-center text-slate-100">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-blue-600 shadow-lg shadow-blue-600/30">
            <ShieldCheck className="h-7 w-7 text-white" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight">Q-Shields</h1>
          <p className="text-sm text-slate-400">
            Internal Endpoint Security, Hardening &amp; AI Remediation
          </p>
        </div>

        <Card className="border-slate-800 bg-white shadow-2xl">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-slate-900">
              <Lock className="h-4 w-4 text-blue-600" />
              Masuk ke Platform
            </CardTitle>
            <CardDescription>
              Mendukung autentikasi akun lokal dan Domain Controller / LDAP.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              {errorMessage && (
                <div
                  role="alert"
                  className="flex items-start gap-2 rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700"
                >
                  <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
                  <span>{errorMessage}</span>
                </div>
              )}

              <div className="space-y-1.5">
                <Label htmlFor="username">Username</Label>
                <Input
                  id="username"
                  name="username"
                  autoComplete="username"
                  placeholder="mis. admin atau hardiyan.p"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  disabled={isSubmitting}
                  required
                />
              </div>

              <div className="space-y-1.5">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  name="password"
                  type="password"
                  autoComplete="current-password"
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={isSubmitting}
                  required
                />
              </div>

              <div className="space-y-1.5">
                <Label htmlFor="auth-mode">Metode Autentikasi</Label>
                <Select
                  value={authMode}
                  onValueChange={(value) => setAuthMode(value as AuthMode)}
                  disabled={isSubmitting}
                >
                  <SelectTrigger id="auth-mode">
                    <SelectValue placeholder="Pilih mode autentikasi" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="AUTO">AUTO (Local lalu LDAP)</SelectItem>
                    <SelectItem value="LOCAL">LOCAL (Akun Lokal PostgreSQL)</SelectItem>
                    <SelectItem value="LDAP">LDAP (Domain Controller / AD)</SelectItem>
                  </SelectContent>
                </Select>
                <p className="flex items-start gap-1.5 text-xs text-muted-foreground">
                  <Server className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                  <span>{AUTH_MODE_DESCRIPTIONS[authMode]}</span>
                </p>
              </div>

              <Button type="submit" className="w-full" disabled={isSubmitting}>
                {isSubmitting ? "Memverifikasi..." : "Login"}
              </Button>
            </form>
          </CardContent>
        </Card>
      </div>
    </main>
  );
}
