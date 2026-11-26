import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Q-Shields | Internal Security & AI Remediation",
  description:
    "Internal Vulnerability Assessment (CVE), CIS Benchmark Hardening & AI-Assisted Remediation Platform",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="id">
      <body className="min-h-screen bg-background font-sans text-foreground">
        {children}
      </body>
    </html>
  );
}
