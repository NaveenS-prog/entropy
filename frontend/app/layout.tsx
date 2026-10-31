import type { Metadata } from "next";
import Link from "next/link";
import { ShieldAlert, ScrollText } from "lucide-react";
import { Analytics } from "@vercel/analytics/react";
import "./globals.css";

export const metadata: Metadata = {
  title: "Entropy — Architectural Security Debt Platform",
  description:
    "Entropy is an architectural security-debt analyzer for AI-assisted codebases. Quantify structural disorder through deterministic AST analysis.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="bg-background text-foreground antialiased flex flex-col min-h-screen relative selection:bg-emerald-500/30 selection:text-emerald-200">
        {/* Subtle ambient lighting orbs */}
        <div className="fixed top-0 left-1/4 w-96 h-96 bg-emerald-500/5 rounded-full blur-3xl pointer-events-none -z-10" />
        <div className="fixed top-1/3 right-10 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none -z-10" />

        <header className="sticky top-0 z-50 border-b border-border/80 bg-ink-950/85 backdrop-blur-xl px-6 h-14 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Link
              href="/"
              className="flex items-center gap-2.5 font-semibold text-sm tracking-tight text-ink-100 hover:text-white transition-colors group"
            >
              <div className="h-8 w-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 group-hover:scale-105 group-hover:border-emerald-500/60 shadow-glow-emerald transition-all duration-200">
                <ShieldAlert className="h-4 w-4" />
              </div>
              <span className="font-bold tracking-tight text-white text-base">Entropy</span>
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-emerald-950/60 border border-emerald-800/60 text-emerald-300 font-mono font-medium">
                v0.1.0-forensic
              </span>
            </Link>
          </div>

          <nav className="flex items-center gap-4 text-xs font-medium">
            <Link
              href="/"
              className="px-3 py-1.5 rounded-lg text-ink-200 hover:text-white hover:bg-ink-850/80 transition-all"
            >
              Scanner Dashboard
            </Link>
            <Link
              href="/constitution"
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-ink-300 hover:text-white hover:bg-ink-850/80 transition-all"
            >
              <ScrollText className="h-3.5 w-3.5 text-emerald-400" />
              <span>Constitution</span>
            </Link>
          </nav>
        </header>

        <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 md:p-8">
          {children}
        </main>

        <footer className="border-t border-border/80 py-6 px-6 text-xs text-ink-400 bg-ink-950/50 backdrop-blur-md">
          <div className="flex flex-col sm:flex-row items-center justify-between max-w-7xl mx-auto gap-3 text-center sm:text-left">
            <div>
              <p className="text-white font-medium">Entropy — Architectural Security Debt Engine</p>
              <p className="text-[11px] text-ink-500 mt-0.5">
                Quantifying structural disorder in AI-assisted codebases • 100% Deterministic AST
              </p>
            </div>
            <div className="flex items-center gap-2 font-mono text-[11px] text-emerald-400/90 bg-ink-900 border border-border px-3 py-1 rounded-full">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
              <span>Hermetic AST Engine</span>
            </div>
          </div>
        </footer>
        <Analytics />
      </body>
    </html>
  );
}
