import type { Metadata } from "next";
import Link from "next/link";
import { ShieldAlert, BookOpen, ScrollText } from "lucide-react";
import "./globals.css";

export const metadata: Metadata = {
  title: "Entropy — Architectural Security Debt Platform",
  description: "Entropy is an architectural security-debt analyzer for AI-assisted codebases. Measure hidden structural disorder in AI-assisted codebases.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="bg-background text-foreground antialiased flex flex-col min-h-screen">
        <header className="sticky top-0 z-50 border-b border-border bg-background/80 backdrop-blur-md px-6 py-3.5 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Link href="/" className="flex items-center gap-2.5 font-bold tracking-tight text-lg text-white">
              <div className="h-8 w-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
                <ShieldAlert className="h-5 w-5" />
              </div>
              <span>ENTROPY</span>
              <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 font-mono font-normal">
                v0.1.0-alpha
              </span>
            </Link>
          </div>

          <nav className="flex items-center gap-5 text-sm font-medium">
            <Link
              href="/"
              className="text-slate-300 hover:text-white transition-colors"
            >
              Dashboard
            </Link>
            <Link
              href="/constitution"
              className="flex items-center gap-1.5 text-slate-400 hover:text-white transition-colors"
            >
              <ScrollText className="h-4 w-4" />
              <span>Constitution</span>
            </Link>
            <a
              href="http://localhost:8000/docs"
              target="_blank"
              rel="noreferrer"
              className="flex items-center gap-1.5 text-slate-400 hover:text-white transition-colors"
            >
              <BookOpen className="h-4 w-4" />
              <span>API Specs</span>
            </a>
          </nav>
        </header>

        <main className="flex-1 max-w-7xl w-full mx-auto p-6 md:p-8">
          {children}
        </main>

        <footer className="border-t border-border py-6 px-8 text-center text-xs text-slate-500">
          <p>Entropy — Architectural Security Debt Analyzer for AI-Assisted Codebases</p>
          <p className="mt-1 text-slate-600">Deterministic Static Analysis • AST Verification • Production Engine</p>
        </footer>
      </body>
    </html>
  );
}
