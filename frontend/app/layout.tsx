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
      <body className="bg-background text-foreground antialiased flex flex-col min-h-screen">
        <header className="sticky top-0 z-50 border-b border-border bg-background/90 backdrop-blur-md px-6 h-14 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Link
              href="/"
              className="flex items-center gap-2.5 font-semibold text-sm tracking-tight text-ink-100 hover:text-white transition-colors"
            >
              <div className="h-7 w-7 rounded-md bg-ink-800 border border-border flex items-center justify-center text-emerald-400">
                <ShieldAlert className="h-4 w-4" />
              </div>
              <span className="font-medium tracking-tight text-white">Entropy</span>
              <span className="text-[11px] px-1.5 py-0.5 rounded bg-ink-800 border border-border/80 text-ink-400 font-mono">
                v0.1.0
              </span>
            </Link>
          </div>

          <nav className="flex items-center gap-5 text-xs font-medium">
            <Link
              href="/"
              className="text-ink-200 hover:text-white transition-colors"
            >
              Scanner Dashboard
            </Link>
            <Link
              href="/constitution"
              className="flex items-center gap-1.5 text-ink-400 hover:text-white transition-colors"
            >
              <ScrollText className="h-3.5 w-3.5" />
              <span>Constitution</span>
            </Link>
          </nav>
        </header>

        <main className="flex-1 max-w-[1600px] w-full mx-auto p-4 sm:p-6 lg:p-8">
          {children}
        </main>

        <footer className="border-t border-border py-6 px-6 text-center text-xs text-ink-500">
          <div className="flex flex-col sm:flex-row items-center justify-between max-w-7xl mx-auto gap-2">
            <p>Entropy — Architectural security-debt engine</p>
            <p className="font-mono text-[11px] text-ink-500">
              Deterministic AST analysis
            </p>
          </div>
        </footer>
        <Analytics />
      </body>
    </html>
  );
}
