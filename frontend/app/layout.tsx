import type { Metadata } from "next";
import Link from "next/link";
import { ScrollText } from "lucide-react";
import { Analytics } from "@vercel/analytics/react";
import { EntropyLogo } from "@/components/brand/EntropyLogo";
import "./globals.css";

export const metadata: Metadata = {
  title: "Entropy — Architectural Security Debt Platform",
  description:
    "Entropy is an architectural security-debt analyzer for AI-assisted codebases. Quantify structural disorder through deterministic AST analysis.",
  icons: {
    icon: [
      { url: "/favicon.ico", sizes: "any" },
      { url: "/favicon-32x32.png", type: "image/png", sizes: "32x32" },
      { url: "/favicon-16x16.png", type: "image/png", sizes: "16x16" },
      { url: "/icon.png", type: "image/png", sizes: "512x512" },
    ],
    apple: [
      { url: "/apple-touch-icon.png", sizes: "180x180", type: "image/png" },
    ],
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="bg-background text-foreground antialiased flex flex-col min-h-screen selection:bg-ink-700 selection:text-white">
        <header className="sticky top-0 z-40 border-b border-border bg-ink-950/90 backdrop-blur px-6 h-13 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Link
              href="/"
              className="flex items-center gap-2.5 font-semibold text-sm tracking-tight text-ink-100 hover:text-white transition-colors group"
            >
              <div className="p-0.5 rounded-lg border border-border/80 bg-ink-900 group-hover:scale-105 group-hover:border-orange-500/60 transition-all duration-200">
                <EntropyLogo size={28} roundedClassName="rounded-md" priority />
              </div>
              <span className="font-bold tracking-tight text-white text-base">Entropy</span>
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-orange-950/50 border border-orange-500/30 text-orange-300 font-mono font-medium">
                v0.1.0
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
              <ScrollText className="h-3.5 w-3.5 text-orange-400" />
              <span>Constitution</span>
            </Link>
          </nav>
        </header>

        <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 md:p-8">
          {children}
        </main>

        <footer className="border-t border-border/80 py-6 px-6 text-xs text-ink-400 bg-ink-950/50 backdrop-blur-md">
          <div className="flex flex-col sm:flex-row items-center justify-between max-w-7xl mx-auto gap-4 text-center sm:text-left">
            <div className="flex items-center gap-3">
              <div className="p-0.5 rounded-lg border border-border/70 bg-ink-900 shrink-0">
                <EntropyLogo size={28} roundedClassName="rounded-md" />
              </div>
              <div>
                <p className="text-white font-medium">Entropy — Architectural Security Debt Engine</p>
                <p className="text-[11px] text-ink-500 mt-0.5">
                  Quantifying structural disorder in AI-assisted codebases • 100% Deterministic AST
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2 font-mono text-[11px] text-orange-400/90 bg-ink-900 border border-border px-3 py-1 rounded-full">
              <span className="h-1.5 w-1.5 rounded-full bg-orange-500 animate-pulse" />
              <span>Hermetic AST Engine</span>
            </div>
          </div>
        </footer>
        <Analytics />
      </body>
    </html>
  );
}
