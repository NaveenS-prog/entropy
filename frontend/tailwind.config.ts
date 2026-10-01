import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "#090d16",
        foreground: "#f8fafc",
        card: "#0f172a",
        "card-hover": "#1e293b",
        border: "#1e293b",
        debt: {
          very_low: "#10b981", // emerald
          low: "#06b6d4",      // cyan
          moderate: "#f59e0b", // amber
          high: "#f97316",     // orange
          very_high: "#ef4444" // red
        }
      },
    },
  },
  plugins: [],
};
export default config;
