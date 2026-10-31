import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./lib/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "#0d0f12",
        foreground: "#edf0f4",
        card: {
          DEFAULT: "#13161b",
          hover: "#181c23",
          raised: "#1d212a",
        },
        border: {
          DEFAULT: "#20242e",
          subtle: "#181c24",
          highlight: "#2d3340",
        },
        ink: {
          950: "#090a0d",
          900: "#0d0f12",
          850: "#13161b",
          800: "#181c23",
          700: "#222732",
          600: "#2f3645",
          500: "#495265",
          400: "#707b91",
          300: "#9da7ba",
          200: "#ccd3e0",
          100: "#edf0f4",
        },
        debt: {
          very_low: "#34d399",
          low: "#38bdf8",
          moderate: "#fbbf24",
          high: "#fb923c",
          very_high: "#f87171",
        },
      },
      fontFamily: {
        sans: [
          "-apple-system",
          "BlinkMacSystemFont",
          '"Segoe UI"',
          "Roboto",
          '"Helvetica Neue"',
          "Arial",
          "sans-serif",
        ],
        mono: [
          '"JetBrains Mono"',
          '"SF Mono"',
          "Menlo",
          "Monaco",
          "Consolas",
          "monospace",
        ],
      },
      keyframes: {
        float: {
          "0%, 100%": { transform: "translateY(0px)" },
          "50%": { transform: "translateY(-8px)" },
        },
        "pulse-subtle": {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.5" },
        },
        shimmer: {
          "0%": { backgroundPosition: "-200% 0" },
          "100%": { backgroundPosition: "200% 0" },
        },
        radar: {
          "0%": { transform: "rotate(0deg)" },
          "100%": { transform: "rotate(360deg)" },
        },
        scanline: {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(1000%)" },
        },
      },
      animation: {
        float: "float 6s ease-in-out infinite",
        "pulse-subtle": "pulse-subtle 3s ease-in-out infinite",
        shimmer: "shimmer 8s linear infinite",
        radar: "radar 10s linear infinite",
        scanline: "scanline 8s linear infinite",
      },
      backgroundImage: {
        "gradient-radial": "radial-gradient(var(--tw-gradient-stops))",
      },
      boxShadow: {
        "glow-red": "0 0 25px -5px rgba(239, 68, 68, 0.45)",
        "glow-crimson": "0 0 30px -5px rgba(225, 29, 72, 0.4)",
        "glow-emerald": "0 0 25px -5px rgba(52, 211, 153, 0.35)",
        "glow-rose": "0 0 25px -5px rgba(244, 63, 94, 0.35)",
        "glow-cyan": "0 0 25px -5px rgba(56, 189, 248, 0.35)",
        "glow-amber": "0 0 25px -5px rgba(251, 191, 36, 0.3)",
      },
    },
  },
  plugins: [],
};
export default config;
