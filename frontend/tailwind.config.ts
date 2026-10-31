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
        background: "#080A0D",
        foreground: "#F0F6FC",
        // Swiss DevSecOps Surfaces & Precision Tokens
        "bg-base": "#080A0D",
        "surface-1": "#0E1217",
        "surface-2": "#151B22",
        "surface-3": "#1C232D",
        "border-subtle": "#1C232D",
        "border-strong": "#2D3748",
        "text-primary": "#F0F6FC",
        "text-secondary": "#8B949E",
        "text-tertiary": "#545D68",
        "severity-critical": "#F85149",
        "severity-high": "#FF7B72",
        "severity-medium": "#D29922",
        "severity-low": "#58A6FF",
        "status-pass": "#2EA043",

        card: {
          DEFAULT: "#0E1217",
          hover: "#151B22",
          raised: "#1C232D",
        },
        border: {
          DEFAULT: "#1C232D",
          subtle: "#141920",
          highlight: "#2D3748",
        },
        ink: {
          950: "#080A0D",
          900: "#0E1217",
          850: "#13171F",
          800: "#151B22",
          700: "#1C232D",
          600: "#2D3748",
          500: "#545D68",
          400: "#8B949E",
          300: "#B1BAC4",
          200: "#C9D1D9",
          100: "#F0F6FC",
        },
        debt: {
          very_low: "#2EA043",
          low: "#58A6FF",
          moderate: "#D29922",
          high: "#FF7B72",
          very_high: "#F85149",
        },
      },
      fontFamily: {
        sans: [
          "-apple-system",
          "BlinkMacSystemFont",
          '"Segoe UI"',
          "Inter",
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
          "ui-monospace",
          "monospace",
        ],
      },
    },
  },
  plugins: [],
};
export default config;
