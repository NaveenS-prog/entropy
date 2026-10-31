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
        background: "#F4F0E7",
        foreground: "#1B2932",
        // Entropy reference-manual surfaces & evidence tokens
        "bg-base": "#F4F0E7",
        "surface-1": "#FCFBF6",
        "surface-2": "#E7F0EE",
        "surface-3": "#D2E2DF",
        "border-subtle": "#C7D3CE",
        "border-strong": "#8DA9A5",
        "text-primary": "#1B2932",
        "text-secondary": "#52656B",
        "text-tertiary": "#6D7B7B",
        "severity-critical": "#BC3F3A",
        "severity-high": "#D35B46",
        "severity-medium": "#B7781D",
        "severity-low": "#236F8B",
        "status-pass": "#17756B",

        card: {
          DEFAULT: "#FCFBF6",
          hover: "#E7F0EE",
          raised: "#D2E2DF",
        },
        border: {
          DEFAULT: "#C7D3CE",
          subtle: "#DBE3DE",
          highlight: "#8DA9A5",
        },
        ink: {
          950: "#1B2932",
          900: "#243640",
          850: "#31454E",
          800: "#40565C",
          700: "#52656B",
          600: "#697C7D",
          500: "#7B8B88",
          400: "#52656B",
          300: "#40565C",
          200: "#31454E",
          100: "#1B2932",
        },
        debt: {
          very_low: "#17756B",
          low: "#236F8B",
          moderate: "#B7781D",
          high: "#D35B46",
          very_high: "#BC3F3A",
        },
      },
      fontFamily: {
        sans: [
          "-apple-system",
          "BlinkMacSystemFont",
          '"Segoe UI"',
          "Aptos",
          "Segoe UI",
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
