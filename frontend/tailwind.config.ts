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
    },
  },
  plugins: [],
};
export default config;
