// Magen Tailwind preset — maps semantic CSS variables from src/styles/tokens.css.
// Rule: components use these utilities (bg-surface, text-muted, border-border...),
// never raw hex or arbitrary values like bg-[#123456] / p-[13px].
import type { Config } from "tailwindcss";

const v = (name: string) => `var(--${name})`;

const preset: Partial<Config> = {
  darkMode: ["class", '[data-theme="dark"]'],
  theme: {
    extend: {
      // design-system §4: master–detail stacks below 1100px.
      screens: { split: "1100px" },
      colors: {
        bg: v("color-bg"),
        surface: { DEFAULT: v("color-surface"), raised: v("color-surface-raised") },
        border: { DEFAULT: v("color-border"), strong: v("color-border-strong") },
        fg: {
          DEFAULT: v("color-text"),
          muted: v("color-text-muted"),
          disabled: v("color-text-disabled"),
        },
        primary: {
          DEFAULT: v("color-primary"),
          hover: v("color-primary-hover"),
          active: v("color-primary-active"),
          fg: v("color-on-primary"),
        },
        accent: v("color-accent-text"),
        focus: v("color-focus"),
        sev: {
          critical: v("color-sev-critical"),
          high: v("color-sev-high"),
          medium: v("color-sev-medium"),
          low: v("color-sev-low"),
          info: v("color-sev-info"),
        },
        "sev-bg": {
          critical: v("color-sev-critical-bg"),
          high: v("color-sev-high-bg"),
          medium: v("color-sev-medium-bg"),
          low: v("color-sev-low-bg"),
          info: v("color-sev-info-bg"),
        },
        success: { DEFAULT: v("color-success"), bg: v("color-success-bg") },
        warning: { DEFAULT: v("color-warning"), bg: v("color-warning-bg") },
        danger: { DEFAULT: v("color-danger"), bg: v("color-danger-bg") },
        ai: { DEFAULT: v("color-ai"), bg: v("color-ai-bg") },
        diff: { add: v("color-diff-add-bg"), del: v("color-diff-del-bg") },
      },
      fontFamily: { sans: v("font-sans"), mono: v("font-mono") },
      fontSize: {
        xs: [v("text-xs"), "1.4"],
        sm: [v("text-sm"), "1.4"],
        base: [v("text-base"), v("leading-body")],
        md: [v("text-md"), v("leading-body")],
        lg: [v("text-lg"), v("leading-heading")],
        xl: [v("text-xl"), v("leading-heading")],
        "2xl": [v("text-2xl"), v("leading-heading")],
      },
      borderRadius: { sm: v("radius-sm"), md: v("radius-md"), lg: v("radius-lg") },
      boxShadow: { 1: v("shadow-1"), 2: v("shadow-2"), 3: v("shadow-3") },
      transitionDuration: {
        fast: v("duration-fast"),
        base: v("duration-base"),
        slow: v("duration-slow"),
      },
      transitionTimingFunction: { standard: v("ease-standard"), exit: v("ease-exit") },
      width: { sidebar: v("sidebar-w"), "sidebar-collapsed": v("sidebar-w-collapsed") },
      maxWidth: { content: v("content-max") },
    },
  },
};

export default preset;
