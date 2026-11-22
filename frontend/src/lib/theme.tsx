import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";

export type ThemePreference = "dark" | "light" | "system";
export type Density = "compact" | "default" | "comfortable";

interface ThemeState {
  theme: ThemePreference;
  resolvedTheme: "dark" | "light";
  density: Density;
  setTheme: (t: ThemePreference) => void;
  setDensity: (d: Density) => void;
}

const ThemeContext = createContext<ThemeState | null>(null);
const STORAGE_KEY = "magen.appearance";

function load(): { theme: ThemePreference; density: Density } {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw) as Partial<{ theme: ThemePreference; density: Density }>;
      return { theme: parsed.theme ?? "dark", density: parsed.density ?? "default" };
    }
  } catch {
    /* corrupt storage → defaults */
  }
  return { theme: "dark", density: "default" };
}

function systemTheme(): "dark" | "light" {
  return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

/**
 * Applies `data-theme` / `data-density` to <html>.
 * "system" is resolved here to a concrete theme: tokens.css only defines palettes for
 * `dark` and `light`, so writing `data-theme="system"` would leave the dark palette active.
 */
export function ThemeProvider({ children }: { children: ReactNode }) {
  const [{ theme, density }, setState] = useState(load);
  const [system, setSystem] = useState(systemTheme);

  useEffect(() => {
    const mq = window.matchMedia("(prefers-color-scheme: light)");
    const onChange = () => {
      setSystem(mq.matches ? "light" : "dark");
    };
    mq.addEventListener("change", onChange);
    return () => {
      mq.removeEventListener("change", onChange);
    };
  }, []);

  const resolvedTheme = theme === "system" ? system : theme;

  useEffect(() => {
    const root = document.documentElement;
    root.dataset.theme = resolvedTheme;
    root.dataset.density = density;
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ theme, density }));
  }, [theme, resolvedTheme, density]);

  const setTheme = useCallback((t: ThemePreference) => {
    setState((s) => ({ ...s, theme: t }));
  }, []);
  const setDensity = useCallback((d: Density) => {
    setState((s) => ({ ...s, density: d }));
  }, []);

  const value = useMemo(
    () => ({ theme, resolvedTheme, density, setTheme, setDensity }),
    [theme, resolvedTheme, density, setTheme, setDensity],
  );
  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useTheme(): ThemeState {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error("useTheme must be used inside <ThemeProvider>");
  return ctx;
}
