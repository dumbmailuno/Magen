import { HashRouter, Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "@/components/layout/AppShell";
import { ScanProvider } from "@/lib/scan";
import { ThemeProvider } from "@/lib/theme";
import { DevComponentsPage } from "@/pages/DevComponents";
import { FindingsPage } from "@/pages/FindingsPage";
import { NewScanPage } from "@/pages/NewScanPage";
import { ComparePage } from "@/pages/ComparePage";
import { TargetsPage } from "@/pages/TargetsPage";
import { SettingsPage } from "@/pages/SettingsPage";

/** HashRouter: works when loaded from Electron's app:// protocol without server rewrites. */
export function App() {
  return (
    <ThemeProvider>
      <ScanProvider>
        <HashRouter>
          <Routes>
            <Route element={<AppShell />}>
              <Route index element={<Navigate to="/targets" replace />} />
              <Route path="targets" element={<TargetsPage />} />
              <Route path="scan" element={<NewScanPage />} />
              <Route path="findings" element={<FindingsPage />} />
              <Route path="compare" element={<ComparePage />} />
              <Route path="settings" element={<SettingsPage />} />
              {import.meta.env.DEV && (
                <Route path="dev/components" element={<DevComponentsPage />} />
              )}
              <Route path="*" element={<Navigate to="/targets" replace />} />
            </Route>
          </Routes>
        </HashRouter>
      </ScanProvider>
    </ThemeProvider>
  );
}
