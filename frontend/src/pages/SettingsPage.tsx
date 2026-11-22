import { PageHeader } from "@/components/layout/PageHeader";
import { useTheme, type Density, type ThemePreference } from "@/lib/theme";
import { cn } from "@/lib/utils";

function Segmented<T extends string>({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: T;
  options: readonly { value: T; label: string }[];
  onChange: (v: T) => void;
}) {
  return (
    <fieldset className="flex flex-col gap-2">
      <legend className="mb-2 text-sm font-medium text-fg">{label}</legend>
      <div className="inline-flex w-fit rounded-md border border-border-strong p-0.5">
        {options.map((o) => (
          <label
            key={o.value}
            className={cn(
              "flex h-8 cursor-pointer items-center rounded-sm px-3 text-sm text-fg-muted focus-within:outline focus-within:outline-2 focus-within:outline-offset-2 focus-within:outline-focus",
              value === o.value && "bg-surface-raised font-medium text-fg",
            )}
          >
            <input
              type="radio"
              className="sr-only"
              name={label}
              value={o.value}
              checked={value === o.value}
              onChange={() => {
                onChange(o.value);
              }}
            />
            {o.label}
          </label>
        ))}
      </div>
    </fieldset>
  );
}

const THEME_OPTIONS = [
  { value: "dark", label: "Dark" },
  { value: "light", label: "Light" },
  { value: "system", label: "System" },
] as const satisfies readonly { value: ThemePreference; label: string }[];

const DENSITY_OPTIONS = [
  { value: "compact", label: "Compact" },
  { value: "default", label: "Default" },
  { value: "comfortable", label: "Comfortable" },
] as const satisfies readonly { value: Density; label: string }[];

export function AppearanceControls() {
  const { theme, density, setTheme, setDensity } = useTheme();
  return (
    <div className="flex flex-wrap gap-8">
      <Segmented label="Theme" value={theme} options={THEME_OPTIONS} onChange={setTheme} />
      <Segmented label="Density" value={density} options={DENSITY_OPTIONS} onChange={setDensity} />
    </div>
  );
}

export function SettingsPage() {
  return (
    <>
      <PageHeader title="Settings" />
      <section className="rounded-md border border-border bg-surface p-4">
        <h2 className="mb-4 text-lg font-semibold">Appearance</h2>
        <AppearanceControls />
      </section>
    </>
  );
}
