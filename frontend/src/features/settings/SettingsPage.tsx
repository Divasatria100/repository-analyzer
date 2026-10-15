import { DENSITIES, usePreferencesStore, type InterfaceDensity } from "../../stores/usePreferencesStore";
import { Panel } from "../../components/ui";

// Settings (TASK-210, docs/14-ui-requirements.md, Section 5.1).
// V1.0 defines exactly one user-facing setting: interface density.
// Comfortable targets 40px data-table rows, Compact targets 32px rows
// (applied as a minimum so multiline content can grow). Persisted
// client-side only — no settings endpoint exists by design.

const DESCRIPTIONS: Record<InterfaceDensity, string> = {
  comfortable: "Comfortable — 40px data-table rows (default).",
  compact: "Compact — 32px data-table rows.",
};

export function SettingsPage() {
  const density = usePreferencesStore((state) => state.density);
  const setDensity = usePreferencesStore((state) => state.setDensity);

  return (
    <Panel title="Settings" labelledBy="settings-heading">
      <fieldset>
        <legend className="mb-1 text-sm font-medium">Interface density</legend>
        <p className="mb-3 text-sm text-text-secondary">
          Controls data-table row height across analysis views. Stored in this
          browser only.
        </p>
        <div className="space-y-2" role="radiogroup" aria-label="Interface density">
          {DENSITIES.map((value) => (
            <label
              key={value}
              className={`flex cursor-pointer items-start gap-3 rounded-control border px-3 py-2 text-sm ${
                density === value
                  ? "border-primary"
                  : "border-border hover:border-text-secondary"
              }`}
            >
              <input
                type="radio"
                name="interface-density"
                value={value}
                checked={density === value}
                onChange={() => setDensity(value)}
                className="mt-1"
                aria-describedby={`density-${value}-desc`}
              />
              <span>
                <span className="block font-medium capitalize">{value}</span>
                <span id={`density-${value}-desc`} className="block text-text-secondary">
                  {DESCRIPTIONS[value]}
                </span>
              </span>
            </label>
          ))}
        </div>
      </fieldset>
    </Panel>
  );
}
