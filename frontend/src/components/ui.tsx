import type { ReactNode } from "react";

// Shared presentation primitives following docs/DESIGN.md and
// docs/14-ui-requirements.md (Section 19: loading/empty/error states).
// Status is always icon + text, never color alone.

export function Panel({
  title,
  children,
  labelledBy,
}: {
  title?: string;
  children: ReactNode;
  labelledBy?: string;
}) {
  return (
    <section
      aria-labelledby={labelledBy}
      className="rounded-panel border border-border bg-surface p-6 shadow-panel"
    >
      {title ? (
        <h2 id={labelledBy} className="mb-4 text-lg font-semibold text-text-primary">
          {title}
        </h2>
      ) : null}
      {children}
    </section>
  );
}

type AlertTone = "error" | "warning" | "info" | "neutral";

const ALERT_STYLES: Record<AlertTone, { icon: string; classes: string }> = {
  error: { icon: "✕", classes: "border-status-error text-status-error" },
  warning: { icon: "▲", classes: "border-status-warning text-status-warning" },
  info: { icon: "●", classes: "border-status-info text-status-info" },
  neutral: { icon: "–", classes: "border-status-neutral text-status-neutral" },
};

export function Alert({
  tone,
  title,
  children,
}: {
  tone: AlertTone;
  title: string;
  children?: ReactNode;
}) {
  const style = ALERT_STYLES[tone];
  return (
    <div
      role="alert"
      className={`rounded-control border bg-secondary px-4 py-3 ${style.classes}`}
    >
      <p className="font-medium text-text-primary">
        <span aria-hidden="true" className="mr-2">
          {style.icon}
        </span>
        {title}
      </p>
      {children ? <div className="mt-1 text-sm text-text-secondary">{children}</div> : null}
    </div>
  );
}

export function FieldError({ id, message }: { id: string; message: string }) {
  return (
    <p id={id} role="alert" className="mt-1 text-sm text-status-error">
      <span aria-hidden="true" className="mr-1">
        ✕
      </span>
      {message}
    </p>
  );
}

export function StatusBadge({
  label,
  tone,
  marker,
}: {
  label: string;
  tone: AlertTone;
  marker: string;
}) {
  const style = ALERT_STYLES[tone];
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-pill border px-2 py-0.5 font-mono text-xs uppercase ${style.classes}`}
    >
      <span aria-hidden="true">{marker}</span>
      {label}
    </span>
  );
}

export function LoadingState({ label }: { label: string }) {
  return (
    <div className="py-8 text-center" role="status" aria-live="polite">
      <p className="text-text-secondary">{label}</p>
    </div>
  );
}

export function EmptyState({
  title,
  children,
}: {
  title: string;
  children?: ReactNode;
}) {
  return (
    <div className="py-8 text-center">
      <p className="font-medium text-text-primary">{title}</p>
      {children ? <div className="mt-2 text-sm text-text-secondary">{children}</div> : null}
    </div>
  );
}
