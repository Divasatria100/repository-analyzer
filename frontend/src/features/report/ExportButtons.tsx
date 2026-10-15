import { useState } from "react";
import {
  ApiRequestError,
  REPORT_CONTENT_TYPES,
  REPORT_FILE_EXTENSIONS,
  REPORT_FORMATS,
  fetchReport,
  type ReportFormat,
} from "../../lib/api";
import { Alert } from "../../components/ui";

// Report export (TASK-207, docs/14 §18.2). Exactly the three server formats,
// downloaded byte-for-byte from the sealed report endpoint (no-store, never
// from cache). Non-2xx responses raise before any Blob is built, so an error
// payload can never be saved as a report.

const FORMAT_LABELS: Record<ReportFormat, string> = {
  json: "JSON (canonical, machine-readable)",
  markdown: "Markdown (human-readable report)",
  html: "HTML (presentation report)",
};

export function ExportButtons({ analysisId }: { analysisId: string }) {
  const [pending, setPending] = useState<ReportFormat | null>(null);
  const [failure, setFailure] = useState<string | null>(null);

  async function exportFormat(format: ReportFormat) {
    if (pending) {
      return;
    }
    setPending(format);
    setFailure(null);
    try {
      const blob = await fetchReport(analysisId, format);
      if (!blob.text) {
        throw new ApiRequestError(
          "UNKNOWN_ERROR",
          "The server returned an empty report. Nothing was downloaded.",
        );
      }
      const objectUrl = URL.createObjectURL(
        new Blob([blob.text], { type: blob.contentType || REPORT_CONTENT_TYPES[format] }),
      );
      try {
        const anchor = document.createElement("a");
        anchor.href = objectUrl;
        anchor.download = `repolens-${analysisId}.${REPORT_FILE_EXTENSIONS[format]}`;
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
      } finally {
        URL.revokeObjectURL(objectUrl);
      }
    } catch (error) {
      setFailure(
        error instanceof ApiRequestError ? error.message : "The export failed. Try again.",
      );
    } finally {
      setPending(null);
    }
  }

  return (
    <div>
      <div className="flex flex-wrap gap-2" role="group" aria-label="Export report">
        {REPORT_FORMATS.map((format) => (
          <button
            key={format}
            type="button"
            onClick={() => void exportFormat(format)}
            disabled={pending !== null}
            aria-busy={pending === format}
            aria-label={`Export report as ${format.toUpperCase()}`}
            title={FORMAT_LABELS[format]}
            className="rounded-control border border-border px-3 py-1.5 text-sm font-medium hover:border-primary disabled:cursor-not-allowed disabled:opacity-50"
          >
            {pending === format ? `Exporting ${format}…` : `Export ${format.toUpperCase()}`}
          </button>
        ))}
      </div>
      {failure ? (
        <div className="mt-3">
          <Alert tone="error" title="The export failed.">
            <p>{failure}</p>
          </Alert>
        </div>
      ) : null}
    </div>
  );
}
