import { useEffect, useId, useRef, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router";
import { ROUTES } from "../router/routes";
import { usePreferencesStore } from "../stores/usePreferencesStore";

// Application shell (docs/14-ui-requirements.md, Section 4):
// persistent sidebar on desktop, navigation drawer on narrow screens,
// top bar with page context, and a consistent main content region.

const NAV_ITEMS = [
  { to: ROUTES.dashboard, label: "Dashboard" },
  { to: ROUTES.analysisNew, label: "New Analysis" },
  { to: ROUTES.history, label: "History" },
  { to: ROUTES.settings, label: "Settings" },
] as const;

const TITLES: Array<[RegExp, string]> = [
  [/^\/analysis\/new\/?$/, "New Analysis"],
  [/^\/analysis\/[^/]+/, "Analysis"],
  [/^\/history/, "History"],
  [/^\/settings/, "Settings"],
  [/^\/dashboard\/?$/, "Dashboard"],
  [/^\/$/, "Dashboard"],
];

function titleFor(pathname: string): string {
  for (const [pattern, title] of TITLES) {
    if (pattern.test(pathname)) {
      return title;
    }
  }
  return "Not Found";
}

export function AppShell() {
  const location = useLocation();
  const [drawerOpen, setDrawerOpen] = useState(false);
  const menuButtonRef = useRef<HTMLButtonElement>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const sidebarLabelId = useId();
  const drawerLabelId = useId();
  const pageTitle = titleFor(location.pathname);
  const density = usePreferencesStore((state) => state.density);

  useEffect(() => {
    document.title = `${pageTitle} · RepoLens`;
  }, [pageTitle]);

  // Density preference drives table row heights via CSS (docs/14 §5.1).
  useEffect(() => {
    document.documentElement.dataset.density = density;
  }, [density]);

  // Close the drawer on navigation and return focus to the menu button.
  useEffect(() => {
    setDrawerOpen((open) => {
      if (open) {
        menuButtonRef.current?.focus();
      }
      return false;
    });
  }, [location.pathname]);

  // After navigation, if focus was lost with the unmounted page (active
  // element fell back to body), move it to the page heading so keyboard
  // and screen-reader users land somewhere sensible. Pages that manage
  // their own initial focus (e.g. autofocus inputs) are left alone.
  useEffect(() => {
    if (
      !drawerOpen &&
      (document.activeElement === document.body || document.activeElement === null)
    ) {
      headingRef.current?.focus({ preventScroll: true });
    }
  }, [location.pathname, drawerOpen]);

  // Escape closes the drawer.
  useEffect(() => {
    if (!drawerOpen) {
      return;
    }
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setDrawerOpen(false);
        menuButtonRef.current?.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [drawerOpen]);

function PrimaryNav({ labelId }: { labelId: string }) {
  return (
    <nav aria-labelledby={labelId}>
      <p id={labelId} className="sr-only">
        Primary
      </p>
      <ul className="space-y-1">
        {NAV_ITEMS.map((item) => (
          <li key={item.to}>
            <NavLink
              to={item.to}
              end={item.to === ROUTES.dashboard}
              className={({ isActive }) =>
                `block rounded-control border-l-4 px-3 py-2 text-sm font-medium transition-colors ${
                  isActive
                    ? "border-primary bg-surface text-text-primary"
                    : "border-transparent text-text-secondary hover:bg-surface hover:text-text-primary"
                }`
              }
            >
              {item.label}
            </NavLink>
          </li>
        ))}
      </ul>
    </nav>
  );
}

  return (
    <div className="flex min-h-screen bg-background text-text-primary">
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded-control focus:bg-primary focus:px-4 focus:py-2 focus:text-sm focus:font-semibold focus:text-background"
      >
        Skip to main content
      </a>
      {/* Desktop sidebar (docs/14 §4.2: exactly the four entries). */}
      <aside className="hidden w-60 shrink-0 border-r border-border bg-secondary p-4 md:block">
        <p className="mb-6 flex items-center gap-2 px-3 text-lg font-bold tracking-tight">
          <span aria-hidden="true" className="inline-block h-2.5 w-2.5 rounded-[3px] bg-primary" />
          RepoLens
        </p>
        <PrimaryNav labelId={sidebarLabelId} />
      </aside>

      {/* Mobile drawer. */}
      {drawerOpen ? (
        <div className="fixed inset-0 z-40 md:hidden" role="dialog" aria-modal="true" aria-label="Primary navigation">
          <button
            type="button"
            aria-label="Close navigation"
            className="absolute inset-0 h-full w-full cursor-default bg-black/60"
            onClick={() => setDrawerOpen(false)}
          />
          <div className="absolute inset-y-0 left-0 w-64 overflow-y-auto bg-secondary p-4">
            <div className="mb-6 flex items-center justify-between px-3">
              <p className="flex items-center gap-2 text-lg font-bold tracking-tight">
                <span aria-hidden="true" className="inline-block h-2.5 w-2.5 rounded-[3px] bg-primary" />
                RepoLens
              </p>
              <button
                type="button"
                onClick={() => setDrawerOpen(false)}
                className="rounded-control border border-border px-2 py-1 text-sm text-text-secondary hover:text-text-primary"
              >
                Close
              </button>
            </div>
            <PrimaryNav labelId={drawerLabelId} />
          </div>
        </div>
      ) : null}

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center gap-3 border-b border-border bg-secondary px-4 py-3">
          <button
            ref={menuButtonRef}
            type="button"
            className="rounded-control border border-border px-2 py-1 text-sm text-text-secondary hover:text-text-primary md:hidden"
            aria-expanded={drawerOpen}
            aria-label={drawerOpen ? "Close navigation" : "Open navigation"}
            onClick={() => setDrawerOpen((open) => !open)}
          >
            Menu
          </button>
          <h1 ref={headingRef} tabIndex={-1} className="min-w-0 truncate text-base font-semibold outline-none">{pageTitle}</h1>
        </header>
        <main id="main-content" tabIndex={-1} className="mx-auto w-full max-w-[1200px] flex-1 px-4 py-6 outline-none md:px-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
