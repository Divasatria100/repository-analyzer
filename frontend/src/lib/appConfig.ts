// Public frontend configuration (no secrets).
//
// VITE_API_BASE_URL is the host-reachable backend address used by FUTURE
// frontend -> backend calls. The browser resolves it, so it must be a
// host address (http://localhost:8000), never a Compose service name.
// No API calls are made here.
const FALLBACK_API_BASE_URL = "http://localhost:8000";

export const apiBaseUrl: string =
  import.meta.env.VITE_API_BASE_URL && import.meta.env.VITE_API_BASE_URL.length > 0
    ? import.meta.env.VITE_API_BASE_URL
    : FALLBACK_API_BASE_URL;
