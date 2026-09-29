import { QueryClient } from "@tanstack/react-query";

// TanStack Query foundation — server state only (see docs/09).
// No polling or background refetch is configured: none is required.
// No queries are defined here, so startup performs no network requests.
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
      refetchOnReconnect: false,
    },
  },
});
