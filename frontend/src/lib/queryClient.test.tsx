import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { QueryClientProvider, useQuery } from "@tanstack/react-query";
import { queryClient } from "./queryClient";

function CachedValue() {
  const { data } = useQuery({ queryKey: ["foundation-smoke"], queryFn: async () => "cached" });
  return <p>{data ?? "loading"}</p>;
}

describe("queryClient foundation", () => {
  it("disables background refetch by default", () => {
    const defaults = queryClient.getDefaultOptions().queries;
    expect(defaults?.refetchOnWindowFocus).toBe(false);
    expect(defaults?.refetchOnReconnect).toBe(false);
  });

  it("serves cached data through the provider without network", async () => {
    render(
      <QueryClientProvider client={queryClient}>
        <CachedValue />
      </QueryClientProvider>,
    );
    expect(await screen.findByText("cached")).toBeDefined();
  });
});
