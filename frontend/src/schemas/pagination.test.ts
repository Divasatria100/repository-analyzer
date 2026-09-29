import { describe, expect, it } from "vitest";
import { paginationParamsSchema, type PaginationParams } from "./pagination";

describe("pagination schema foundation", () => {
  it("accepts valid data and applies contract defaults", () => {
    const parsed: PaginationParams = paginationParamsSchema.parse({});
    expect(parsed).toEqual({ page: 1, page_size: 50 });
  });

  it("accepts explicit valid values", () => {
    expect(paginationParamsSchema.parse({ page: 2, page_size: 200 })).toEqual({
      page: 2,
      page_size: 200,
    });
  });

  it("rejects invalid data", () => {
    expect(paginationParamsSchema.safeParse({ page: 0 }).success).toBe(false);
    expect(paginationParamsSchema.safeParse({ page_size: 201 }).success).toBe(false);
    expect(paginationParamsSchema.safeParse({ page: "abc" }).success).toBe(false);
  });
});
