import { z } from "zod";

// Central location for frontend schemas. Full API schemas arrive in later
// phases and MUST follow docs/17-api-contract.md. This smoke schema covers
// only the shared pagination convention (17, Section 3.5) to prove the
// validation layer works end to end.
export const paginationParamsSchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  page_size: z.coerce.number().int().min(1).max(200).default(50),
});

export type PaginationParams = z.infer<typeof paginationParamsSchema>;
