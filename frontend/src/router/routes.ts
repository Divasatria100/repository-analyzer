// Centralized route paths (docs/14-ui-requirements.md, Section 5).
// Pages themselves arrive in later phases; only paths live here.

export const ROUTES = {
  root: "/",
  dashboard: "/dashboard",
  analysisNew: "/analysis/new",
  analysisDetail: (analysisId: string) => `/analysis/${analysisId}`,
  analysisOverview: (analysisId: string) => `/analysis/${analysisId}/overview`,
  analysisSecurity: (analysisId: string) => `/analysis/${analysisId}/security`,
  analysisArchitecture: (analysisId: string) => `/analysis/${analysisId}/architecture`,
  analysisDependencies: (analysisId: string) => `/analysis/${analysisId}/dependencies`,
  analysisCodeStructure: (analysisId: string) => `/analysis/${analysisId}/code-structure`,
  analysisFiles: (analysisId: string) => `/analysis/${analysisId}/files`,
  analysisFindings: (analysisId: string) => `/analysis/${analysisId}/findings`,
  history: "/history",
  settings: "/settings",
} as const;

export const ANALYSIS_ID_PARAM = "analysisId";
