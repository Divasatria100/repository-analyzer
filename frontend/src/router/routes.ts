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
  analysisFindingDetail: (analysisId: string, findingId: string) =>
    `/analysis/${analysisId}/findings/${findingId}`,
  analysisComparison: (analysisId: string) => `/analysis/${analysisId}/comparison`,
  analysisReport: (analysisId: string) => `/analysis/${analysisId}/report`,
  history: "/history",
  settings: "/settings",
} as const;

export const ANALYSIS_ID_PARAM = "analysisId";
export const FINDING_ID_PARAM = "findingId";
