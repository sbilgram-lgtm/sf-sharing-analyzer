export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface SharingFinding {
  id: string;
  category: string;
  severity: Severity;
  title: string;
  impact: string;
  remediation: string;
  metadata?: {
    count?: number;
    records?: { name: string; detail?: string }[];
    [key: string]: unknown;
  };
}

export interface CategoryResult {
  category: string;
  score: number;
  items: SharingFinding[];
}

export interface AssessmentResult {
  categories: CategoryResult[];
  overallScore: number;
  instanceUrl?: string | null;
  orgId?: string | null;
  orgName?: string | null;
  orgType?: string | null;
  isSandbox?: boolean;
  instanceName?: string | null;
  // Inventory data for Current State tab
  owdInventory?: unknown[];
  sharingRulesSummary?: { object: string; ownerRules: number; criteriaRules: number }[];
  roleStats?: { totalRoles: number; maxDepth: number; maxBreadth: number };
  teamStats?: { accountTeamEnabled: boolean; caseTeamEnabled: boolean; oppTeamEnabled: boolean; accountTeamCount: number; caseTeamCount: number; oppTeamCount: number };
  bypassStats?: { vadCount: number; madCount: number; viewAllObjectCount: number; modifyAllObjectCount: number };
  territoryStats?: { enabled: boolean; modelCount: number; territoryCount: number };
}
