import { SharingFinding, CategoryResult, AssessmentResult } from '../types/assessment';

function createFinding(
  category: string,
  severity: SharingFinding['severity'],
  title: string,
  impact: string,
  remediation: string,
  metadata?: SharingFinding['metadata']
): SharingFinding {
  return {
    id: `${category}-${title}`.replace(/\s+/g, '-').toLowerCase().slice(0, 80),
    category,
    severity,
    title,
    impact,
    remediation,
    metadata
  };
}

function calculateCategoryScore(findings: SharingFinding[]): number {
  if (findings.length === 0) return 100;
  let deductions = 0;
  for (const f of findings) {
    if (f.severity === 'critical') deductions += 25;
    else if (f.severity === 'high') deductions += 15;
    else if (f.severity === 'medium') deductions += 7;
    else deductions += 3;
  }
  return Math.max(0, 100 - deductions);
}

// ── OWD Analysis ──────────────────────────────────────────────────────────────
export function assessOwd(data: { entities: any[] }): CategoryResult & { inventory: any[] } {
  const findings: SharingFinding[] = [];
  const entities: any[] = data.entities || [];
  const CAT = 'OWD Analysis';

  const sensitiveObjects = ['Case', 'Opportunity', 'Lead', 'Contract', 'Order', 'Campaign'];
  const rwInternalSensitive = entities.filter(e =>
    e.InternalSharingModel === 'ReadWrite' &&
    sensitiveObjects.some(s => e.QualifiedApiName === s || e.Label === s)
  );
  rwInternalSensitive.forEach(e => {
    findings.push(createFinding(CAT, 'high',
      `${e.Label} Object Is Public Read/Write`,
      `All internal users can read and edit every ${e.Label} record regardless of role or ownership. This is rarely the intended access model for this object.`,
      `Change the OWD for ${e.Label} to Private or Public Read Only and implement sharing rules or role hierarchy to grant access where needed.`,
      { records: [{ name: e.Label, detail: `Internal OWD: ${e.InternalSharingModel}` }] }
    ));
  });

  const rwExternalEntities = entities.filter(e => e.ExternalSharingModel === 'ReadWrite');
  if (rwExternalEntities.length > 0) {
    findings.push(createFinding(CAT, 'critical',
      `${rwExternalEntities.length} Object${rwExternalEntities.length > 1 ? 's' : ''} Have External OWD Set to Public Read/Write`,
      'Guest users and portal users can read and edit all records on these objects. This is almost never intentional and represents a critical data exposure risk.',
      'Immediately review and restrict external OWD settings. No object should be Public Read/Write externally unless it was explicitly designed for guest write access.',
      { records: rwExternalEntities.map(e => ({ name: e.Label, detail: `External OWD: ${e.ExternalSharingModel}` })) }
    ));
  }

  const readExternalEntities = entities.filter(e => e.ExternalSharingModel === 'Read');
  if (readExternalEntities.length > 0) {
    findings.push(createFinding(CAT, 'medium',
      `${readExternalEntities.length} Object${readExternalEntities.length > 1 ? 's' : ''} Are Publicly Readable by External Users`,
      'Objects with external OWD of Public Read are visible to all Experience Cloud and portal users. Review whether all of these objects should be broadly accessible.',
      'Review each object. If external visibility is not intentional, set external OWD to Private and use sharing rules or sharing sets to grant access to specific portal users.',
      { records: readExternalEntities.map(e => ({ name: e.Label, detail: `External OWD: ${e.ExternalSharingModel}` })) }
    ));
  }

  const rwInternalAll = entities.filter(e => e.InternalSharingModel === 'ReadWrite');
  if (rwInternalAll.length > 10) {
    findings.push(createFinding(CAT, 'medium',
      `${rwInternalAll.length} Objects Have Public Read/Write Internal OWD — Review Recommended`,
      'Having more than 10 objects with Public Read/Write OWD is unusual for most production orgs and may indicate the sharing model was never properly designed.',
      'Audit all objects with Public Read/Write OWD. For any sensitive business object, consider tightening to Private or Public Read Only and adding targeted sharing rules.',
      { count: rwInternalAll.length }
    ));
  }

  return {
    category: CAT,
    score: calculateCategoryScore(findings),
    items: findings,
    inventory: entities
  };
}

// ── Role Hierarchy ────────────────────────────────────────────────────────────
export function assessRoleHierarchy(data: {
  allRoles: any[];
  totalRoleCount: number;
  topLevelRoleUsers: any[];
  emptyRoles: any[];
}): CategoryResult & { stats: any } {
  const findings: SharingFinding[] = [];
  const CAT = 'Role Hierarchy';

  const allRoles: any[] = data.allRoles || [];
  const totalRoleCount: number = data.totalRoleCount || 0;
  const topLevelRoleUsers: any[] = data.topLevelRoleUsers || [];
  const emptyRoles: any[] = data.emptyRoles || [];

  // Compute max depth and max breadth via tree traversal
  const parentMap = new Map<string, string | null>(allRoles.map((r: any) => [r.Id, r.ParentRoleId]));
  const depthByRole = new Map<string, number>();

  function getDepth(roleId: string, visited = new Set<string>()): number {
    if (depthByRole.has(roleId)) return depthByRole.get(roleId)!;
    if (visited.has(roleId)) return 0;
    visited.add(roleId);
    const parent = parentMap.get(roleId);
    const d = parent ? getDepth(parent, visited) + 1 : 0;
    depthByRole.set(roleId, d);
    return d;
  }

  for (const role of allRoles) {
    getDepth(role.Id);
  }

  let maxDepth = 0;
  const countByLevel = new Map<number, number>();
  Array.from(depthByRole.values()).forEach(depth => {
    if (depth > maxDepth) maxDepth = depth;
    countByLevel.set(depth, (countByLevel.get(depth) || 0) + 1);
  });

  let maxBreadth = 0;
  let maxBreadthLevel = 0;
  Array.from(countByLevel.entries()).forEach(([level, count]) => {
    if (count > maxBreadth) { maxBreadth = count; maxBreadthLevel = level; }
  });

  if (maxDepth > 10) {
    findings.push(createFinding(CAT, 'high',
      `Role Hierarchy Is ${maxDepth} Levels Deep — Exceeds Recommended Maximum`,
      `Salesforce recommends a maximum of 7 levels. At ${maxDepth} levels, sharing recalculation when users are added or roles change causes significant performance impact.`,
      'Review intermediate roles that exist only for structural reasons. Consolidate where possible to flatten the hierarchy toward 7 or fewer levels.',
      { count: maxDepth }
    ));
  } else if (maxDepth > 7) {
    findings.push(createFinding(CAT, 'medium',
      `Role Hierarchy Is ${maxDepth} Levels Deep — Approaching Recommended Maximum`,
      `Salesforce recommends keeping the role hierarchy to 7 or fewer levels. At ${maxDepth} levels, the hierarchy is approaching the threshold where sharing recalculation starts to impact performance.`,
      'Review intermediate roles. Consider consolidating levels where roles represent the same visibility boundary.',
      { count: maxDepth }
    ));
  }

  if (totalRoleCount >= 1000) {
    findings.push(createFinding(CAT, 'high',
      `${totalRoleCount} Total Roles — Large Role Hierarchy`,
      'Orgs with 1,000+ roles experience significantly slower sharing recalculation, slower user record saves, and increased risk of async sharing timeouts.',
      'Audit the role hierarchy. Remove roles with no active users. Flatten intermediate roles that add no business value. Consider whether role-based sharing can be replaced with criteria-based sharing rules.',
      { count: totalRoleCount }
    ));
  } else if (totalRoleCount >= 500) {
    findings.push(createFinding(CAT, 'medium',
      `${totalRoleCount} Total Roles — Monitor Role Hierarchy Size`,
      'Orgs with 500+ roles start to see performance impacts on sharing recalculation and user saves. Salesforce recommends a lean role hierarchy.',
      'Audit the role hierarchy for roles with no active users. Flatten intermediate roles where possible.',
      { count: totalRoleCount }
    ));
  }

  const topLevelWithManyUsers = topLevelRoleUsers.filter((r: any) => (r.userCount || r.expr0 || 0) > 5);
  if (topLevelWithManyUsers.length > 0) {
    findings.push(createFinding(CAT, 'medium',
      `${topLevelWithManyUsers.length} Top-Level Role${topLevelWithManyUsers.length > 1 ? 's Have' : ' Has'} More Than 5 Users`,
      'Users in top-level roles can see all records below them in the hierarchy. Top-level roles should contain only executive or admin users — widespread use inflates record visibility and undermines least-privilege access.',
      'Review which users are assigned to top-level roles. Move non-executive users to appropriate roles lower in the hierarchy.',
      { records: topLevelWithManyUsers.map((r: any) => ({ name: r.UserRoleId, detail: `${r.userCount || r.expr0} active users` })) }
    ));
  }

  if (maxBreadth > 100) {
    findings.push(createFinding(CAT, 'high',
      `Role Hierarchy Level ${maxBreadthLevel} Has ${maxBreadth} Roles — Excessively Wide`,
      `A single level with 100+ roles creates governance complexity and slows sharing recalculation. Each role at this level is a separate branch Salesforce must traverse on every sharing event.`,
      'Consolidate roles at this level. Introduce intermediate grouping roles to reduce breadth. Review whether roles at this level represent real business distinctions.',
      { count: maxBreadth }
    ));
  } else if (maxBreadth > 50) {
    findings.push(createFinding(CAT, 'medium',
      `Role Hierarchy Level ${maxBreadthLevel} Has ${maxBreadth} Roles — Wide Hierarchy`,
      `Having 50+ roles at a single level increases sharing recalculation time and makes the hierarchy difficult to govern.`,
      'Review roles at this level for consolidation opportunities.',
      { count: maxBreadth }
    ));
  }

  if (emptyRoles.length > 0) {
    findings.push(createFinding(CAT, 'low',
      `${emptyRoles.length} Role${emptyRoles.length > 1 ? 's Have' : ' Has'} No Active Users`,
      'Roles with no active users add noise to the hierarchy and still participate in sharing recalculation, adding unnecessary overhead.',
      'Remove roles that have no active users and no foreseeable use. Archive them in documentation if they represent historical org structure.',
      { records: emptyRoles.map((r: any) => ({ name: r.Name })) }
    ));
  }

  return {
    category: CAT,
    score: calculateCategoryScore(findings),
    items: findings,
    stats: { totalRoles: totalRoleCount, maxDepth, maxBreadth }
  };
}

// ── Territory Management 2.0 ──────────────────────────────────────────────────
export function assessTerritories(data: {
  enabled: boolean;
  models: any[];
  territories: any[];
  rules: any[];
  userAssociations: any[];
}): CategoryResult & { stats: any } {
  const findings: SharingFinding[] = [];
  const CAT = 'Territory Management';

  if (!data.enabled) {
    return {
      category: CAT,
      score: 100,
      items: [],
      stats: { enabled: false }
    };
  }

  const models: any[] = data.models || [];
  const territories: any[] = data.territories || [];
  const rules: any[] = data.rules || [];
  const userAssociations: any[] = data.userAssociations || [];

  const activeModels = models.filter(m => m.State === 'Active');
  if (activeModels.length > 1) {
    findings.push(createFinding(CAT, 'high',
      `${activeModels.length} Active Territory Models Found`,
      'Only one territory model should be active at a time. Multiple active models can cause confusion about which model drives record visibility and may produce conflicting territory assignments.',
      'Review active territory models. Deactivate or archive all but the primary active model. Use Planning state for models under development.',
      { count: activeModels.length, records: activeModels.map(m => ({ name: m.Name, detail: 'Active' })) }
    ));
  }

  // Territories with no user associations
  const territoriesWithUsers = new Set(userAssociations.map((u: any) => u.Territory2Id));
  const territoriesWithNoUsers = territories.filter(t => !territoriesWithUsers.has(t.Id));
  if (territoriesWithNoUsers.length > 0) {
    findings.push(createFinding(CAT, 'medium',
      `${territoriesWithNoUsers.length} Territories Have No Users Assigned`,
      'Territories with no users assigned will not grant any record visibility to team members. Accounts assigned to these territories will have no territory-based access.',
      'Review each territory without users. Either assign appropriate users or remove the territory from the active model.',
      { records: territoriesWithNoUsers.slice(0, 50).map((t: any) => ({ name: t.Name })) }
    ));
  }

  const inactiveRules = rules.filter(r => !r.IsActive);
  if (inactiveRules.length > 0) {
    findings.push(createFinding(CAT, 'low',
      `${inactiveRules.length} Territory Assignment Rules Are Inactive`,
      'Inactive assignment rules may represent obsolete criteria or work in progress. They add clutter to the territory model and may cause confusion during audits.',
      'Review inactive rules. Delete rules that are no longer needed. Activate rules that should be running.',
      { count: inactiveRules.length }
    ));
  }

  return {
    category: CAT,
    score: calculateCategoryScore(findings),
    items: findings,
    stats: { enabled: true, modelCount: models.length, territoryCount: territories.length }
  };
}

// ── Sharing Rules ─────────────────────────────────────────────────────────────
export function assessSharingRules(data: { ownerRules: any[]; criteriaRules: any[] }): CategoryResult & { stats: any } {
  const findings: SharingFinding[] = [];
  const CAT = 'Sharing Rules';

  const ownerRules: any[] = data.ownerRules || [];
  const criteriaRules: any[] = data.criteriaRules || [];
  const totalRules = ownerRules.length + criteriaRules.length;

  const allRulesTargetingAll = [...ownerRules, ...criteriaRules].filter(r =>
    r.SharedTo?.Type === 'AllInternalUsers' || r.SharedTo?.Type === 'AllCustomerPortalUsers'
  );
  if (allRulesTargetingAll.length > 0) {
    findings.push(createFinding(CAT, 'high',
      `${allRulesTargetingAll.length} Sharing Rule${allRulesTargetingAll.length > 1 ? 's Target' : ' Targets'} All Internal Users`,
      'Sharing rules targeting all internal users are equivalent to setting the OWD to Public Read. The rule adds no value, creates unnecessary sharing recalculation load, and signals a misunderstood sharing model.',
      'Review each rule. If all internal users truly need access, change the OWD to Public Read instead and delete the rule. Otherwise, narrow the target to a specific role, group, or territory.',
      { count: allRulesTargetingAll.length }
    ));
  }

  if (totalRules > 500) {
    findings.push(createFinding(CAT, 'high',
      `${totalRules} Total Sharing Rules — Sharing Recalculation Risk`,
      'Orgs with 500+ sharing rules experience significant delays in sharing recalculation events, which are triggered by record ownership changes, role hierarchy updates, and mass transfers.',
      'Audit sharing rules for redundancy. Consolidate criteria-based rules for the same object. Replace per-user sharing rules with role or group-based rules. Consider whether some sharing can be handled by the role hierarchy instead.',
      { count: totalRules }
    ));
  } else if (totalRules > 200) {
    findings.push(createFinding(CAT, 'medium',
      `${totalRules} Total Sharing Rules — Review for Redundancy`,
      'Large numbers of sharing rules increase recalculation time. Review for rules that can be consolidated.',
      'Audit sharing rules by object. Identify rules that overlap in criteria or target the same groups. Consolidate where possible.',
      { count: totalRules }
    ));
  }

  // Per-object rule counts
  const rulesByObject = new Map<string, { ownerCount: number; criteriaCount: number }>();
  for (const r of ownerRules) {
    const obj = r.EntityDefinition?.QualifiedApiName || 'Unknown';
    const current = rulesByObject.get(obj) || { ownerCount: 0, criteriaCount: 0 };
    rulesByObject.set(obj, { ...current, ownerCount: current.ownerCount + 1 });
  }
  for (const r of criteriaRules) {
    const obj = r.EntityDefinition?.QualifiedApiName || 'Unknown';
    const current = rulesByObject.get(obj) || { ownerCount: 0, criteriaCount: 0 };
    rulesByObject.set(obj, { ...current, criteriaCount: current.criteriaCount + 1 });
  }

  Array.from(rulesByObject.entries()).forEach(([obj, counts]) => {
    const objTotal = counts.ownerCount + counts.criteriaCount;
    if (objTotal > 50) {
      findings.push(createFinding(CAT, 'medium',
        `${obj} Has ${objTotal} Sharing Rules — High Recalculation Risk`,
        `Objects with many sharing rules require more time to recalculate sharing when records change owners or when hierarchy changes occur.`,
        `Review sharing rules for ${obj}. Consolidate criteria-based rules. Consider whether some access can be granted through the role hierarchy instead.`,
        { count: objTotal }
      ));
    }
  });

  // Build summary for inventory
  const summary = Array.from(rulesByObject.entries()).map(([object, counts]) => ({
    object,
    ownerRules: counts.ownerCount,
    criteriaRules: counts.criteriaCount
  })).sort((a, b) => (b.ownerRules + b.criteriaRules) - (a.ownerRules + a.criteriaRules));

  return {
    category: CAT,
    score: calculateCategoryScore(findings),
    items: findings,
    stats: {
      ownerRuleCount: ownerRules.length,
      criteriaRuleCount: criteriaRules.length,
      totalRuleCount: totalRules,
      summary
    }
  };
}

// ── Manual Sharing ────────────────────────────────────────────────────────────
export function assessManualSharing(data: { manualShares: { object: string; count: number }[] }): CategoryResult & { stats: any } {
  const findings: SharingFinding[] = [];
  const CAT = 'Manual Sharing';
  const manualShares = data.manualShares || [];
  const totalManualShares = manualShares.reduce((sum, s) => sum + (s.count || 0), 0);

  for (const share of manualShares) {
    if (share.count > 10000) {
      findings.push(createFinding(CAT, 'high',
        `${share.object} Has ${share.count.toLocaleString()} Manual Share Records`,
        `High volumes of manual sharing indicate a compensating control for a poorly designed sharing model. Manual sharing does not scale, cannot be automated, and creates significant maintenance overhead.`,
        'Identify why manual sharing is being used on this object. Replace with criteria-based sharing rules, role hierarchy adjustments, or Apex managed sharing where appropriate.',
        { count: share.count }
      ));
    } else if (share.count > 1000) {
      findings.push(createFinding(CAT, 'medium',
        `${share.object} Has ${share.count.toLocaleString()} Manual Share Records`,
        'A large number of manual shares suggests users are compensating for gaps in the sharing architecture. This creates an ongoing manual maintenance burden.',
        'Review the sharing architecture for this object. Consider whether criteria-based sharing rules could replace the manual share grants.',
        { count: share.count }
      ));
    }
  }

  return {
    category: CAT,
    score: calculateCategoryScore(findings),
    items: findings,
    stats: { totalManualShares }
  };
}

// ── Apex Sharing ──────────────────────────────────────────────────────────────
export function assessApexSharing(data: {
  withoutSharingClasses: { name: string; id: string }[];
  sharesCreatingClasses: { name: string; id: string }[];
  customSharingReasons: any[];
}): CategoryResult & { stats: any } {
  const findings: SharingFinding[] = [];
  const CAT = 'Apex Sharing';
  const withoutSharing = data.withoutSharingClasses || [];
  const customReasons = data.customSharingReasons || [];

  if (withoutSharing.length > 20) {
    findings.push(createFinding(CAT, 'high',
      `${withoutSharing.length} Apex Classes Run Without Sharing Enforcement`,
      'Classes running without sharing bypass all record-level security including OWD, sharing rules, and role hierarchy. Each class is a potential data exposure vector.',
      "Review each class. Add 'with sharing' unless there is a documented business reason for the bypass. Maintain a sharing exception register for justified cases.",
      { records: withoutSharing.slice(0, 50).map(c => ({ name: c.name, detail: 'without sharing' })) }
    ));
  } else if (withoutSharing.length > 5) {
    findings.push(createFinding(CAT, 'medium',
      `${withoutSharing.length} Apex Classes Run Without Sharing Enforcement`,
      "Classes using 'without sharing' bypass record-level security. Review each to ensure the bypass is intentional and documented.",
      "Add 'with sharing' to each class unless there is a specific, documented reason the class needs to bypass the sharing model.",
      { records: withoutSharing.map(c => ({ name: c.name, detail: 'without sharing' })) }
    ));
  }

  if (customReasons.length > 0) {
    findings.push(createFinding(CAT, 'low',
      `${customReasons.length} Custom Apex Sharing Reason${customReasons.length > 1 ? 's' : ''} Defined`,
      'Custom Apex sharing reasons indicate programmatic record sharing is in use. Ensure each reason has a corresponding active Apex class creating share records and is still needed.',
      'Audit each custom sharing reason. Remove reasons that are no longer being used by active Apex code.',
      { count: customReasons.length }
    ));
  }

  return {
    category: CAT,
    score: calculateCategoryScore(findings),
    items: findings,
    stats: {
      withoutSharingCount: withoutSharing.length,
      customReasonCount: customReasons.length
    }
  };
}

// ── Record Teams ──────────────────────────────────────────────────────────────
export function assessRecordTeams(data: {
  accountTeam: { members: any[]; enabled: boolean };
  caseTeam: { templates: any[]; enabled: boolean };
  oppTeam: { members: any[]; enabled: boolean };
}): CategoryResult & { stats: any } {
  const findings: SharingFinding[] = [];
  const CAT = 'Record Teams';

  const accountMembers = data.accountTeam?.members || [];
  const caseTemplates = data.caseTeam?.templates || [];
  const oppMembers = data.oppTeam?.members || [];

  if (accountMembers.length > 0) {
    const editMembers = accountMembers.filter(m => m.AccountAccessLevel === 'Edit');
    if (editMembers.length > accountMembers.length * 0.5) {
      findings.push(createFinding(CAT, 'medium',
        'Account Team Roles Grant Edit Access — Review Least Privilege',
        `${editMembers.length} of ${accountMembers.length} account team members have Edit access. Team members rarely need to edit the account itself — they typically need access to related records.`,
        'Review account team roles. Change Edit access to Read Only for team members who do not need to edit account fields. Use record-level sharing rules for broader access needs.',
        { count: editMembers.length }
      ));
    }
  }

  if (oppMembers.length > 0) {
    const editMembers = oppMembers.filter(m => m.OpportunityAccessLevel === 'Edit');
    if (editMembers.length > oppMembers.length * 0.5) {
      findings.push(createFinding(CAT, 'medium',
        'Opportunity Team Roles Grant Edit Access — Review Least Privilege',
        `${editMembers.length} of ${oppMembers.length} opportunity team members have Edit access. Apply least-privilege principles to team access levels.`,
        'Review opportunity team roles. Restrict edit access to team members who actively update opportunity records.',
        { count: editMembers.length }
      ));
    }
  }

  return {
    category: CAT,
    score: calculateCategoryScore(findings),
    items: findings,
    stats: {
      accountTeamEnabled: data.accountTeam?.enabled || false,
      caseTeamEnabled: data.caseTeam?.enabled || false,
      oppTeamEnabled: data.oppTeam?.enabled || false,
      accountTeamCount: accountMembers.length,
      caseTeamCount: caseTemplates.length,
      oppTeamCount: oppMembers.length
    }
  };
}

// ── Groups & Queues ───────────────────────────────────────────────────────────
export function assessGroupsQueues(data: {
  groups: any[];
  groupMemberCounts: any[];
  queues: any[];
  queueObjects: any[];
}): CategoryResult & { stats: any } {
  const findings: SharingFinding[] = [];
  const CAT = 'Groups & Queues';

  const groups: any[] = data.groups || [];
  const groupMemberCounts: any[] = data.groupMemberCounts || [];
  const queues: any[] = data.queues || [];

  const memberCountMap = new Map<string, number>(
    groupMemberCounts.map(g => [g.GroupId, g.memberCount || g.expr0 || 0])
  );

  const allInternalGroups = groups.filter(g =>
    /all\s+internal/i.test(g.Name) || g.DeveloperName === 'AllInternalUsers'
  );
  if (allInternalGroups.length > 0) {
    findings.push(createFinding(CAT, 'high',
      `${allInternalGroups.length} Public Group${allInternalGroups.length > 1 ? 's Include' : ' Includes'} All Internal Users`,
      'Public groups that contain all internal users grant org-wide access when used in sharing rules or manual shares — equivalent to making the OWD Public Read.',
      'Replace these groups in sharing rules with more targeted groups. If all-internal access is truly needed, change the OWD instead.',
      { records: allInternalGroups.map(g => ({ name: g.Name })) }
    ));
  }

  const emptyGroups = groups.filter(g => g.Type === 'Regular' && (memberCountMap.get(g.Id) || 0) === 0);
  if (emptyGroups.length > 0) {
    findings.push(createFinding(CAT, 'low',
      `${emptyGroups.length} Public Group${emptyGroups.length > 1 ? 's Have' : ' Has'} No Members`,
      'Empty public groups add administrative noise and may indicate stale configuration. Groups used in sharing rules with no members grant access to no one, which may be unintentional.',
      'Review empty groups. Delete groups that are no longer needed. Add members to groups that should be active.',
      { records: emptyGroups.slice(0, 50).map(g => ({ name: g.Name })) }
    ));
  }

  const emptyQueues = queues.filter(q => (memberCountMap.get(q.Id) || 0) === 0);
  if (emptyQueues.length > 0) {
    findings.push(createFinding(CAT, 'medium',
      `${emptyQueues.length} Queue${emptyQueues.length > 1 ? 's Have' : ' Has'} No Members — Work Items Cannot Be Assigned`,
      'Queues with no members will accumulate work items with no one to process them. This is a silent failure mode that can cause missed SLAs without any visible error.',
      'Review each empty queue. Either add members or deactivate the queue if it is no longer in use.',
      { records: emptyQueues.map(q => ({ name: q.Name })) }
    ));
  }

  const publicGroups = groups.filter(g => g.Type === 'Regular');
  return {
    category: CAT,
    score: calculateCategoryScore(findings),
    items: findings,
    stats: { publicGroupCount: publicGroups.length, queueCount: queues.length }
  };
}

// ── Permission Bypasses ───────────────────────────────────────────────────────
export function assessPermissionBypasses(data: {
  viewAllDataUsers: any[];
  modifyAllDataUsers: any[];
  viewAllObjectPerms: any[];
  modifyAllObjectPerms: any[];
}): CategoryResult & { stats: any } {
  const findings: SharingFinding[] = [];
  const CAT = 'Permission Bypasses';

  const vadUsers: any[] = data.viewAllDataUsers || [];
  const madUsers: any[] = data.modifyAllDataUsers || [];
  const viewAllPerms: any[] = data.viewAllObjectPerms || [];
  const modifyAllPerms: any[] = data.modifyAllObjectPerms || [];

  if (vadUsers.length > 5) {
    findings.push(createFinding(CAT, 'critical',
      `${vadUsers.length} Users Have View All Data — Complete Sharing Bypass`,
      'View All Data grants complete visibility of all records in the org regardless of OWD, sharing rules, role hierarchy, or any other sharing mechanism. Each user with this permission can see every record in every object.',
      'Remove View All Data from all profiles and permission sets except system administrators who genuinely require full visibility. Replace with targeted View All object-level permissions where broader access is needed.',
      { records: vadUsers.map(u => ({ name: u.Name, detail: u.Profile?.Name || 'Unknown Profile' })) }
    ));
  } else if (vadUsers.length > 0) {
    findings.push(createFinding(CAT, 'high',
      `${vadUsers.length} User${vadUsers.length > 1 ? 's Have' : ' Has'} View All Data — Complete Sharing Bypass`,
      'View All Data bypasses all record-level security. Limit this permission to only those with a genuine need for complete data visibility.',
      'Review each user with View All Data. Remove the permission where it is not strictly required.',
      { records: vadUsers.map(u => ({ name: u.Name, detail: u.Profile?.Name || 'Unknown Profile' })) }
    ));
  }

  if (madUsers.length > 5) {
    findings.push(createFinding(CAT, 'critical',
      `${madUsers.length} Users Have Modify All Data — Complete Sharing Bypass`,
      'Modify All Data allows users to create, edit, delete, and transfer ownership of all records in the org. This is one of the most powerful permissions in Salesforce and should be restricted to a tiny number of administrators.',
      'Remove Modify All Data from all but a very small number of system administrator accounts. Audit every profile and permission set granting this permission.',
      { records: madUsers.map(u => ({ name: u.Name, detail: u.Profile?.Name || 'Unknown Profile' })) }
    ));
  } else if (madUsers.length > 0) {
    findings.push(createFinding(CAT, 'high',
      `${madUsers.length} User${madUsers.length > 1 ? 's Have' : ' Has'} Modify All Data — Complete Sharing Bypass`,
      'Modify All Data bypasses all record-level security for write operations. Limit this permission to only true system administrators.',
      'Review each user with Modify All Data. Remove the permission where it is not strictly required.',
      { records: madUsers.map(u => ({ name: u.Name, detail: u.Profile?.Name || 'Unknown Profile' })) }
    ));
  }

  const viewAllObjects = new Set(viewAllPerms.map((p: any) => p.SobjectType));
  const modifyAllObjects = new Set(modifyAllPerms.map((p: any) => p.SobjectType));

  if (viewAllObjects.size > 10) {
    findings.push(createFinding(CAT, 'high',
      `View All Records Granted on ${viewAllObjects.size} Objects`,
      'Object-level View All Records bypasses sharing for individual objects. Having this granted on 10+ objects indicates broad visibility grants that may exceed what users actually need.',
      "Audit which profiles and permission sets grant View All Records on each object. Remove where users don't need full visibility.",
      { count: viewAllObjects.size }
    ));
  }

  if (modifyAllObjects.size > 5) {
    findings.push(createFinding(CAT, 'high',
      `Modify All Records Granted on ${modifyAllObjects.size} Objects`,
      'Object-level Modify All Records bypasses sharing for write operations on individual objects. Having this on 5+ objects is unusually broad.',
      'Audit which profiles and permission sets grant Modify All Records. Restrict to only objects where bulk admin access is genuinely required.',
      { count: modifyAllObjects.size }
    ));
  }

  return {
    category: CAT,
    score: calculateCategoryScore(findings),
    items: findings,
    stats: {
      vadCount: vadUsers.length,
      madCount: madUsers.length,
      viewAllObjectCount: viewAllObjects.size,
      modifyAllObjectCount: modifyAllObjects.size
    }
  };
}

// ── Implicit Sharing ──────────────────────────────────────────────────────────
export function assessImplicitSharing(data: { entities: any[] }): CategoryResult & { stats: any } {
  const findings: SharingFinding[] = [];
  const CAT = 'Implicit Sharing';
  const entities: any[] = data.entities || [];

  const byName = new Map<string, any>(entities.map(e => [e.QualifiedApiName, e]));
  const account = byName.get('Account');
  const contact = byName.get('Contact');
  const caseObj = byName.get('Case');
  const opp = byName.get('Opportunity');

  let implicitChainsActive = 0;

  if (account && contact && account.InternalSharingModel === 'Private' && contact.InternalSharingModel === 'ControlledByParent') {
    implicitChainsActive++;
    findings.push(createFinding(CAT, 'medium',
      'Contact Visibility Is Controlled by Account — Implicit Sharing Active',
      "When Contact OWD is 'Controlled by Parent', users who can see an Account automatically see all related Contacts. This implicit sharing grant can expand Contact visibility beyond what the Contact OWD alone would suggest — particularly when Account sharing rules exist.",
      "Review whether 'Controlled by Parent' is the intended behavior for Contacts. If Contacts should have tighter visibility than the Account, consider a separate Contact OWD setting with explicit sharing rules.",
      { records: [{ name: 'Contact → Account', detail: 'Controlled by Parent' }] }
    ));
  }

  if (account && caseObj && account.InternalSharingModel === 'Private' && caseObj.InternalSharingModel === 'ControlledByParent') {
    implicitChainsActive++;
    findings.push(createFinding(CAT, 'medium',
      'Case Visibility Is Controlled by Account — Implicit Sharing Active',
      "When Case OWD is 'Controlled by Parent', access to an Account automatically grants access to all related Cases. Account sharing rules or role hierarchy grants therefore also expose all Cases on that account.",
      "Evaluate whether Case visibility should be tighter than Account visibility. If Case data is more sensitive, consider a separate Case OWD and explicit Case sharing rules.",
      { records: [{ name: 'Case → Account', detail: 'Controlled by Parent' }] }
    ));
  }

  if (account && opp && account.InternalSharingModel === 'Private' && opp.InternalSharingModel === 'Private') {
    implicitChainsActive++;
    findings.push(createFinding(CAT, 'low',
      'Account-Opportunity Implicit Sharing Is Active',
      'When both Account and Opportunity are Private, Salesforce grants implicit read access to the Account for users who own a related Opportunity. This is by design but is worth documenting in the sharing architecture.',
      'Document this implicit sharing chain in your sharing architecture documentation. Ensure the sharing model accounts for this when designing Account visibility rules.',
      { records: [{ name: 'Account ← Opportunity', detail: 'Implicit read from Opp ownership' }] }
    ));
  }

  return {
    category: CAT,
    score: calculateCategoryScore(findings),
    items: findings,
    stats: { implicitChainsActive }
  };
}

// ── External & Guest Access ───────────────────────────────────────────────────
export function assessExternalAccess(data: { guestProfiles: any[]; externalEntities: any[] }): CategoryResult & { stats: any } {
  const findings: SharingFinding[] = [];
  const CAT = 'External & Guest Access';
  const guestProfiles: any[] = data.guestProfiles || [];
  const externalEntities: any[] = data.externalEntities || [];

  const rwExternalEntities = externalEntities.filter(e => e.ExternalSharingModel === 'ReadWrite');
  if (rwExternalEntities.length > 0) {
    findings.push(createFinding(CAT, 'critical',
      `${rwExternalEntities.length} Object${rwExternalEntities.length > 1 ? 's Allow' : ' Allows'} External Users to Create/Edit Records`,
      'Objects with external OWD of Public Read/Write allow Experience Cloud guest users and portal users to create or edit records. This is almost never intentional for guest users.',
      'Immediately set external OWD to Private or Public Read for these objects. If write access is needed, grant it via sharing rules scoped to authenticated portal users only.',
      { records: rwExternalEntities.map(e => ({ name: e.Label, detail: `External OWD: ${e.ExternalSharingModel}` })) }
    ));
  }

  if (guestProfiles.length > 0 && externalEntities.length > 0) {
    const readExternalEntities = externalEntities.filter(e => e.ExternalSharingModel === 'Read');
    if (readExternalEntities.length > 0) {
      findings.push(createFinding(CAT, 'high',
        `${readExternalEntities.length} Object${readExternalEntities.length > 1 ? 's Are' : ' Is'} Accessible to External/Guest Users`,
        'Objects with non-Private external OWD are accessible to Experience Cloud guest users and portal users. Review whether all of these objects should be visible to unauthenticated visitors.',
        'Review each object with a non-Private external OWD. Set to Private for objects that should not be accessible externally. Use sharing sets or sharing rules to grant access to authenticated portal users where needed.',
        { records: readExternalEntities.map(e => ({ name: e.Label, detail: `External OWD: ${e.ExternalSharingModel}` })) }
      ));
    }
  }

  return {
    category: CAT,
    score: calculateCategoryScore(findings),
    items: findings,
    stats: {
      guestEnabled: guestProfiles.length > 0,
      externalObjectCount: externalEntities.length
    }
  };
}

// ── Overall Score ─────────────────────────────────────────────────────────────
export function calculateOverallScore(categoryResults: CategoryResult[]): AssessmentResult {
  const validScores = categoryResults.map(c => c.score).filter(s => s !== null && s !== undefined);
  const overall = validScores.length > 0
    ? Math.round(validScores.reduce((a, b) => a + b, 0) / validScores.length)
    : 100;
  return {
    categories: categoryResults,
    overallScore: overall
  };
}
