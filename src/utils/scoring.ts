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

  // Controlled by Parent where parent is also Private — chain confusion
  const parentOf: Record<string, string> = { Contact: 'Account', Case: 'Account', Order: 'Account', Contract: 'Account' };
  const owdByName = new Map(entities.map((e: any) => [e.QualifiedApiName, e.InternalSharingModel]));
  const chainConfusion = entities.filter((e: any) =>
    e.InternalSharingModel === 'ControlledByParent' &&
    parentOf[e.QualifiedApiName] &&
    owdByName.get(parentOf[e.QualifiedApiName]) === 'Private'
  );
  if (chainConfusion.length > 0) {
    findings.push(createFinding(CAT, 'medium',
      `${chainConfusion.length} Object${chainConfusion.length > 1 ? 's Are' : ' Is'} Controlled by Parent With a Private Parent OWD`,
      "When a child object's OWD is 'Controlled by Parent' and the parent (Account) is Private, users can only access child records through their access to the parent. Any change to Account-level sharing rules, role hierarchy, or ownership directly affects visibility of all related child records.",
      'Document this dependency in your sharing architecture. When planning changes to Account-level sharing, evaluate the cascading impact on all child objects set to Controlled by Parent.',
      { records: chainConfusion.map((e: any) => ({ name: e.Label, detail: `Controlled by Parent → ${parentOf[e.QualifiedApiName]} is Private` })) }
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
  usersInManyTerritories?: any[];
  ruleItems?: any[];
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

  // Users in 50+ territories
  const manyTerritoryUsers = data.usersInManyTerritories || [];
  if (manyTerritoryUsers.length > 0) {
    findings.push(createFinding(CAT, 'medium',
      `${manyTerritoryUsers.length} User${manyTerritoryUsers.length > 1 ? 's Are' : ' Is'} Assigned to 50 or More Territories`,
      'Users assigned to a very large number of territories gain broad record visibility that is difficult to audit and may exceed what their role requires.',
      'Review territory assignments for these users. Consolidate access using higher-level parent territories where possible.',
      { records: manyTerritoryUsers.slice(0, 50).map((u: any) => ({ name: u.Assignee?.Name || u.AssociateId, detail: `${u.tCount || u.expr0 || '50+'} territories` })) }
    ));
  }

  // Hard-coded Salesforce IDs in assignment rule criteria
  const ruleItems = data.ruleItems || [];
  const sfIdPattern = /^[a-zA-Z0-9]{15}$|^[a-zA-Z0-9]{18}$/;
  const hardCodedItems = ruleItems.filter((item: any) => sfIdPattern.test(item.Value || ''));
  if (hardCodedItems.length > 0) {
    findings.push(createFinding(CAT, 'medium',
      `${hardCodedItems.length} Territory Assignment Rule Criteria Use Hard-Coded Record IDs`,
      'Assignment rules that filter on hard-coded record IDs will break silently when those records are deleted or when rules are migrated to another org.',
      'Replace hard-coded ID values with text or picklist field criteria.',
      { count: hardCodedItems.length }
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
export function assessSharingRules(data: { ownerRules: any[]; criteriaRules: any[]; allInternalGroupId?: string | null }, owdEntities?: any[]): CategoryResult & { stats: any } {
  const findings: SharingFinding[] = [];
  const CAT = 'Sharing Rules';

  const ownerRules: any[] = data.ownerRules || [];
  const criteriaRules: any[] = data.criteriaRules || [];
  const allInternalGroupId = data.allInternalGroupId || null;
  const totalRules = ownerRules.length + criteriaRules.length;

  const allRulesTargetingAll = [...ownerRules, ...criteriaRules].filter(r => {
    if (r.SharedToType === 'AllInternalUsers' || r.SharedToType === 'AllCustomerPortalUsers') return true;
    if (allInternalGroupId && r.SharedToId === allInternalGroupId) return true;
    if (r.SharedTo?.Type === 'AllInternalUsers') return true;
    return false;
  });
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
    if (objTotal > 250) {
      findings.push(createFinding(CAT, 'high',
        `${obj} Is Approaching the 300 Sharing Rules Per Object Platform Limit`,
        `With ${objTotal} sharing rules, ${obj} is within 50 rules of the Salesforce platform limit of 300 sharing rules per object. Reaching the limit will prevent new rules from being created and may cause org configuration errors.`,
        `Urgently audit and consolidate ${obj} sharing rules. Merge criteria-based rules where possible and review whether any rules are redundant with the role hierarchy.`,
        { count: objTotal }
      ));
    } else if (objTotal > 100) {
      findings.push(createFinding(CAT, 'medium',
        `${obj} Has ${objTotal} Sharing Rules — High Recalculation Risk`,
        `Objects with many sharing rules require more time to recalculate sharing when records change owners or when hierarchy changes occur.`,
        `Review sharing rules for ${obj}. Consolidate criteria-based rules. Consider whether some access can be granted through the role hierarchy instead.`,
        { count: objTotal }
      ));
    }
    if (counts.criteriaCount > 40) {
      findings.push(createFinding(CAT, 'medium',
        `${obj} Is Approaching the 50 Criteria-Based Sharing Rule Per Object Limit`,
        `${obj} has ${counts.criteriaCount} criteria-based sharing rules, approaching the platform limit of 50 per object. Exceeding this limit blocks creation of further criteria-based rules.`,
        `Review and consolidate criteria-based sharing rules for ${obj}. Combine overlapping criteria where possible.`,
        { count: counts.criteriaCount }
      ));
    }
  });

  // Restriction rules inventory
  const restrictionRules: any[] = (data as any).restrictionRules || [];
  if (restrictionRules.length > 0) {
    findings.push(createFinding(CAT, 'low',
      `${restrictionRules.length} Restriction Rule${restrictionRules.length > 1 ? 's Are' : ' Is'} Configured`,
      'Restriction rules further limit record visibility below what OWD settings allow. They are powerful but can have unexpected side effects if not carefully documented and reviewed.',
      'Document all restriction rules in your sharing architecture. Confirm each rule is still intentional and correctly scoped. Test that the intended users can still access required records.',
      { records: restrictionRules.map((r: any) => ({ name: r.DeveloperName, detail: r.EntityDefinition?.QualifiedApiName || 'Unknown Object' })) }
    ));
  } else {
    findings.push(createFinding(CAT, 'low',
      'No Restriction Rules Configured — Evaluate Opportunity',
      'Restriction rules allow limiting record visibility below OWD for specific user groups. If any objects have users who should see fewer records than the OWD grants, restriction rules may be appropriate.',
      'Evaluate whether any object would benefit from restriction rules to limit access for specific profiles or permission sets. Particularly useful for compliance-sensitive data.',
      {}
    ));
  }

  // Redundant sharing rules where OWD is already Public Read/Write
  if (owdEntities && owdEntities.length > 0) {
    const publicOwdObjects = new Set(owdEntities.filter((e: any) => e.InternalSharingModel === 'ReadWrite').map((e: any) => e.QualifiedApiName));
    const redundantRuleObjects = Array.from(rulesByObject.keys()).filter(obj => publicOwdObjects.has(obj));
    if (redundantRuleObjects.length > 0) {
      findings.push(createFinding(CAT, 'medium',
        `${redundantRuleObjects.length} Object${redundantRuleObjects.length > 1 ? 's Have' : ' Has'} Sharing Rules But OWD Is Already Public Read/Write`,
        'Sharing rules on objects where the OWD is Public Read/Write have no effect — all internal users can already see and edit all records. These rules add sharing recalculation overhead without providing any access control benefit.',
        'Delete sharing rules on objects where the internal OWD is Public Read/Write. If the intent is to restrict access, first change the OWD to Private and then implement targeted sharing rules.',
        { records: redundantRuleObjects.map(obj => ({ name: obj, detail: `OWD: Public Read/Write, rules: ${(rulesByObject.get(obj)?.ownerCount || 0) + (rulesByObject.get(obj)?.criteriaCount || 0)}` })) }
      ));
    }
  }

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
export function assessManualSharing(data: { manualShares: { object: string; count: number }[] }, owdEntities?: any[]): CategoryResult & { stats: any } {
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

  // Private OWD + high manual sharing = compensating pattern
  if (owdEntities && owdEntities.length > 0) {
    const privateOwdObjects = new Set(owdEntities.filter((e: any) => e.InternalSharingModel === 'Private').map((e: any) => e.QualifiedApiName));
    const compensatingObjects = manualShares.filter(s => s.count > 500 && privateOwdObjects.has(s.object));
    if (compensatingObjects.length > 0) {
      findings.push(createFinding(CAT, 'high',
        `${compensatingObjects.length} Object${compensatingObjects.length > 1 ? 's Have' : ' Has'} Private OWD But High Manual Sharing Volume — Compensating Pattern Detected`,
        'When an object has a Private OWD but high volumes of manual shares, it indicates users are manually granting access because the sharing model does not provide it automatically.',
        'Analyze who is performing manual shares and why. Design sharing rules, role hierarchy adjustments, or Apex sharing to replace manual grants with automated access.',
        { records: compensatingObjects.map(s => ({ name: s.object, detail: `${s.count.toLocaleString()} manual shares, OWD: Private` })) }
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
  apexShareVolumes?: { object: string; reasons: { reason: string; count: number }[] }[];
}): CategoryResult & { stats: any } {
  const findings: SharingFinding[] = [];
  const CAT = 'Apex Sharing';
  const withoutSharing = data.withoutSharingClasses || [];
  const customReasons = data.customSharingReasons || [];
  const noSharingDecl: { name: string; id: string }[] = (data as any).noSharingDeclarationClasses || [];

  if (noSharingDecl.length > 50) {
    findings.push(createFinding(CAT, 'high',
      `${noSharingDecl.length} Apex Classes Have No Sharing Declaration`,
      "Apex classes with no sharing declaration default to 'without sharing' behavior in many execution contexts. Each undeclared class is a potential data exposure vector where record-level security is silently bypassed.",
      "Explicitly declare 'with sharing', 'without sharing', or 'inherited sharing' on every class. 'inherited sharing' is the safest default when the correct context is unknown.",
      { records: noSharingDecl.slice(0, 50).map(c => ({ name: c.name, detail: 'No sharing declaration' })) }
    ));
  } else if (noSharingDecl.length > 0) {
    findings.push(createFinding(CAT, 'medium',
      `${noSharingDecl.length} Apex Class${noSharingDecl.length > 1 ? 'es Have' : ' Has'} No Sharing Declaration`,
      "Apex classes with no sharing declaration inherit the sharing context of their caller, which can lead to unexpected data access when the class is invoked from different entry points.",
      "Add 'with sharing', 'without sharing', or 'inherited sharing' to each class. This makes the sharing behavior explicit and auditable.",
      { records: noSharingDecl.map(c => ({ name: c.name, detail: 'No sharing declaration' })) }
    ));
  }

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

  // Apex-managed share volume
  const shareVolumes = data.apexShareVolumes || [];
  const highVolumeApexShares = shareVolumes.filter(s => s.reasons.some((r: any) => r.count > 5000));
  if (highVolumeApexShares.length > 0) {
    findings.push(createFinding(CAT, 'medium',
      `Apex-Managed Share Records Exceed 5,000 on ${highVolumeApexShares.length} Object${highVolumeApexShares.length > 1 ? 's' : ''}`,
      'Large volumes of Apex-managed share records indicate the org relies heavily on programmatic sharing. High share record counts can slow sharing recalculation and increase storage usage.',
      'Review the Apex classes creating these share records. Evaluate whether criteria-based sharing rules could replace some Apex sharing to reduce volume.',
      { records: highVolumeApexShares.map(s => ({ name: s.object, detail: s.reasons.map((r: any) => `${r.reason}: ${r.count.toLocaleString()}`).join(', ') })) }
    ));
  }

  // Zombie sharing reasons — defined but no class creating them
  if (customReasons.length > 0 && data.sharesCreatingClasses && data.sharesCreatingClasses.length > 0) {
    const creatingClassNames = data.sharesCreatingClasses.map((c: any) => c.name.toLowerCase()).join(' ');
    const zombieReasons = customReasons.filter((r: any) =>
      !creatingClassNames.includes((r.DeveloperName || '').toLowerCase())
    );
    if (zombieReasons.length > 0) {
      findings.push(createFinding(CAT, 'low',
        `${zombieReasons.length} Custom Sharing Reason${zombieReasons.length > 1 ? 's Have' : ' Has'} No Corresponding Active Apex Class`,
        'Custom Apex sharing reasons that are not referenced by any active Apex class are zombie configuration — they exist in the org but serve no current purpose.',
        'Review each sharing reason. Delete reasons that are no longer used.',
        { records: zombieReasons.map((r: any) => ({ name: r.Label || r.DeveloperName, detail: 'No matching Apex class found' })) }
      ));
    }
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
}, owdEntities?: any[]): CategoryResult & { stats: any } {
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

  // Case teams + Private Case OWD — compensating control check
  if (owdEntities && owdEntities.length > 0 && data.caseTeam?.enabled && caseTemplates.length > 0) {
    const caseEntity = owdEntities.find((e: any) => e.QualifiedApiName === 'Case');
    if (caseEntity && caseEntity.InternalSharingModel === 'Private') {
      findings.push(createFinding(CAT, 'medium',
        'Case Teams Are Active with Private Case OWD — Review Access Patterns',
        `Case teams are in use and Case OWD is Private. While case teams are a legitimate access mechanism, they can become the primary way Case records are shared — creating an administrative burden and making Case access difficult to audit systematically.`,
        'Review case team templates. Evaluate whether criteria-based sharing rules could replace manual case team membership for predictable access patterns. Reserve case teams for exceptions that sharing rules cannot address.',
        { count: caseTemplates.length }
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
}, owdEntities?: any[]): CategoryResult & { stats: any } {
  const findings: SharingFinding[] = [];
  const CAT = 'Groups & Queues';

  const groups: any[] = data.groups || [];
  const groupMemberCounts: any[] = data.groupMemberCounts || [];
  const queues: any[] = data.queues || [];

  const memberCountMap = new Map<string, number>(
    groupMemberCounts.map(g => [g.GroupId, g.memberCount || g.expr0 || 0])
  );

  const allInternalGroups = groups.filter(g =>
    g.DeveloperName === 'AllInternalUsers' || g.DeveloperName === 'AllCustomerPortalUsers'
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

  // Queues on Public OWD objects — redundant sharing pattern
  if (owdEntities && owdEntities.length > 0 && data.queueObjects && data.queueObjects.length > 0) {
    const publicOwdNames = new Set(
      owdEntities
        .filter((e: any) => e.InternalSharingModel === 'Public' || e.InternalSharingModel === 'ReadWrite')
        .map((e: any) => e.QualifiedApiName)
    );
    const queuesOnPublicObjects = data.queueObjects.filter((qo: any) => publicOwdNames.has(qo.SobjectType));
    if (queuesOnPublicObjects.length > 0) {
      const uniqueObjects = [...new Set(queuesOnPublicObjects.map((qo: any) => qo.SobjectType))];
      findings.push(createFinding(CAT, 'low',
        `Queues Configured on Public OWD Objects — Redundant Access Mechanism`,
        `Queues exist for ${uniqueObjects.length} object${uniqueObjects.length > 1 ? 's' : ''} that already have Public internal OWD. Since all users can already read these records, queue membership grants no additional visibility — the configuration is redundant.`,
        'Review whether queues on Public OWD objects serve a workflow routing purpose (valid) or were created under the assumption that they grant visibility (not needed). Clean up queues that serve no routing function.',
        { records: uniqueObjects.map(o => ({ name: o as string, detail: 'Public OWD — queue visibility redundant' })) }
      ));
    }
  }

  // Queue DoesIncludeBosses on Private OWD objects
  if (owdEntities && owdEntities.length > 0 && queues.length > 0) {
    const privateOwdQualNames = new Set(
      owdEntities
        .filter((e: any) => e.InternalSharingModel === 'Private')
        .map((e: any) => e.QualifiedApiName)
    );
    const queueObjectMap = new Map<string, string[]>();
    for (const qo of (data.queueObjects || [])) {
      const existing = queueObjectMap.get(qo.QueueId) || [];
      queueObjectMap.set(qo.QueueId, [...existing, qo.SobjectType]);
    }
    const queuesWithBossesOnPrivate = queues.filter((q: any) => {
      if (!q.DoesIncludeBosses) return false;
      const qObjs = queueObjectMap.get(q.Id) || [];
      return qObjs.some((obj: string) => privateOwdQualNames.has(obj));
    });
    if (queuesWithBossesOnPrivate.length > 0) {
      findings.push(createFinding(CAT, 'medium',
        `${queuesWithBossesOnPrivate.length} Queue${queuesWithBossesOnPrivate.length > 1 ? 's Have' : ' Has'} "Include Bosses" Enabled on Private OWD Objects`,
        '"Include Bosses in Queue" causes all role hierarchy superiors of queue members to also gain visibility to queue records. On Private OWD objects, this can unexpectedly expose records to senior managers who were not intended to see them.',
        'Review queue settings. Disable "Include Bosses" unless role hierarchy visibility is explicitly required. If visibility is needed for managers, consider sharing rules instead.',
        { records: queuesWithBossesOnPrivate.map((q: any) => ({ name: q.Name, detail: 'DoesIncludeBosses = true, object has Private OWD' })) }
      ));
    }
  }

  // Nested public groups
  const nestedGroupMembers: any[] = (data as any).nestedGroupMembers || [];
  if (nestedGroupMembers.length > 5) {
    findings.push(createFinding(CAT, 'medium',
      `${nestedGroupMembers.length} Nested Group Memberships Detected`,
      'Public groups that contain other groups as members create complex, difficult-to-audit membership chains. When used in sharing rules, the actual set of users receiving access can be opaque and may expand unexpectedly when parent group membership changes.',
      'Document nested group structures. Flatten where possible. Conduct periodic audits of effective membership for groups used in sharing rules.',
      { count: nestedGroupMembers.length }
    ));
  } else if (nestedGroupMembers.length > 0) {
    findings.push(createFinding(CAT, 'low',
      `${nestedGroupMembers.length} Nested Group Membership${nestedGroupMembers.length > 1 ? 's' : ''} Detected`,
      'Groups containing other groups as members create membership chains that require careful documentation to audit effectively.',
      'Review nested group structures and document the effective membership for groups used in sharing rules.',
      { count: nestedGroupMembers.length }
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
  totalActiveUsers?: number;
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
      { records: vadUsers.map(u => ({ name: u.Name, detail: `${u.Profile?.Name || 'Unknown'} (${(u as any).grantSource || 'Profile'})` })) }
    ));
  } else if (vadUsers.length > 0) {
    findings.push(createFinding(CAT, 'high',
      `${vadUsers.length} User${vadUsers.length > 1 ? 's Have' : ' Has'} View All Data — Complete Sharing Bypass`,
      'View All Data bypasses all record-level security. Limit this permission to only those with a genuine need for complete data visibility.',
      'Review each user with View All Data. Remove the permission where it is not strictly required.',
      { records: vadUsers.map(u => ({ name: u.Name, detail: `${u.Profile?.Name || 'Unknown'} (${(u as any).grantSource || 'Profile'})` })) }
    ));
  }

  if (madUsers.length > 5) {
    findings.push(createFinding(CAT, 'critical',
      `${madUsers.length} Users Have Modify All Data — Complete Sharing Bypass`,
      'Modify All Data allows users to create, edit, delete, and transfer ownership of all records in the org. This is one of the most powerful permissions in Salesforce and should be restricted to a tiny number of administrators.',
      'Remove Modify All Data from all but a very small number of system administrator accounts. Audit every profile and permission set granting this permission.',
      { records: madUsers.map(u => ({ name: u.Name, detail: `${u.Profile?.Name || 'Unknown'} (${(u as any).grantSource || 'Profile'})` })) }
    ));
  } else if (madUsers.length > 0) {
    findings.push(createFinding(CAT, 'high',
      `${madUsers.length} User${madUsers.length > 1 ? 's Have' : ' Has'} Modify All Data — Complete Sharing Bypass`,
      'Modify All Data bypasses all record-level security for write operations. Limit this permission to only true system administrators.',
      'Review each user with Modify All Data. Remove the permission where it is not strictly required.',
      { records: madUsers.map(u => ({ name: u.Name, detail: `${u.Profile?.Name || 'Unknown'} (${(u as any).grantSource || 'Profile'})` })) }
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

  // 5% bypass threshold check
  if (data.totalActiveUsers && data.totalActiveUsers > 0) {
    const totalBypasses = new Set([...vadUsers.map(u => u.Id), ...madUsers.map(u => u.Id)]).size;
    const bypassPct = totalBypasses / data.totalActiveUsers;
    if (bypassPct > 0.05) {
      findings.push(createFinding(CAT, 'high',
        `${Math.round(bypassPct * 100)}% of Active Users Have Org-Wide Sharing Bypass Permissions`,
        `${totalBypasses} of ${data.totalActiveUsers} active users hold View All Data or Modify All Data. When more than 5% of users bypass record-level security, the sharing model provides limited real protection.`,
        'Establish a target of fewer than 5 named system admin accounts with these permissions. Migrate over-privileged users to object-level View All / Modify All permissions where broader access is genuinely needed.',
        { count: totalBypasses }
      ));
    }
  }

  // Profile vs Permission Set breakdown — flag if Permission Set grants are the majority
  if (vadUsers.length > 0 || madUsers.length > 0) {
    const allBypassUsers = [...vadUsers, ...madUsers];
    const permSetGrants = allBypassUsers.filter((u: any) => u.grantSource === 'Permission Set').length;
    if (permSetGrants > allBypassUsers.length * 0.5) {
      findings.push(createFinding(CAT, 'medium',
        `Majority of Sharing Bypass Grants Are via Permission Sets — Harder to Audit`,
        `${permSetGrants} of ${allBypassUsers.length} bypass grants come from Permission Sets rather than Profiles. Permission Set assignments are harder to audit at scale and can proliferate over time.`,
        'Review all Permission Set assignments granting VAD/MAD. Consider consolidating to Profile-based grants for the small number of users who truly need these permissions, making the grant list easier to audit and govern.',
        { count: permSetGrants }
      ));
    }
  }

  // Permission Set Groups
  const psgCount: number = (data as any).permissionSetGroupCount || 0;
  if (psgCount === 0) {
    findings.push(createFinding(CAT, 'medium',
      'No Permission Set Groups Defined — Consider Adopting for Access Governance',
      'Permission Set Groups bundle related permission sets into a single assignment, reducing assignment sprawl and making it easier to audit who has access to what. Orgs without PSGs tend to accumulate many individual permission set assignments that are hard to govern.',
      'Define Permission Set Groups for common job functions. This simplifies assignment management, reduces the risk of over-permissioning, and makes access audits faster and more reliable.',
      {}
    ));
  }

  // Author Apex and Manage Users — high-risk admin permissions
  const authorApexUsers: any[] = (data as any).authorApexUsers || [];
  const manageUsersUsersList: any[] = (data as any).manageUsersUsers || [];
  const highRiskUserMap = new Map<string, { Id: string; Name: string; permissions: string[] }>();
  for (const u of authorApexUsers) {
    highRiskUserMap.set(u.Id, { Id: u.Id, Name: u.Name, permissions: ['Author Apex'] });
  }
  for (const u of manageUsersUsersList) {
    if (highRiskUserMap.has(u.Id)) {
      highRiskUserMap.get(u.Id)!.permissions.push('Manage Users');
    } else {
      highRiskUserMap.set(u.Id, { Id: u.Id, Name: u.Name, permissions: ['Manage Users'] });
    }
  }
  const highRiskUserList = Array.from(highRiskUserMap.values());
  if (highRiskUserList.length > 10) {
    findings.push(createFinding(CAT, 'high',
      `${highRiskUserList.length} Users Hold High-Risk Admin Permissions (Author Apex / Manage Users)`,
      "Author Apex allows writing code that can bypass the sharing model using 'without sharing'. Manage Users allows changing other users' profiles and permission assignments, enabling privilege escalation. Having these widely granted significantly weakens sharing governance.",
      'Restrict Author Apex to a small number of certified developers. Restrict Manage Users to dedicated user-admin accounts. Review all holders and remove from anyone who no longer requires it.',
      { records: highRiskUserList.slice(0, 50).map(u => ({ name: u.Name, detail: u.permissions.join(', ') })) }
    ));
  } else if (highRiskUserList.length > 0) {
    findings.push(createFinding(CAT, 'medium',
      `${highRiskUserList.length} User${highRiskUserList.length > 1 ? 's Hold' : ' Holds'} High-Risk Admin Permissions (Author Apex / Manage Users)`,
      "Author Apex and Manage Users can be used to circumvent or manipulate the sharing model. Even a small number of holders warrants review.",
      "Review each user. Confirm Author Apex is restricted to developers who actively write code. Confirm Manage Users is restricted to designated user administrators.",
      { records: highRiskUserList.map(u => ({ name: u.Name, detail: u.permissions.join(', ') })) }
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
export function assessExternalAccess(data: { guestProfiles: any[]; externalEntities: any[]; sharingSets?: any[] }): CategoryResult & { stats: any } {
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

  // High-volume portal user sharing sets
  const sharingSets: any[] = data.sharingSets || [];
  if (sharingSets.length > 0) {
    findings.push(createFinding(CAT, 'medium',
      `${sharingSets.length} Sharing Set${sharingSets.length > 1 ? 's' : ''} Grant Access to High-Volume Portal Users`,
      'Sharing sets grant record access to High-Volume Portal (HVP) users based on field relationships — these users are excluded from the standard sharing model. Sharing sets can grant broad access if the access-mapping field is widely populated.',
      'Review each sharing set. Confirm the access mapping field correctly scopes access. Ensure the access level (Read vs Read/Write) matches the minimum necessary for the portal use case.',
      { records: sharingSets.map((s: any) => ({ name: s.name || s.Name, detail: `${s.accessLevel || 'Unknown'} access` })) }
    ));
  }

  return {
    category: CAT,
    score: calculateCategoryScore(findings),
    items: findings,
    stats: {
      guestEnabled: guestProfiles.length > 0,
      externalObjectCount: externalEntities.length,
      sharingSetsCount: sharingSets.length
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
