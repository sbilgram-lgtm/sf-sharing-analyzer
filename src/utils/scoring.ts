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

  // ── Ownership Skew ──────────────────────────────────────────────────────────
  const ownershipSkew: any[] = (data as any).ownershipSkew || [];
  const skewedWithNonPrivateOwd = ownershipSkew.filter(obj => {
    const owd = owdByName.get(obj.object);
    return obj.skewedOwners.length > 0 && owd && owd !== 'Private' && owd !== 'ControlledByParent';
  });
  if (skewedWithNonPrivateOwd.length > 0) {
    findings.push(createFinding(CAT, 'high',
      `Ownership Skew on ${skewedWithNonPrivateOwd.length} Non-Private Object${skewedWithNonPrivateOwd.length > 1 ? 's' : ''} — Sharing Recalculation Risk`,
      'A single user owns over 10,000 records on an object with non-Private OWD. Ownership skew causes extremely long sharing recalculations when the skewed owner changes roles, is deactivated, or records are mass-transferred.',
      'Redistribute record ownership across queues or business unit users. Avoid mass-parking records on a single user. Any ownership transfer or role change for the skewed owner must be planned with recalculation impact analysis.',
      { records: skewedWithNonPrivateOwd.flatMap(obj => obj.skewedOwners.map((o: any) => ({ name: obj.object, detail: `${o.ownerName}: ${o.count.toLocaleString()} records, OWD: ${owdByName.get(obj.object)}` }))) }
    ));
  }

  const skewedPrivateOnly = ownershipSkew.filter(obj => {
    const owd = owdByName.get(obj.object);
    return obj.skewedOwners.length > 0 && (owd === 'Private' || owd === 'ControlledByParent') &&
      !skewedWithNonPrivateOwd.find(s => s.object === obj.object);
  });
  if (skewedPrivateOnly.length > 0) {
    findings.push(createFinding(CAT, 'medium',
      `Ownership Skew on ${skewedPrivateOnly.length} Private OWD Object${skewedPrivateOnly.length > 1 ? 's' : ''} — Lock and Recalculation Risk`,
      'Ownership skew on Private OWD objects can cause UNABLE TO LOCK ROW errors on the skewed owner\'s records, slow sharing recalculations on ownership changes, and serialized integration processing.',
      'Confirm whether concentrated ownership is intentional (integration or archival owner). If records should be distributed, plan a phased reassignment with locking and recalculation impact analysis.',
      { records: skewedPrivateOnly.flatMap(obj => obj.skewedOwners.map((o: any) => ({ name: obj.object, detail: `${o.ownerName}: ${o.count.toLocaleString()} records` }))) }
    ));
  }

  // ── LDV + Non-Private OWD ───────────────────────────────────────────────────
  const recordCounts: any[] = (data as any).recordCounts || [];
  const ldvNonPrivate = recordCounts.filter(r => {
    const owd = owdByName.get(r.object);
    return r.count > 1000000 && owd && owd !== 'Private' && owd !== 'ControlledByParent';
  });
  if (ldvNonPrivate.length > 0) {
    findings.push(createFinding(CAT, 'critical',
      `${ldvNonPrivate.length} High-Volume Object${ldvNonPrivate.length > 1 ? 's Have' : ' Has'} Non-Private OWD — Severe Sharing Recalculation Risk`,
      'Objects with over 1 million records and a non-Private OWD trigger very long sharing recalculations on any role hierarchy change, sharing rule edit, or mass ownership transfer. These recalculations can block or slow the entire org for hours.',
      'Evaluate moving these objects to Private OWD with targeted sharing rules. Any sharing model change on high-volume objects must be planned with full recalculation time estimates and tested in a full-size sandbox.',
      { records: ldvNonPrivate.map(r => ({ name: r.object, detail: `${r.count.toLocaleString()} records, OWD: ${owdByName.get(r.object)}` })) }
    ));
  }

  const ldvPrivate = recordCounts.filter(r => {
    const owd = owdByName.get(r.object);
    return r.count > 1000000 && (owd === 'Private' || owd === 'ControlledByParent');
  });
  if (ldvPrivate.length > 0) {
    findings.push(createFinding(CAT, 'medium',
      `${ldvPrivate.length} High-Volume Object${ldvPrivate.length > 1 ? 's' : ''} with Private OWD — Monitor Recalculation Performance`,
      'Large data volume objects with Private OWD still trigger sharing recalculation on ownership changes. At this scale, even planned operations like mass transfers or role changes can create hours-long async sharing queues.',
      'Establish baseline recalculation times. Plan any sharing model changes with full-size sandbox testing. Monitor ownership distribution to prevent skew.',
      { records: ldvPrivate.map(r => ({ name: r.object, detail: `${r.count.toLocaleString()} records, OWD: ${owdByName.get(r.object)}` })) }
    ));
  }

  // ── Grant Access Using Hierarchies ──────────────────────────────────────────
  const gauhDisabled = entities.filter((e: any) => e.GrantAccessUsingHierarchies === false);
  const gauhPrivate = gauhDisabled.filter((e: any) => e.InternalSharingModel === 'Private');
  const gauhOther = gauhDisabled.filter((e: any) => e.InternalSharingModel !== 'Private' && e.InternalSharingModel !== 'ReadWrite' && e.InternalSharingModel !== 'ControlledByParent');
  if (gauhPrivate.length > 0) {
    findings.push(createFinding(CAT, 'high',
      `${gauhPrivate.length} Object${gauhPrivate.length > 1 ? 's Have' : ' Has'} Private OWD With "Grant Access Using Hierarchies" Disabled`,
      'When GAUH is disabled on a Private OWD object, the role hierarchy grants no record access at all — only the record owner and users with explicit sharing grants can see the record. Managers cannot see their team\'s records. This is almost always unintentional and can cause significant access gaps.',
      'Review each object. If managers should see subordinates\' records (the typical expectation), re-enable GAUH. If the restriction is intentional, document it explicitly in your sharing architecture.',
      { records: gauhPrivate.map((e: any) => ({ name: e.Label, detail: 'Private OWD, GAUH disabled — managers see no subordinate records' })) }
    ));
  }
  if (gauhOther.length > 0) {
    findings.push(createFinding(CAT, 'medium',
      `${gauhOther.length} Object${gauhOther.length > 1 ? 's Have' : ' Has'} "Grant Access Using Hierarchies" Disabled — Role Hierarchy Grants No Access`,
      'With GAUH disabled, the role hierarchy does not grant access to records on these objects. Users above the owner in the hierarchy must have explicit sharing grants to view or edit records.',
      'Confirm this setting is intentional. If role-based access is expected, re-enable GAUH. If disabled for compliance reasons, ensure sharing rules or explicit grants are in place for all required access paths.',
      { records: gauhOther.map((e: any) => ({ name: e.Label, detail: `OWD: ${e.InternalSharingModel}, GAUH disabled` })) }
    ));
  }

  // ── Custom objects with Controlled by Parent OWD ─────────────────────────
  const customCbP = entities.filter((e: any) => e.IsCustom === true && e.InternalSharingModel === 'ControlledByParent');
  if (customCbP.length > 0) {
    findings.push(createFinding(CAT, 'low',
      `${customCbP.length} Custom Object${customCbP.length > 1 ? 's Use' : ' Uses'} Controlled by Parent OWD — Sharing Delegated to Parent Record`,
      'These custom objects have a master-detail relationship and inherit record access from their parent. Any change to the parent\'s sharing model — OWD, sharing rules, ownership, or role hierarchy — directly and immediately affects visibility of all child records on these objects.',
      'Document these parent-child dependencies in your sharing architecture. When planning changes to parent object sharing (especially Account, Opportunity, or Case), evaluate the cascading impact on all Controlled by Parent children.',
      { records: customCbP.map((e: any) => ({ name: e.Label, detail: 'Custom object, sharing controlled by parent' })) }
    ));
  }

  // ── Split internal vs external OWD ──────────────────────────────────────
  const permOrder: Record<string, number> = { ReadWrite: 3, Read: 2, Private: 1 };
  const splitOwd = entities.filter((e: any) => {
    const intP = permOrder[e.InternalSharingModel] || 0;
    const extP = permOrder[e.ExternalSharingModel] || 0;
    return extP > 0 && extP < intP;
  });
  if (splitOwd.length > 0) {
    findings.push(createFinding(CAT, 'low',
      `${splitOwd.length} Object${splitOwd.length > 1 ? 's Have' : ' Has'} a Stricter External OWD Than Internal OWD — Split Access Model in Place`,
      'These objects allow broader access for internal users than for Experience Cloud or portal users. This is intentional security-by-design when configured deliberately, but should be reviewed periodically to confirm the split remains appropriate and portal users aren\'t inadvertently blocked.',
      'Review each split-OWD object. Confirm the external restriction is intentional. Document which portal user types are affected and how they are granted access (sharing sets, sharing rules) where needed.',
      { records: splitOwd.map((e: any) => ({ name: e.Label, detail: `Internal: ${e.InternalSharingModel}, External: ${e.ExternalSharingModel}` })) }
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
export function assessSharingRules(data: { ownerRules: any[]; criteriaRules: any[]; allInternalGroupId?: string | null; groupsWithRoleMembers?: string[] }, owdEntities?: any[]): CategoryResult & { stats: any } {
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

  // Scoping rules inventory
  const scopingRules: any[] = (data as any).scopingRules || [];
  if (scopingRules.length > 0) {
    const byObject = new Map<string, number>();
    scopingRules.forEach((r: any) => {
      const obj = r.EntityDefinition?.QualifiedApiName || 'Unknown';
      byObject.set(obj, (byObject.get(obj) || 0) + 1);
    });
    findings.push(createFinding(CAT, 'low',
      `${scopingRules.length} Scoping Rule${scopingRules.length > 1 ? 's Are' : ' Is'} Defined — Confirm Not Used as Security Boundary`,
      'Scoping rules control which records users see in supported UI list contexts (list views, related lists) but do not restrict record access in reports, SOQL, SOSL, APIs, or search. They are a user-experience control, not a security control. If scoping rules are being relied upon to restrict data access, this represents a security gap.',
      'Review each scoping rule. Confirm it is documented as a UI productivity control only. Ensure any data security requirement is enforced through OWD, sharing rules, restriction rules, or field-level security — not scoping rules.',
      { records: Array.from(byObject.entries()).map(([obj, count]) => ({ name: obj, detail: `${count} scoping rule${count > 1 ? 's' : ''}` })) }
    ));
  }

  // Objects with only owner-based sharing rules — less adaptive to data changes
  const ownerOnlyObjects = Array.from(rulesByObject.entries())
    .filter(([, counts]) => counts.ownerCount >= 3 && counts.criteriaCount === 0)
    .map(([obj]) => obj);
  if (ownerOnlyObjects.length > 0) {
    findings.push(createFinding(CAT, 'low',
      `${ownerOnlyObjects.length} Object${ownerOnlyObjects.length > 1 ? 's Rely' : ' Relies'} Exclusively on Owner-Based Sharing Rules`,
      'Owner-based sharing rules grant access based on record ownership only — they cannot respond to field value changes. If records change status, territory, or classification and need different access, only criteria-based rules can react automatically.',
      'Evaluate whether any of these objects would benefit from criteria-based sharing rules that respond to field values (e.g., share a Case when Status = \'Escalated\'). Owner-based rules remain valid but should be the deliberate choice, not the default.',
      { records: ownerOnlyObjects.map(obj => { const c = rulesByObject.get(obj)!; return { name: obj, detail: `${c.ownerCount} owner-based rule${c.ownerCount > 1 ? 's' : ''}, 0 criteria-based` }; }) }
    ));
  }

  // Objects with many criteria-based sharing rules but no restriction rules — potential over-sharing
  const restrictionRulesByObject = new Set<string>(
    (restrictionRules as any[]).map((r: any) => r.EntityDefinition?.QualifiedApiName).filter(Boolean)
  );
  const criteriaHeavyNoRestriction = Array.from(rulesByObject.entries())
    .filter(([obj, counts]) => counts.criteriaCount >= 5 && !restrictionRulesByObject.has(obj));
  if (criteriaHeavyNoRestriction.length > 0) {
    findings.push(createFinding(CAT, 'low',
      `${criteriaHeavyNoRestriction.length} Object${criteriaHeavyNoRestriction.length > 1 ? 's Have' : ' Has'} 5+ Criteria-Based Sharing Rules But No Restriction Rules`,
      'Many criteria-based sharing rules indicate complex, additive access grants with multiple paths that open record visibility. Without restriction rules to provide a counterbalancing narrowing filter, the cumulative effect may grant broader access than intended.',
      'Evaluate whether restriction rules could simplify the sharing model for these objects — restricting a subset of users from seeing records that OWD or sharing rules would otherwise expose. Restriction rules work independently of OWD and can significantly reduce audit complexity.',
      { records: criteriaHeavyNoRestriction.map(([obj, counts]) => ({ name: obj, detail: `${counts.criteriaCount} criteria-based rules, no restriction rules` })) }
    ));
  }

  // Sharing rules targeting public groups that contain role-type group members
  const groupsWithRoleMembers = new Set<string>(data.groupsWithRoleMembers || []);
  if (groupsWithRoleMembers.size > 0) {
    const rulesTargetingRoleGroups = [...ownerRules, ...criteriaRules].filter(r =>
      r.SharedToType === 'Group' && groupsWithRoleMembers.has(r.SharedToId)
    );
    if (rulesTargetingRoleGroups.length > 0) {
      const byObject = new Map<string, number>();
      rulesTargetingRoleGroups.forEach((r: any) => {
        const obj = r.EntityDefinition?.QualifiedApiName || 'Unknown';
        byObject.set(obj, (byObject.get(obj) || 0) + 1);
      });
      findings.push(createFinding(CAT, 'medium',
        `${rulesTargetingRoleGroups.length} Sharing Rule${rulesTargetingRoleGroups.length > 1 ? 's Target' : ' Targets'} Public Groups That Contain Role or Role Hierarchy Members`,
        'Public groups used as sharing rule targets that contain role-type groups expose records to every user in those role branches — including future users added to those roles. The effective audience expands automatically as role membership changes, making the true set of users with access difficult to audit.',
        'Review the membership of each targeted public group. If role-hierarchy exposure is broader than intended, replace role-type group members with explicit user or profile-based members. Document why each role branch needs access to the affected objects.',
        { records: Array.from(byObject.entries()).map(([obj, cnt]) => ({ name: obj, detail: `${cnt} rule${cnt > 1 ? 's' : ''} targeting groups with role members` })) }
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
export function assessManualSharing(
  data: {
    manualShares: { object: string; count: number }[];
    fullAccessShares?: { object: string; count: number }[];
    roleShares?: { object: string; count: number }[];
    inactiveShares?: { object: string; count: number }[];
  },
  owdEntities?: any[],
  sharingRuleData?: { ownerRules: any[]; criteriaRules: any[] }
): CategoryResult & { stats: any } {
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

  // Full Access manual shares — grantee can re-share
  const fullAccessShares = data.fullAccessShares || [];
  const fullAccessObjects = fullAccessShares.filter(s => s.count > 0);
  if (fullAccessObjects.length > 0) {
    const totalFull = fullAccessObjects.reduce((sum, s) => sum + s.count, 0);
    findings.push(createFinding(CAT, 'high',
      `${totalFull.toLocaleString()} Manual Share${totalFull > 1 ? 's' : ''} Grant Full Access — Recipients Can Re-Share Records`,
      'Full Access (owner-level) manual shares allow the grantee to share the record with additional users, transfer ownership, and in some cases delete the record. This creates an uncontrolled sharing escalation path that bypasses the intended access model.',
      'Review all Full Access manual shares. Downgrade to Read Only or Read/Write unless owner-level access is explicitly required. Consider an Apex trigger to prevent Full Access manual sharing where not needed.',
      { records: fullAccessObjects.map(s => ({ name: s.object, detail: `${s.count.toLocaleString()} Full Access manual share${s.count > 1 ? 's' : ''}` })) }
    ));
  }

  // Role/role+subordinates manual shares — unexpectedly broad
  const roleShares = data.roleShares || [];
  const roleShareObjects = roleShares.filter(s => s.count > 0);
  if (roleShareObjects.length > 0) {
    const totalRole = roleShareObjects.reduce((sum, s) => sum + s.count, 0);
    findings.push(createFinding(CAT, 'medium',
      `${totalRole.toLocaleString()} Manual Share${totalRole > 1 ? 's' : ''} Target Roles or Role Hierarchies — Potentially Broad Exposure`,
      'Manual shares granted to a Role or Role and Subordinates group expose the record to every user in that role branch. A single share can silently grant access to dozens or hundreds of users, and access expands automatically as users are added to the role.',
      'Review role-targeted manual shares. Confirm the intent is to share with the entire role branch. Where narrower access is needed, replace with individual user grants or criteria-based sharing rules.',
      { records: roleShareObjects.map(s => ({ name: s.object, detail: `${s.count.toLocaleString()} role-targeted manual share${s.count > 1 ? 's' : ''}` })) }
    ));
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

    // Private OWD + no sharing rules + high manual volume — only access mechanism is manual
    if (sharingRuleData) {
      const objectsWithRules = new Set<string>();
      [...(sharingRuleData.ownerRules || []), ...(sharingRuleData.criteriaRules || [])].forEach((r: any) => {
        const apiName = r.EntityDefinition?.QualifiedApiName;
        if (apiName) objectsWithRules.add(apiName);
      });
      const noRuleManualOnly = manualShares.filter(
        s => s.count > 200 && privateOwdObjects.has(s.object) && !objectsWithRules.has(s.object)
      );
      if (noRuleManualOnly.length > 0) {
        findings.push(createFinding(CAT, 'high',
          `${noRuleManualOnly.length} Object${noRuleManualOnly.length > 1 ? 's Have' : ' Has'} Private OWD, No Sharing Rules, and High Manual Sharing — Manual Is the Only Access Mechanism`,
          'These objects have a Private OWD with no sharing rules configured. All record access beyond the owner and their role chain depends entirely on manual sharing. This is not scalable and creates significant risk when users leave or change roles.',
          'Design an automated access strategy for these objects: criteria-based sharing rules, role hierarchy adjustments, or Apex managed sharing. Manual sharing should supplement an automated model, not replace it.',
          { records: noRuleManualOnly.map(s => ({ name: s.object, detail: `${s.count.toLocaleString()} manual shares, OWD: Private, 0 sharing rules` })) }
        ));
      }
    }

    // Manual shares on Public OWD objects — redundant
    const publicOwdObjects = new Set(owdEntities.filter((e: any) => e.InternalSharingModel === 'ReadWrite').map((e: any) => e.QualifiedApiName));
    const redundantShares = manualShares.filter(s => s.count > 0 && publicOwdObjects.has(s.object));
    if (redundantShares.length > 0) {
      findings.push(createFinding(CAT, 'medium',
        `${redundantShares.length} Object${redundantShares.length > 1 ? 's Have' : ' Has'} Manual Shares But OWD Is Already Public Read/Write`,
        'Manual share records on objects with Public Read/Write OWD grant no additional access — all internal users can already see and edit every record. These shares add sharing recalculation overhead and signal that the OWD may have been opened after the manual shares were created without cleaning up.',
        'Review manual shares on these objects. If Public R/W OWD is intentional, delete the redundant manual share records. If the OWD should be tighter, change it back to Private and validate the manual shares provide the intended access.',
        { records: redundantShares.map(s => ({ name: s.object, detail: `${s.count.toLocaleString()} manual shares, OWD: Public Read/Write` })) }
      ));
    }
  }

  // Manual shares to inactive users — stale grants
  const inactiveShares = data.inactiveShares || [];
  const inactiveShareObjects = inactiveShares.filter(s => s.count > 0);
  if (inactiveShareObjects.length > 0) {
    const totalInactive = inactiveShareObjects.reduce((sum, s) => sum + s.count, 0);
    findings.push(createFinding(CAT, 'medium',
      `${totalInactive.toLocaleString()} Manual Share${totalInactive > 1 ? 's' : ''} Are Granted to Inactive Users`,
      'Manual share records remain in Salesforce after a user is deactivated. While inactive users cannot log in, these shares consume sharing calculation resources and create a risk if the user account is ever reactivated — access is immediately restored with no review.',
      'Run a data cleanup to delete manual share records where the UserOrGroupId belongs to an inactive user. Implement a deactivation checklist or automation to remove manual shares as part of the offboarding process.',
      { records: inactiveShareObjects.map(s => ({ name: s.object, detail: `${s.count.toLocaleString()} share${s.count > 1 ? 's' : ''} to inactive users` })) }
    ));
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
  noSharingDeclarationClasses?: { name: string; id: string }[];
  auraEnabledWithoutSharingClasses?: { name: string; id: string }[];
  invocableWithoutSharingClasses?: { name: string; id: string }[];
  invocableNoDeclarationClasses?: { name: string; id: string }[];
  batchWithoutSharingClasses?: { name: string; id: string }[];
  schedulableWithoutSharingClasses?: { name: string; id: string }[];
  inheritedSharingClasses?: { name: string; id: string }[];
  apexTriggers?: { name: string; id: string }[];
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

  // @AuraEnabled in without-sharing classes
  const auraClasses = data.auraEnabledWithoutSharingClasses || [];
  if (auraClasses.length > 0) {
    findings.push(createFinding(CAT, auraClasses.length > 5 ? 'high' : 'medium',
      `${auraClasses.length} Apex Class${auraClasses.length > 1 ? 'es Have' : ' Has'} @AuraEnabled Methods Running Without Sharing`,
      '@AuraEnabled methods are callable from LWC and Aura components directly from the UI. Classes marked without sharing expose those endpoints to bypass record-level security — any authenticated user invoking the controller gets unrestricted data access.',
      "Add 'with sharing' to each class. If system context is required for specific methods, move those methods to a separate inner class or service class with an explicit sharing declaration and a documented exception.",
      { records: auraClasses.map(c => ({ name: c.name, detail: '@AuraEnabled + without sharing' })) }
    ));
  }

  // @InvocableMethod in without-sharing or no-declaration classes
  const invocableRisk = [
    ...(data.invocableWithoutSharingClasses || []).map(c => ({ ...c, detail: 'without sharing' })),
    ...(data.invocableNoDeclarationClasses || []).map(c => ({ ...c, detail: 'no sharing declaration' }))
  ];
  if (invocableRisk.length > 0) {
    findings.push(createFinding(CAT, invocableRisk.length > 3 ? 'high' : 'medium',
      `${invocableRisk.length} @InvocableMethod Class${invocableRisk.length > 1 ? 'es' : ''} Without Sharing Enforcement — Callable From Flows`,
      "Apex classes with @InvocableMethod that run without sharing (or have no sharing declaration) grant any flow that calls them system-level data access, regardless of the flow's own run mode setting. This creates a cross-layer sharing bypass.",
      "Add 'with sharing' to each @InvocableMethod class. If the method requires elevated access, declare 'without sharing' explicitly and document the exception register entry.",
      { records: invocableRisk.slice(0, 50).map(c => ({ name: c.name, detail: c.detail })) }
    ));
  }

  // Batch Apex without sharing
  const batchClasses = data.batchWithoutSharingClasses || [];
  if (batchClasses.length > 0) {
    findings.push(createFinding(CAT, 'medium',
      `${batchClasses.length} Batch Apex Class${batchClasses.length > 1 ? 'es' : ''} Without Sharing Enforcement`,
      'Batch Apex classes running without sharing process large record volumes without any record-level security enforcement. While system context is sometimes intentional for batch processes, each class should be explicitly reviewed and justified.',
      "Verify each batch class requires system context. Add 'with sharing' where the batch should only process records accessible to the running user. Document exceptions in the sharing exception register.",
      { records: batchClasses.map(c => ({ name: c.name, detail: 'Database.Batchable — without sharing or no declaration' })) }
    ));
  }

  // Schedulable without sharing
  const schedulableClasses = data.schedulableWithoutSharingClasses || [];
  if (schedulableClasses.length > 0) {
    findings.push(createFinding(CAT, 'medium',
      `${schedulableClasses.length} Scheduled Apex Class${schedulableClasses.length > 1 ? 'es' : ''} Without Sharing Enforcement`,
      'Scheduled Apex runs on a time-based schedule without a user session. Classes without sharing enforcement access all records regardless of ownership or sharing rules, with no running-user context to constrain scope.',
      "Add 'with sharing' or 'inherited sharing' unless the scheduled job has a documented requirement for unrestricted record access. Ensure the record scope each job processes is as narrow as possible.",
      { records: schedulableClasses.map(c => ({ name: c.name, detail: 'Schedulable — without sharing or no declaration' })) }
    ));
  }

  // Inherited sharing inventory
  const inheritedClasses = data.inheritedSharingClasses || [];
  if (inheritedClasses.length > 0) {
    findings.push(createFinding(CAT, 'low',
      `${inheritedClasses.length} Apex Class${inheritedClasses.length > 1 ? 'es Use' : ' Uses'} Inherited Sharing — Context Depends on Caller`,
      "Classes declared with 'inherited sharing' take on the sharing context of their caller. When invoked from a 'without sharing' class or a system context (batch, triggers, flows), they effectively run without sharing enforcement.",
      "Audit each inherited sharing class to understand all call paths. Where a class may be called from system context, consider whether 'with sharing' would be safer. Document call-path dependencies.",
      { count: inheritedClasses.length, records: inheritedClasses.slice(0, 30).map(c => ({ name: c.name, detail: 'inherited sharing — context depends on caller' })) }
    ));
  }

  // Apex Triggers (informational)
  const triggers = data.apexTriggers || [];
  if (triggers.length > 0) {
    findings.push(createFinding(CAT, 'low',
      `${triggers.length} Active Custom Apex Trigger${triggers.length > 1 ? 's' : ''} — Always System Context`,
      'Apex triggers cannot declare a sharing mode and always run in system context. Any SOQL or DML in a trigger bypasses record-level security. This is an inventory finding — review each trigger for scope appropriateness.',
      "Review each trigger's SOQL queries and DML. Ensure triggers do not expose records to side effects that bypass the intended sharing model. Consider whether trigger logic should delegate to a with-sharing service class.",
      { count: triggers.length, records: triggers.slice(0, 30).map(t => ({ name: t.name, detail: 'Apex Trigger — always system context' })) }
    ));
  }

  return {
    category: CAT,
    score: calculateCategoryScore(findings),
    items: findings,
    stats: {
      withoutSharingCount: withoutSharing.length,
      customReasonCount: customReasons.length,
      inheritedSharingCount: (data.inheritedSharingClasses || []).length,
      triggerCount: (data.apexTriggers || []).length
    }
  };
}

// ── Flow & Automation Sharing ─────────────────────────────────────────────────
export function assessFlowSharing(data: {
  flows: { ApiName: string; Label: string; ProcessType: string; RunInMode: string }[];
}, apexData?: {
  invocableWithoutSharingClasses?: { name: string; id: string }[];
  invocableNoDeclarationClasses?: { name: string; id: string }[];
}): CategoryResult {
  const findings: SharingFinding[] = [];
  const CAT = 'Flow & Automation Sharing';
  const flows = data.flows || [];

  // Screen flows explicitly set to SystemModeWithoutSharing
  const screenWithoutSharing = flows.filter(f =>
    f.ProcessType === 'Flow' && f.RunInMode === 'SystemModeWithoutSharing'
  );
  if (screenWithoutSharing.length > 0) {
    findings.push(createFinding(CAT, 'high',
      `${screenWithoutSharing.length} Screen Flow${screenWithoutSharing.length > 1 ? 's' : ''} Set to System Context Without Sharing`,
      'Screen flows run in user context by default. Explicitly setting SystemModeWithoutSharing means the flow bypasses record-level security for all users who run it — almost always unintentional and a significant exposure risk.',
      "Change each screen flow to 'User or system context' or 'System context with sharing'. Remove SystemModeWithoutSharing unless there is a specific, documented requirement and the exposure has been risk-accepted.",
      { records: screenWithoutSharing.map(f => ({ name: f.Label || f.ApiName, detail: 'Screen Flow — System context without sharing' })) }
    ));
  }

  // Record-triggered flows explicitly set to SystemModeWithoutSharing
  const recordTriggeredWithoutSharing = flows.filter(f =>
    f.ProcessType === 'RecordTriggeredFlow' && f.RunInMode === 'SystemModeWithoutSharing'
  );
  if (recordTriggeredWithoutSharing.length > 0) {
    findings.push(createFinding(CAT, 'high',
      `${recordTriggeredWithoutSharing.length} Record-Triggered Flow${recordTriggeredWithoutSharing.length > 1 ? 's' : ''} Set to System Context Without Sharing`,
      "Record-triggered flows default to 'System context with sharing' since Spring '22. Explicitly overriding to SystemModeWithoutSharing removes that protection, allowing the flow to read and write records the triggering user cannot access.",
      "Remove SystemModeWithoutSharing from each record-triggered flow. Use the default 'System context with sharing' unless a specific requirement mandates the override — document the exception.",
      { records: recordTriggeredWithoutSharing.map(f => ({ name: f.Label || f.ApiName, detail: 'Record-Triggered Flow — System context without sharing' })) }
    ));
  }

  // Autolaunched flows in system context (explicit or default)
  const autolaunchedSystem = flows.filter(f =>
    f.ProcessType === 'AutoLaunchedFlow' &&
    (f.RunInMode === 'SystemModeWithoutSharing' || !f.RunInMode || f.RunInMode === 'DefaultMode')
  );
  if (autolaunchedSystem.length > 0) {
    findings.push(createFinding(CAT, autolaunchedSystem.length > 20 ? 'high' : 'medium',
      `${autolaunchedSystem.length} Autolaunched Flow${autolaunchedSystem.length > 1 ? 's' : ''} Run in System Context Without Sharing`,
      'Autolaunched flows run in system context without sharing by default — bypassing OWD, sharing rules, and role hierarchy. This is the platform default for this flow type; each flow should be evaluated for whether system context is actually required.',
      "For each autolaunched flow, evaluate whether 'System context with sharing' is viable. Flows called from Apex can inherit the calling class's sharing context. Restrict system context to flows that genuinely require unrestricted record access.",
      { count: autolaunchedSystem.length, records: autolaunchedSystem.slice(0, 30).map(f => ({ name: f.Label || f.ApiName, detail: `AutoLaunched — ${f.RunInMode || 'DefaultMode (system context)'}` })) }
    ));
  }

  // Scheduled flows
  const scheduledFlows = flows.filter(f => f.ProcessType === 'ScheduledFlow');
  if (scheduledFlows.length > 0) {
    findings.push(createFinding(CAT, 'medium',
      `${scheduledFlows.length} Active Scheduled Flow${scheduledFlows.length > 1 ? 's' : ''} — Always System Context`,
      'Scheduled flows always run in system context because they execute without a user session. They have unrestricted record access. Verify each scheduled flow accesses and modifies only the records it is intended to process.',
      'Review each scheduled flow for data scope. Add filter criteria to limit the record set each run processes. Ensure the flow does not perform DML on records outside its intended scope.',
      { records: scheduledFlows.map(f => ({ name: f.Label || f.ApiName, detail: 'Scheduled Flow — always system context' })) }
    ));
  }

  // Platform Event-triggered flows
  const platformEventFlows = flows.filter(f => f.ProcessType === 'PlatformEventTriggeredFlow');
  if (platformEventFlows.length > 0) {
    findings.push(createFinding(CAT, 'medium',
      `${platformEventFlows.length} Platform Event-Triggered Flow${platformEventFlows.length > 1 ? 's' : ''} — Always System Context`,
      'Platform event-triggered flows run in system context because platform events are published asynchronously without a user session. These flows have unrestricted record access and bypass sharing.',
      'Review each platform event-triggered flow. Ensure data operations are tightly scoped and do not expose or modify records beyond the intended use case. Consider whether the triggering event could carry sufficient context to restrict scope.',
      { records: platformEventFlows.map(f => ({ name: f.Label || f.ApiName, detail: 'Platform Event Flow — always system context' })) }
    ));
  }

  // Flows with DefaultMode — inventory across all types
  const defaultModeFlows = flows.filter(f => !f.RunInMode || f.RunInMode === 'DefaultMode');
  if (defaultModeFlows.length > 0) {
    const byType: Record<string, number> = {};
    defaultModeFlows.forEach(f => { byType[f.ProcessType || 'Unknown'] = (byType[f.ProcessType || 'Unknown'] || 0) + 1; });
    findings.push(createFinding(CAT, 'low',
      `${defaultModeFlows.length} Active Flow${defaultModeFlows.length > 1 ? 's' : ''} Rely on Platform Default Run Mode`,
      'Flows with no explicit RunInMode depend on Salesforce platform defaults, which vary by flow type and can change across releases. Explicit declarations make sharing behavior auditable and resistant to default-behavior changes.',
      'Set an explicit RunInMode on every active flow. This ensures sharing behavior is declared in metadata, visible in audit, and unaffected by future platform default changes.',
      { count: defaultModeFlows.length, records: Object.entries(byType).map(([type, count]) => ({ name: type, detail: `${count} flow${count > 1 ? 's' : ''} using platform default run mode` })) }
    ));
  }

  return {
    category: CAT,
    score: calculateCategoryScore(findings),
    items: findings
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
  // ── Report & Dashboard folder visibility ────────────────────────────────────
  const broadFolderShares: any[] = (data as any).broadFolderShares || [];
  if (broadFolderShares.length > 0) {
    const byFolder = new Map<string, { name: string; type: string }>();
    for (const fs of broadFolderShares) {
      const key = fs.FolderId || 'unknown';
      if (!byFolder.has(key)) {
        byFolder.set(key, { name: fs.Folder?.Name || 'Unknown', type: fs.Folder?.Type || 'Unknown' });
      }
    }
    findings.push(createFinding(CAT, 'high',
      `${byFolder.size} Report/Dashboard Folder${byFolder.size > 1 ? 's Are' : ' Is'} Shared with All Internal Users`,
      'Report and dashboard folders shared with All Internal Users expose their contents to every user in the org. If these folders contain reports on sensitive objects (finance, HR, clinical), any user can access that data regardless of their record-level sharing permissions.',
      'Review each broadly shared folder. Restrict sharing to specific roles, groups, or users. Never share folders containing sensitive reports with All Internal Users unless the data is genuinely non-sensitive.',
      { records: Array.from(byFolder.values()).map(f => ({ name: f.name, detail: `${f.type} folder — shared with all users` })) }
    ));
  }

  // ── Delegated Administration ────────────────────────────────────────────────
  const delegateGroups: any[] = (data as any).delegateGroups || [];
  if (delegateGroups.length > 0) {
    findings.push(createFinding(CAT, 'medium',
      `${delegateGroups.length} Delegated Administration Group${delegateGroups.length > 1 ? 's Are' : ' Is'} Configured`,
      'Delegated administration groups grant non-administrator users the ability to manage other users in specific roles or profiles, including resetting passwords and modifying permission assignments. A delegated admin can effectively escalate access by changing permissions for the users they manage.',
      'Review all delegated admin groups. Confirm each delegated admin is a current, trusted employee with a documented need. Audit which profiles and roles each group is authorised to manage and review on a quarterly basis.',
      { records: delegateGroups.map((g: any) => ({ name: g.Name, detail: `DeveloperName: ${g.DeveloperName || 'N/A'}` })) }
    ));
  }

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
  psViewAllObjectPerms?: any[];
  psModifyAllObjectPerms?: any[];
}, owdEntities?: any[]): CategoryResult & { stats: any } {
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

  // ── PS × OWD cross-reference checks ───────────────────────────────────────
  const psViewAllPerms: any[] = data.psViewAllObjectPerms || [];
  const psModifyAllPerms: any[] = data.psModifyAllObjectPerms || [];

  if (owdEntities && owdEntities.length > 0 && (psViewAllPerms.length > 0 || psModifyAllPerms.length > 0)) {
    const owdMap = new Map<string, string>();
    for (const e of owdEntities) owdMap.set(e.QualifiedApiName, e.InternalSharingModel);

    // Check 1: PS grants View All / Modify All on Private OWD objects
    const privateViewAll = psViewAllPerms.filter(p => owdMap.get(p.SobjectType) === 'Private');
    const privateModAll  = psModifyAllPerms.filter(p => owdMap.get(p.SobjectType) === 'Private');
    if (privateViewAll.length > 0 || privateModAll.length > 0) {
      const byObj = new Map<string, { va: string[]; ma: string[] }>();
      for (const p of privateViewAll) {
        if (!byObj.has(p.SobjectType)) byObj.set(p.SobjectType, { va: [], ma: [] });
        byObj.get(p.SobjectType)!.va.push(p.Parent?.Name || p.Parent?.Label || 'Unknown PS');
      }
      for (const p of privateModAll) {
        if (!byObj.has(p.SobjectType)) byObj.set(p.SobjectType, { va: [], ma: [] });
        byObj.get(p.SobjectType)!.ma.push(p.Parent?.Name || p.Parent?.Label || 'Unknown PS');
      }
      findings.push(createFinding(CAT, byObj.size > 5 ? 'critical' : 'high',
        `${byObj.size} Private OWD Object${byObj.size > 1 ? 's Have' : ' Has'} Permission Sets Granting View All / Modify All Records`,
        'Permission sets granting View All or Modify All Records on Private OWD objects bypass the sharing model entirely for every holder — a targeted, object-level sharing bypass that does not appear in standard VAD/MAD user reports.',
        'Review each permission set listed. Remove View All / Modify All Records grants where the sharing model (OWD + sharing rules + role hierarchy) should govern access instead. Document any justified exceptions.',
        { records: Array.from(byObj.entries()).map(([obj, g]) => ({
            name: obj,
            detail: [
              g.va.length ? `View All: ${g.va.slice(0, 3).join(', ')}${g.va.length > 3 ? ` +${g.va.length - 3} more` : ''}` : '',
              g.ma.length ? `Modify All: ${g.ma.slice(0, 3).join(', ')}${g.ma.length > 3 ? ` +${g.ma.length - 3} more` : ''}` : '',
            ].filter(Boolean).join(' | ')
          })) }
      ));
    }

    // Check 2: PS escalates Public Read OWD to write via Modify All Records
    const pubReadModAll = psModifyAllPerms.filter(p => owdMap.get(p.SobjectType) === 'Read');
    if (pubReadModAll.length > 0) {
      const byObj2 = new Map<string, string[]>();
      for (const p of pubReadModAll) {
        if (!byObj2.has(p.SobjectType)) byObj2.set(p.SobjectType, []);
        byObj2.get(p.SobjectType)!.push(p.Parent?.Name || p.Parent?.Label || 'Unknown PS');
      }
      findings.push(createFinding(CAT, 'high',
        `${byObj2.size} Public Read OWD Object${byObj2.size > 1 ? 's Have' : ' Has'} Permission Sets Granting Modify All Records`,
        'The OWD grants all internal users read access, but these permission sets escalate a subset of users to Modify All Records — unrestricted write access. This two-tier pattern is not visible from OWD or sharing rule reviews alone.',
        'Review each permission set. If write access should be limited to specific roles, consider tightening the OWD to Private and using sharing rules to grant broad read access, keeping Modify All only for justified PS holders.',
        { records: Array.from(byObj2.entries()).map(([obj, ps]) => ({
            name: obj,
            detail: `Modify All via: ${ps.slice(0, 3).join(', ')}${ps.length > 3 ? ` +${ps.length - 3} more` : ''}`
          })) }
      ));
    }

    // Check 3: PS grants View/Modify All on Public Read/Write OWD objects — redundant
    const pubRWAll = [...psViewAllPerms, ...psModifyAllPerms].filter(p => owdMap.get(p.SobjectType) === 'ReadWrite');
    if (pubRWAll.length > 0) {
      const redundantObjs = new Set(pubRWAll.map(p => p.SobjectType));
      findings.push(createFinding(CAT, 'low',
        `View All / Modify All Records Grants on ${redundantObjs.size} Public Read/Write OWD Object${redundantObjs.size > 1 ? 's' : ''} — Redundant`,
        'These objects already have Public Read/Write OWD — all internal users can read and edit records without any permission grant. View All / Modify All Records in permission sets adds governance noise without adding access control value.',
        'Remove View All / Modify All Records from permission sets on these objects. This reduces permission set complexity without changing any user\'s access, and makes future OWD tightening easier to apply.',
        { records: Array.from(redundantObjs).map(obj => ({ name: obj as string, detail: 'OWD is Public Read/Write — grant is redundant' })) }
      ));
    }
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

  // Customize Application
  const customizeAppUsers: any[] = (data as any).customizeAppUsers || [];
  if (customizeAppUsers.length > 10) {
    findings.push(createFinding(CAT, 'high',
      `${customizeAppUsers.length} Users Hold the Customize Application Permission`,
      'Customize Application grants the ability to modify org metadata, create custom objects, edit page layouts, manage flows, and alter automation behavior. It is equivalent to partial system administrator access and can be used to change the runtime context of sharing enforcement.',
      'Restrict Customize Application to declared administrators and senior developers. Remove from users who do not actively manage org configuration. This permission should appear in the access exception register.',
      { records: customizeAppUsers.slice(0, 50).map((u: any) => ({ name: u.Name, detail: `${u.Profile?.Name || 'Unknown'} (${u.grantSource || 'Profile'})` })) }
    ));
  } else if (customizeAppUsers.length > 0) {
    findings.push(createFinding(CAT, 'medium',
      `${customizeAppUsers.length} User${customizeAppUsers.length > 1 ? 's Hold' : ' Holds'} the Customize Application Permission`,
      'Customize Application grants broad metadata change capability including flow management and automation context control. Each holder can modify sharing-relevant configuration.',
      'Confirm each holder has a current business need. Document in the access exception register.',
      { records: customizeAppUsers.map((u: any) => ({ name: u.Name, detail: `${u.Profile?.Name || 'Unknown'} (${u.grantSource || 'Profile'})` })) }
    ));
  }

  // Expiring PSA check
  const expiringPsaCount: number = (data as any).expiringPsaCount || 0;
  if (expiringPsaCount === 0) {
    findings.push(createFinding(CAT, 'low',
      'No Expiring Permission Set Assignments Detected — Temporary Access Governance Gap',
      'Salesforce best practice recommends using expiration dates on permission set assignments for break-glass, project, support, and elevated temporary access. Zero expiring assignments suggests all elevated access grants are permanent with no built-in review trigger.',
      'Audit permission set assignments for elevated and temporary roles. Add expiration dates to break-glass, contractor, and project-based assignments. Establish a review cadence for assignments without expiration.',
      {}
    ));
  }

  // User Access Policies
  const uapCount: number = (data as any).userAccessPolicyCount || 0;
  if (uapCount === 0) {
    findings.push(createFinding(CAT, 'low',
      'No User Access Policies Defined',
      'User Access Policies automate permission set, group, and queue assignments based on user attributes. Without UAPs, access assignments are manual — increasing the risk of inconsistent provisioning, forgotten de-provisioning, and assignment sprawl over time.',
      'Define User Access Policies for common job functions and personas. Use UAPs to automate assignment of permission set groups when users match role or department criteria. This reduces manual overhead and access inconsistency.',
      {}
    ));
  }

  // ── Non-human / stale users with elevated access ────────────────────────────
  const ninetyDaysAgo = new Date();
  ninetyDaysAgo.setDate(ninetyDaysAgo.getDate() - 90);
  const elevatedUserMap = new Map<string, any>();
  for (const u of vadUsers) elevatedUserMap.set(u.Id, u);
  for (const u of madUsers) if (!elevatedUserMap.has(u.Id)) elevatedUserMap.set(u.Id, u);
  const allElevatedUsers = Array.from(elevatedUserMap.values());

  const neverLoggedIn = allElevatedUsers.filter((u: any) => !u.LastLoginDate);
  if (neverLoggedIn.length > 0) {
    findings.push(createFinding(CAT, 'high',
      `${neverLoggedIn.length} User${neverLoggedIn.length > 1 ? 's With' : ' With'} Elevated Access Have Never Logged In`,
      'Active users with View All Data or Modify All Data who have never logged in are likely integration, API-only, or orphaned accounts. These represent a standing privileged access risk with no verified active business purpose.',
      'Investigate each account. Confirm it has a current owner and documented purpose. If it is an integration user, verify it uses certificate-based or named credential authentication. Remove elevated permissions from any account without a verified purpose.',
      { records: neverLoggedIn.map((u: any) => ({ name: u.Name, detail: `${u.Profile?.Name || 'Unknown'} — Never logged in` })) }
    ));
  }

  const staleElevated = allElevatedUsers.filter((u: any) => {
    if (!u.LastLoginDate) return false;
    return new Date(u.LastLoginDate) < ninetyDaysAgo;
  });
  if (staleElevated.length > 0) {
    findings.push(createFinding(CAT, 'medium',
      `${staleElevated.length} User${staleElevated.length > 1 ? 's With' : ' With'} Elevated Access Have Not Logged In for 90+ Days`,
      'Users with View All Data or Modify All Data who have not logged in recently may be former employees, dormant accounts, or seasonal users whose elevated access was not revoked.',
      'Review each account. Deactivate former-employee accounts immediately. For seasonal users, replace standing elevated access with time-limited permission set assignments using an expiration date.',
      { records: staleElevated.map((u: any) => ({ name: u.Name, detail: `${u.Profile?.Name || 'Unknown'} — Last login: ${new Date(u.LastLoginDate).toLocaleDateString()}` })) }
    ));
  }

  // ── Unassigned profiles/PSes with elevated access ───────────────────────────
  const unassignedVadProfiles: any[] = (data as any).unassignedVadProfiles || [];
  const unassignedMadProfiles: any[] = (data as any).unassignedMadProfiles || [];
  const unassignedVadPs: any[] = (data as any).unassignedVadPermSets || [];
  const unassignedMadPs: any[] = (data as any).unassignedMadPermSets || [];
  const allUnassignedElevated = [
    ...unassignedVadProfiles.map((p: any) => ({ name: p.Name, detail: 'Profile: View All Data, no active users' })),
    ...unassignedMadProfiles.map((p: any) => ({ name: p.Name, detail: 'Profile: Modify All Data, no active users' })),
    ...unassignedVadPs.map((p: any) => ({ name: p.Name, detail: 'Permission Set: View All Data, no active assignments' })),
    ...unassignedMadPs.map((p: any) => ({ name: p.Name, detail: 'Permission Set: Modify All Data, no active assignments' }))
  ];
  if (allUnassignedElevated.length > 0) {
    findings.push(createFinding(CAT, 'medium',
      `${allUnassignedElevated.length} Unassigned Profile${allUnassignedElevated.length > 1 ? 's/Permission Sets Grant' : '/Permission Set Grants'} Org-Wide Data Access`,
      'Profiles and permission sets with View All Data or Modify All Data that have no active user assignments represent a latent access risk — if accidentally assigned during onboarding or profile cloning, they immediately grant full data visibility.',
      'Remove org-wide data access permissions from unassigned profiles and permission sets, or delete them if no longer required. A profile that is not assigned to anyone should not carry the highest-risk permissions.',
      { records: allUnassignedElevated }
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
export function assessExternalAccess(data: { guestProfiles: any[]; externalEntities: any[]; sharingSets?: any[]; guestSharingRules?: any[]; portalTargetedRules?: any[]; knowledgeCategories?: any[] }): CategoryResult & { stats: any } {
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

  // Guest user sharing rules
  const guestSharingRules: any[] = data.guestSharingRules || [];
  if (guestSharingRules.length > 0) {
    const byObject = new Map<string, number>();
    guestSharingRules.forEach((r: any) => {
      const obj = r.EntityDefinition?.QualifiedApiName || 'Unknown';
      byObject.set(obj, (byObject.get(obj) || 0) + 1);
    });
    findings.push(createFinding(CAT, 'high',
      `${guestSharingRules.length} Criteria-Based Sharing Rule${guestSharingRules.length > 1 ? 's Target' : ' Targets'} Guest Users`,
      'Guest user sharing rules grant record access to unauthenticated internet users. Each rule represents a deliberate decision to expose records to the public internet. These rules require the highest level of scrutiny — the criteria must be narrow, the access level appropriate, and the business justification explicit and formally approved.',
      'Review every guest user sharing rule. Confirm the criteria explicitly select only records intended for public access. Confirm no sensitive fields are exposed via the shared records. Document the business justification and review cadence for each rule.',
      { records: Array.from(byObject.entries()).map(([obj, count]) => ({ name: obj, detail: `${count} guest user sharing rule${count > 1 ? 's' : ''}` })) }
    ));
  }

  // ── Experience Cloud authenticated users ────────────────────────────────────
  const portalUsersWithBypass: any[] = (data as any).portalUsersWithBypass || [];
  if (portalUsersWithBypass.length > 0) {
    findings.push(createFinding(CAT, 'critical',
      `${portalUsersWithBypass.length} Experience Cloud User${portalUsersWithBypass.length > 1 ? 's Have' : ' Has'} Org-Wide Data Access Permissions`,
      'Active Experience Cloud users (Partner or Customer Community) with View All Data or Modify All Data can access every record in the org. External users with these permissions represent a critical data breach risk.',
      'Immediately revoke View All Data and Modify All Data from all Experience Cloud user profiles and permission sets. External users should never hold org-wide bypass permissions.',
      { records: portalUsersWithBypass.map((u: any) => ({ name: u.Name, detail: `${u.UserType} — ${u.Profile?.Name || 'Unknown profile'}` })) }
    ));
  }

  const portalUserCounts: any[] = (data as any).portalUserCounts || [];
  const totalPortalUsers = portalUserCounts.reduce((sum: number, r: any) => sum + (r.cnt || r.expr0 || 0), 0);
  if (totalPortalUsers > 0) {
    findings.push(createFinding(CAT, 'low',
      `${totalPortalUsers.toLocaleString()} Active Experience Cloud Authenticated User${totalPortalUsers > 1 ? 's' : ''} — Review Sharing Model Coverage`,
      'Authenticated Experience Cloud users (Partner Community, Customer Community) access records via Sharing Sets, sharing rules, or standard sharing. As user counts grow, the sharing model must be intentional and not over-expose records through non-Private external OWD.',
      'Audit the sharing access for each Experience Cloud user license type. Confirm Sharing Sets are correctly scoped. Verify no object has a non-Private external OWD that inadvertently exposes records to all portal users.',
      { records: portalUserCounts.filter((r: any) => (r.cnt || r.expr0 || 0) > 0).map((r: any) => ({ name: r.UserType, detail: `${(r.cnt || r.expr0 || 0).toLocaleString()} active users` })) }
    ));
  }

  // Sharing rules targeting portal roles — hierarchy cascades for external users
  const portalTargetedRules: any[] = (data as any).portalTargetedRules || [];
  if (portalTargetedRules.length > 0) {
    const byType = new Map<string, number>();
    const byObject = new Map<string, number>();
    portalTargetedRules.forEach((r: any) => {
      byType.set(r.SharedToType, (byType.get(r.SharedToType) || 0) + 1);
      const obj = r.EntityDefinition?.QualifiedApiName || 'Unknown';
      byObject.set(obj, (byObject.get(obj) || 0) + 1);
    });
    findings.push(createFinding(CAT, 'medium',
      `${portalTargetedRules.length} Sharing Rule${portalTargetedRules.length > 1 ? 's Target' : ' Targets'} External User Portal Roles or Role Hierarchies`,
      'Sharing rules scoped to Portal Roles or Portal Roles and Subordinates grant access to every external user in that portal role branch, including all subordinate roles. This mirrors the same hierarchy-escalation risk as internal role sharing — a single rule can expose records to a broad set of external users.',
      'Review each portal-role-targeted sharing rule. Confirm the scope matches the intended audience. For narrower external access, use criteria-based sharing rules with explicit field conditions rather than role hierarchy targeting.',
      { records: Array.from(byObject.entries()).map(([obj, cnt]) => ({ name: obj, detail: `${cnt} portal-role-targeted rule${cnt > 1 ? 's' : ''}` })) }
    ));
  }

  // Customer Community Plus users — participate in role hierarchy
  const ccPlusCount = portalUserCounts
    .filter((r: any) => r.UserType === 'PowerCustomerSuccess')
    .reduce((sum: number, r: any) => sum + (r.cnt || r.expr0 || 0), 0);
  if (ccPlusCount > 0) {
    findings.push(createFinding(CAT, 'low',
      `${ccPlusCount.toLocaleString()} Customer Community Plus User${ccPlusCount > 1 ? 's' : ''} Active — External Users Participate in Role Hierarchy`,
      'Customer Community Plus (CC+) users are assigned portal roles and participate in the Experience Cloud role hierarchy. Unlike standard Community users, CC+ users can see records owned by users below them in the portal role hierarchy, and their access expands as more users join the same portal role branch.',
      'Audit the portal role hierarchy structure for CC+ users. Ensure records visible via portal role hierarchy are intentional. Review external OWD settings and sharing rules to confirm CC+ users can only access records they should.',
      { count: ccPlusCount }
    ));
  }

  // HVPUs active with no Sharing Sets — no record access path
  const hvpuCount = portalUserCounts
    .filter((r: any) => r.UserType === 'CspLitePortal')
    .reduce((sum: number, r: any) => sum + (r.cnt || r.expr0 || 0), 0);
  if (hvpuCount > 0 && sharingSets.length === 0) {
    findings.push(createFinding(CAT, 'high',
      `${hvpuCount.toLocaleString()} High-Volume Portal User${hvpuCount > 1 ? 's Are' : ' Is'} Active But No Sharing Sets Are Defined`,
      'High-Volume Portal Users (HVPUs) are excluded from the standard Salesforce sharing model — they cannot be targeted by sharing rules and do not participate in the role hierarchy. Sharing Sets are the only mechanism to grant HVPUs record access. Without any Sharing Sets, these users have no path to access records.',
      'Create Sharing Sets for each HVPU profile and object they need to access. Map the Sharing Set access field to the appropriate relationship field (e.g., AccountId or ContactId) to grant access to records the user is related to.',
      { count: hvpuCount }
    ));
  }

  // Knowledge data categories — separate visibility model in place
  const knowledgeCategories: any[] = (data as any).knowledgeCategories || [];
  const knowledgeCatGroups = knowledgeCategories.filter((c: any) => c.ObjectType === 'KnowledgeArticle' || !c.ObjectType);
  if (knowledgeCatGroups.length > 0) {
    findings.push(createFinding(CAT, 'low',
      `${knowledgeCatGroups.length} Knowledge Data Category Group${knowledgeCatGroups.length > 1 ? 's Are' : ' Is'} Active — Separate Visibility Model in Place`,
      'Salesforce Knowledge uses data category groups to control article visibility, independently of the standard sharing model. Users and portal/community users see only articles in categories visible to their profile or permission set. This visibility is not reflected in standard sharing checks and must be audited separately.',
      'Audit data category visibility assignments for all profiles and permission sets. Confirm guest users (unauthenticated) cannot access categories containing sensitive content. Verify that portal user profiles have the correct category visibility for their intended audience.',
      { records: knowledgeCatGroups.map((c: any) => ({ name: c.Name, detail: 'Knowledge data category group' })) }
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
