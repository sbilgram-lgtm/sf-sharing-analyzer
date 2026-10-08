const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../.env') });
const express = require('express');
const session = require('express-session');
const cors = require('cors');
const crypto = require('crypto');
const jsforce = require('jsforce');

function generatePkce() {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

const app = express();
const PORT = process.env.PORT || 3001;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const isProduction = process.env.NODE_ENV === 'production';

if (!isProduction) {
  app.use(cors({ origin: 'http://localhost:3000', credentials: true }));
}
app.use(express.json({ limit: '10mb' }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: isProduction,
    maxAge: 3600000,
    sameSite: 'lax'
  },
  proxy: isProduction
}));

if (isProduction) {
  app.set('trust proxy', 1);
}

app.get('/health', (req, res) => res.json({ status: 'ok' }));

function getBaseUrl(req) {
  if (process.env.BASE_URL) return process.env.BASE_URL;
  if (isProduction) return `${req.protocol}://${req.get('host')}`;
  return 'http://localhost:3000';
}

function getCallbackUrl(req) {
  if (process.env.SF_CALLBACK_URL) return process.env.SF_CALLBACK_URL;
  const base = process.env.BASE_URL || `${req.protocol}://${req.get('host')}`;
  return `${base}/auth/callback`;
}

app.get('/auth/login', (req, res) => {
  let rawLoginUrl = req.query.loginUrl || process.env.SF_LOGIN_URL || 'https://login.salesforce.com';
  if (rawLoginUrl && !/^https?:\/\//i.test(rawLoginUrl)) rawLoginUrl = 'https://' + rawLoginUrl;
  const loginUrl = rawLoginUrl.replace(/\/$/, '');
  const clientId = req.query.clientId || process.env.SF_CLIENT_ID;
  const clientSecret = req.query.clientSecret || process.env.SF_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    return res.redirect(`${getBaseUrl(req)}/login?error=missing_credentials`);
  }

  req.session.loginUrl = loginUrl;
  req.session.clientId = clientId;
  req.session.clientSecret = clientSecret;

  const { verifier, challenge } = generatePkce();
  req.session.pkceVerifier = verifier;

  const oauth = new jsforce.OAuth2({
    loginUrl,
    clientId,
    clientSecret,
    redirectUri: getCallbackUrl(req)
  });

  const authUrl = oauth.getAuthorizationUrl({
    scope: 'api refresh_token',
    code_challenge: challenge,
    code_challenge_method: 'S256',
  });
  req.session.save(err => {
    if (err) {
      console.error('Session save error:', err);
      return res.redirect(`${getBaseUrl(req)}/login?error=session_error`);
    }
    res.redirect(authUrl);
  });
});

app.get('/auth/callback', async (req, res) => {
  if (req.query.error) {
    const desc = req.query.error_description || req.query.error;
    console.error('Salesforce auth error:', desc);
    return res.redirect(`${getBaseUrl(req)}/login?error=${encodeURIComponent(desc)}`);
  }

  const loginUrl = req.session.loginUrl || 'https://login.salesforce.com';
  const clientId = req.session.clientId || process.env.SF_CLIENT_ID;
  const clientSecret = req.session.clientSecret || process.env.SF_CLIENT_SECRET;

  const oauth = new jsforce.OAuth2({
    loginUrl,
    clientId,
    clientSecret,
    redirectUri: getCallbackUrl(req)
  });

  const conn = new jsforce.Connection({ oauth2: oauth });
  try {
    const tokenParams = req.session.pkceVerifier ? { code_verifier: req.session.pkceVerifier } : {};
    const tokenRes = await new Promise((resolve, reject) => {
      oauth.requestToken(req.query.code, tokenParams, (err, res) => err ? reject(err) : resolve(res));
    });
    conn.initialize({
      accessToken: tokenRes.access_token,
      instanceUrl: tokenRes.instance_url,
      refreshToken: tokenRes.refresh_token,
    });
    req.session.accessToken = conn.accessToken;
    req.session.instanceUrl = conn.instanceUrl;
    req.session.refreshToken = conn.refreshToken;

    try {
      await new Promise((resolve) => {
        conn.query(
          "SELECT Id, Name, OrganizationType, IsSandbox, InstanceName FROM Organization LIMIT 1",
          (err, result) => {
            if (!err && result.records && result.records.length > 0) {
              const org = result.records[0];
              req.session.orgId        = org.Id;
              req.session.orgName      = org.Name;
              req.session.orgType      = org.OrganizationType;
              req.session.isSandbox    = org.IsSandbox;
              req.session.instanceName = org.InstanceName;
            }
            resolve(null);
          }
        );
      });
    } catch (e) { /* non-fatal */ }

    req.session.save(err => {
      if (err) {
        console.error('Session save error after auth:', err);
        return res.redirect(`${getBaseUrl(req)}/login?error=auth_failed`);
      }
      res.redirect(`${getBaseUrl(req)}/dashboard`);
    });
  } catch (err) {
    console.error('OAuth error:', err);
    res.redirect(`${getBaseUrl(req)}/login?error=auth_failed`);
  }
});

app.get('/auth/status', (req, res) => {
  res.json({
    authenticated: !!(req.session.accessToken && req.session.instanceUrl),
    instanceUrl:   req.session.instanceUrl  || null,
    orgId:         req.session.orgId        || null,
    orgName:       req.session.orgName      || null,
    orgType:       req.session.orgType      || null,
    isSandbox:     req.session.isSandbox    || false,
    instanceName:  req.session.instanceName || null
  });
});

app.post('/auth/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

function getConnection(req) {
  if (!req.session.accessToken || !req.session.instanceUrl) return null;
  return new jsforce.Connection({
    accessToken: req.session.accessToken,
    instanceUrl: req.session.instanceUrl
  });
}

function requireAuth(req, res, next) {
  if (!req.session.accessToken) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
}

function safeQuery(conn, soql) {
  return new Promise((resolve) => {
    conn.query(soql, (err, result) => {
      if (err) resolve({ records: [], totalSize: 0 });
      else resolve(result || { records: [], totalSize: 0 });
    });
  });
}

function safeToolingQuery(conn, soql) {
  return new Promise((resolve) => {
    conn.tooling.query(soql, (err, result) => {
      if (err) resolve({ records: [], totalSize: 0 });
      else resolve(result || { records: [], totalSize: 0 });
    });
  });
}

// ── OWD Analysis ──────────────────────────────────────────────────────────────
app.get('/api/assess/owd', requireAuth, async (req, res) => {
  const conn = getConnection(req);
  try {
    const entityDefsRes = await safeToolingQuery(conn,
      "SELECT QualifiedApiName, Label, InternalSharingModel, ExternalSharingModel " +
      "FROM EntityDefinition WHERE IsCustomizable = true AND IsDeprecated = false " +
      "ORDER BY Label LIMIT 500"
    );
    res.json({ entities: entityDefsRes.records || [] });
  } catch (err) {
    console.error('OWD assessment error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── Role Hierarchy ────────────────────────────────────────────────────────────
app.get('/api/assess/role-hierarchy', requireAuth, async (req, res) => {
  const conn = getConnection(req);
  try {
    const [allRolesRes, totalRoleCountRes, topLevelRoleUsersRes, emptyRolesRes] = await Promise.all([
      safeQuery(conn, "SELECT Id, Name, ParentRoleId FROM UserRole WHERE NamespacePrefix = null LIMIT 1000"),
      safeQuery(conn, "SELECT COUNT(Id) FROM UserRole WHERE NamespacePrefix = null"),
      safeQuery(conn,
        "SELECT UserRoleId, COUNT(Id) userCount FROM User " +
        "WHERE IsActive = true AND UserType = 'Standard' " +
        "AND UserRoleId IN (SELECT Id FROM UserRole WHERE ParentRoleId = null AND NamespacePrefix = null) " +
        "GROUP BY UserRoleId LIMIT 50"
      ),
      safeQuery(conn,
        "SELECT Id, Name FROM UserRole WHERE NamespacePrefix = null AND Id NOT IN " +
        "(SELECT UserRoleId FROM User WHERE IsActive = true AND UserRoleId != null) LIMIT 200"
      )
    ]);
    res.json({
      allRoles: allRolesRes.records || [],
      totalRoleCount: (totalRoleCountRes.records[0] || {}).expr0 || 0,
      topLevelRoleUsers: topLevelRoleUsersRes.records || [],
      emptyRoles: emptyRolesRes.records || []
    });
  } catch (err) {
    console.error('Role hierarchy assessment error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── Territory Management 2.0 ──────────────────────────────────────────────────
app.get('/api/assess/territories', requireAuth, async (req, res) => {
  const conn = getConnection(req);
  try {
    const [modelsRes, territoriesRes, rulesRes, userAssocRes] = await Promise.all([
      safeQuery(conn, "SELECT Id, Name, State, Description FROM Territory2Model LIMIT 50"),
      safeQuery(conn, "SELECT Id, Name, ParentTerritory2Id, Territory2ModelId FROM Territory2 LIMIT 2000"),
      safeQuery(conn, "SELECT Id, Territory2Id, IsActive, BooleanFilter FROM Territory2Rule LIMIT 2000"),
      safeQuery(conn, "SELECT Territory2Id, COUNT(Id) userCount FROM UserTerritory2Association GROUP BY Territory2Id LIMIT 2000")
    ]);
    res.json({
      enabled: (modelsRes.records || []).length > 0,
      models: modelsRes.records || [],
      territories: territoriesRes.records || [],
      rules: rulesRes.records || [],
      userAssociations: userAssocRes.records || []
    });
  } catch (err) {
    // Territory2 not enabled — return disabled state
    res.json({ enabled: false, models: [], territories: [], rules: [], userAssociations: [] });
  }
});

// ── Sharing Rules ─────────────────────────────────────────────────────────────
app.get('/api/assess/sharing-rules', requireAuth, async (req, res) => {
  const conn = getConnection(req);
  try {
    const [ownerRulesRes, criteriaRulesRes, allInternalGroupRes] = await Promise.all([
      safeToolingQuery(conn,
        "SELECT Id, DeveloperName, EntityDefinition.QualifiedApiName, SharedToType, SharedToId " +
        "FROM OwnerSharingRule LIMIT 2000"
      ),
      safeToolingQuery(conn,
        "SELECT Id, DeveloperName, EntityDefinition.QualifiedApiName, SharedToType, SharedToId " +
        "FROM CriteriaBasedSharingRule LIMIT 2000"
      ),
      safeQuery(conn, "SELECT Id FROM Group WHERE DeveloperName = 'AllInternalUsers' LIMIT 1")
    ]);
    const allInternalGroupId = (allInternalGroupRes.records[0] || {}).Id || null;
    res.json({
      ownerRules: ownerRulesRes.records || [],
      criteriaRules: criteriaRulesRes.records || [],
      allInternalGroupId
    });
  } catch (err) {
    console.error('Sharing rules assessment error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── Manual Sharing ────────────────────────────────────────────────────────────
app.get('/api/assess/manual-sharing', requireAuth, async (req, res) => {
  const conn = getConnection(req);
  try {
    const objects = ['Account', 'Case', 'Opportunity', 'Contact', 'Lead', 'Campaign'];
    const shareQueries = objects.map(obj =>
      safeQuery(conn,
        `SELECT COUNT(Id) shareCount FROM ${obj}Share WHERE RowCause = 'Manual'`
      ).then(r => ({
        object: obj,
        count: (r.records[0] || {}).shareCount || (r.records[0] || {}).expr0 || 0
      })).catch(() => ({ object: obj, count: 0 }))
    );
    const manualShares = await Promise.all(shareQueries);
    res.json({ manualShares });
  } catch (err) {
    console.error('Manual sharing assessment error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── Apex Sharing ──────────────────────────────────────────────────────────────
app.get('/api/assess/apex-sharing', requireAuth, async (req, res) => {
  const conn = getConnection(req);
  try {
    const [apexClassesRes, sharingReasonsRes] = await Promise.all([
      safeToolingQuery(conn,
        "SELECT Id, Name, Body FROM ApexClass " +
        "WHERE NamespacePrefix = null AND Status = 'Active' LIMIT 2000"
      ),
      safeToolingQuery(conn,
        "SELECT DeveloperName, Label FROM SharingReason LIMIT 200"
      ).catch(() => ({ records: [] }))
    ]);

    const classes = apexClassesRes.records || [];
    const withoutSharing = classes.filter(c => /\bwithout\s+sharing\b/i.test(c.Body || ''));
    const createsShares = classes.filter(c =>
      /new\s+\w+Share\s*\(/i.test(c.Body || '') ||
      /\b\w+Share\b\s*\w+\s*=\s*new\b/i.test(c.Body || '')
    );

    res.json({
      withoutSharingClasses: withoutSharing.map(c => ({ name: c.Name, id: c.Id })),
      sharesCreatingClasses: createsShares.map(c => ({ name: c.Name, id: c.Id })),
      customSharingReasons: sharingReasonsRes.records || []
    });
  } catch (err) {
    console.error('Apex sharing assessment error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── Record Teams ──────────────────────────────────────────────────────────────
app.get('/api/assess/record-teams', requireAuth, async (req, res) => {
  const conn = getConnection(req);
  try {
    const [accountTeamMembersRes, caseTeamTemplatesRes, oppTeamMembersRes] = await Promise.all([
      safeQuery(conn,
        "SELECT AccountId, TeamMemberRole, AccountAccessLevel FROM AccountTeamMember LIMIT 1000"
      ).catch(() => ({ records: [] })),
      safeQuery(conn,
        "SELECT Id, Name FROM CaseTeamTemplate LIMIT 200"
      ).catch(() => ({ records: [] })),
      safeQuery(conn,
        "SELECT OpportunityId, TeamMemberRole, OpportunityAccessLevel FROM OpportunityTeamMember LIMIT 1000"
      ).catch(() => ({ records: [] }))
    ]);
    res.json({
      accountTeam: {
        members: accountTeamMembersRes.records || [],
        enabled: (accountTeamMembersRes.records || []).length > 0
      },
      caseTeam: {
        templates: caseTeamTemplatesRes.records || [],
        enabled: (caseTeamTemplatesRes.records || []).length > 0
      },
      oppTeam: {
        members: oppTeamMembersRes.records || [],
        enabled: (oppTeamMembersRes.records || []).length > 0
      }
    });
  } catch (err) {
    console.error('Record teams assessment error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── Groups & Queues ───────────────────────────────────────────────────────────
app.get('/api/assess/groups-queues', requireAuth, async (req, res) => {
  const conn = getConnection(req);
  try {
    const [groupsRes, groupMembersRes, queuesRes, queueSobjectsRes] = await Promise.all([
      safeQuery(conn,
        "SELECT Id, Name, Type, DeveloperName FROM Group WHERE Type IN ('Regular', 'Queue') LIMIT 1000"
      ),
      safeQuery(conn,
        "SELECT GroupId, COUNT(Id) memberCount FROM GroupMember GROUP BY GroupId LIMIT 1000"
      ),
      safeQuery(conn,
        "SELECT Id, Name FROM Group WHERE Type = 'Queue' LIMIT 200"
      ),
      safeQuery(conn,
        "SELECT QueueId, SobjectType FROM QueueSobject LIMIT 1000"
      )
    ]);
    res.json({
      groups: groupsRes.records || [],
      groupMemberCounts: groupMembersRes.records || [],
      queues: queuesRes.records || [],
      queueObjects: queueSobjectsRes.records || []
    });
  } catch (err) {
    console.error('Groups & queues assessment error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── Permission Bypasses ───────────────────────────────────────────────────────
app.get('/api/assess/permission-bypasses', requireAuth, async (req, res) => {
  const conn = getConnection(req);
  try {
    const [
      vadProfileUsersRes, madProfileUsersRes,
      vadPermSetUsersRes, madPermSetUsersRes,
      viewAllPermsRes, modifyAllPermsRes
    ] = await Promise.all([
      safeQuery(conn,
        "SELECT Id, Name, Profile.Name FROM User " +
        "WHERE IsActive = true AND Profile.PermissionsViewAllData = true LIMIT 500"
      ),
      safeQuery(conn,
        "SELECT Id, Name, Profile.Name FROM User " +
        "WHERE IsActive = true AND Profile.PermissionsModifyAllData = true LIMIT 500"
      ),
      safeQuery(conn,
        "SELECT AssigneeId, Assignee.Name, PermissionSet.Name FROM PermissionSetAssignment " +
        "WHERE PermissionSet.PermissionsViewAllData = true AND Assignee.IsActive = true " +
        "AND PermissionSet.IsOwnedByProfile = false LIMIT 500"
      ).catch(() => ({ records: [] })),
      safeQuery(conn,
        "SELECT AssigneeId, Assignee.Name, PermissionSet.Name FROM PermissionSetAssignment " +
        "WHERE PermissionSet.PermissionsModifyAllData = true AND Assignee.IsActive = true " +
        "AND PermissionSet.IsOwnedByProfile = false LIMIT 500"
      ).catch(() => ({ records: [] })),
      safeToolingQuery(conn,
        "SELECT Id, SobjectType FROM ObjectPermissions WHERE PermissionsViewAllRecords = true LIMIT 500"
      ),
      safeToolingQuery(conn,
        "SELECT Id, SobjectType FROM ObjectPermissions WHERE PermissionsModifyAllRecords = true LIMIT 500"
      )
    ]);

    const vadUserMap = new Map();
    for (const u of (vadProfileUsersRes.records || [])) {
      vadUserMap.set(u.Id, { Id: u.Id, Name: u.Name, Profile: u.Profile, grantSource: 'Profile' });
    }
    for (const psa of (vadPermSetUsersRes.records || [])) {
      const id = psa.AssigneeId;
      if (!vadUserMap.has(id)) {
        vadUserMap.set(id, { Id: id, Name: psa.Assignee?.Name || id, Profile: { Name: psa.PermissionSet?.Name || 'Permission Set' }, grantSource: 'Permission Set' });
      }
    }

    const madUserMap = new Map();
    for (const u of (madProfileUsersRes.records || [])) {
      madUserMap.set(u.Id, { Id: u.Id, Name: u.Name, Profile: u.Profile, grantSource: 'Profile' });
    }
    for (const psa of (madPermSetUsersRes.records || [])) {
      const id = psa.AssigneeId;
      if (!madUserMap.has(id)) {
        madUserMap.set(id, { Id: id, Name: psa.Assignee?.Name || id, Profile: { Name: psa.PermissionSet?.Name || 'Permission Set' }, grantSource: 'Permission Set' });
      }
    }

    res.json({
      viewAllDataUsers: Array.from(vadUserMap.values()),
      modifyAllDataUsers: Array.from(madUserMap.values()),
      viewAllObjectPerms: viewAllPermsRes.records || [],
      modifyAllObjectPerms: modifyAllPermsRes.records || []
    });
  } catch (err) {
    console.error('Permission bypasses assessment error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── Implicit Sharing ──────────────────────────────────────────────────────────
app.get('/api/assess/implicit-sharing', requireAuth, async (req, res) => {
  const conn = getConnection(req);
  try {
    const entityDefsRes = await safeToolingQuery(conn,
      "SELECT QualifiedApiName, Label, InternalSharingModel, ExternalSharingModel " +
      "FROM EntityDefinition " +
      "WHERE QualifiedApiName IN ('Account','Contact','Case','Opportunity','Asset','Contract') " +
      "LIMIT 20"
    );
    res.json({ entities: entityDefsRes.records || [] });
  } catch (err) {
    console.error('Implicit sharing assessment error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── External & Guest Access ───────────────────────────────────────────────────
app.get('/api/assess/external-access', requireAuth, async (req, res) => {
  const conn = getConnection(req);
  try {
    const [guestProfileRes, externalEntitiesRes] = await Promise.all([
      safeQuery(conn, "SELECT Id, Name FROM Profile WHERE UserType = 'Guest' LIMIT 10"),
      safeToolingQuery(conn,
        "SELECT QualifiedApiName, Label, ExternalSharingModel " +
        "FROM EntityDefinition " +
        "WHERE ExternalSharingModel != 'Private' AND IsCustomizable = true LIMIT 200"
      )
    ]);
    res.json({
      guestProfiles: guestProfileRes.records || [],
      externalEntities: externalEntitiesRes.records || []
    });
  } catch (err) {
    console.error('External access assessment error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── Serve React build ────────────────────────────────────────────────────────
const buildPath = path.join(__dirname, '../build');
const fs = require('fs');
if (fs.existsSync(buildPath)) {
  app.use(express.static(buildPath));
  app.get('*', (req, res) => {
    res.sendFile(path.join(buildPath, 'index.html'));
  });
}

app.listen(PORT, () => {
  console.log(`SF Sharing Analyzer server running on port ${PORT}`);
});
