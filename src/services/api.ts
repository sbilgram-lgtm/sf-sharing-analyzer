async function apiFetch(url: string, options?: RequestInit) {
  const res = await fetch(url, { credentials: 'include', ...options });
  if (!res.ok) throw new Error(`API error ${res.status}: ${await res.text()}`);
  return res.json();
}

export function getAuthStatus() {
  return apiFetch('/auth/status');
}

export function logout() {
  return apiFetch('/auth/logout', { method: 'POST' });
}

export function getOwdData() {
  return apiFetch('/api/assess/owd');
}

export function getRoleHierarchyData() {
  return apiFetch('/api/assess/role-hierarchy');
}

export function getTerritoriesData() {
  return apiFetch('/api/assess/territories');
}

export function getSharingRulesData() {
  return apiFetch('/api/assess/sharing-rules');
}

export function getManualSharingData() {
  return apiFetch('/api/assess/manual-sharing');
}

export function getApexSharingData() {
  return apiFetch('/api/assess/apex-sharing');
}

export function getRecordTeamsData() {
  return apiFetch('/api/assess/record-teams');
}

export function getGroupsQueuesData() {
  return apiFetch('/api/assess/groups-queues');
}

export function getPermissionBypassesData() {
  return apiFetch('/api/assess/permission-bypasses');
}

export function getImplicitSharingData() {
  return apiFetch('/api/assess/implicit-sharing');
}

export function getExternalAccessData() {
  return apiFetch('/api/assess/external-access');
}
