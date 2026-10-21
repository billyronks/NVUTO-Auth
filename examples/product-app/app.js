'use strict';
let access = '', refresh = '', challenge = '';
let refreshing = null;
const byId = id => document.getElementById(id);
function status(message) { byId('status').textContent = message; }
function clear() {
  access = refresh = challenge = '';
  byId('actions').hidden = true;
  byId('mfa').hidden = true;
  byId('login').hidden = false;
  byId('result').textContent = '';
}
async function request(path, body, bearer = '') {
  const response = await fetch(path, {
    method: body === undefined ? 'GET' : 'POST', credentials: 'omit',
    headers: { 'Content-Type': 'application/json', ...(bearer ? { Authorization: 'Bearer ' + bearer } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) })
  });
  const text = await response.text();
  if (!response.ok) throw new Error('Request failed (' + response.status + '). ' + text.slice(0, 160));
  return JSON.parse(text);
}
function signedIn(data) {
  if (data.mfa_required) {
    challenge = data.challenge;
    byId('login').hidden = true; byId('mfa').hidden = false;
    status('Enter your authenticator code.'); return;
  }
  if (data.mfa_enrollment_required) {
    clear(); status('MFA enrollment is required. Use the account-management link, enroll, then sign in again.'); return;
  }
  if (!data.access_token || !data.refresh_token) throw new Error('Invalid sign-in response');
  access = data.access_token; refresh = data.refresh_token; challenge = '';
  byId('login').hidden = byId('mfa').hidden = true;
  byId('actions').hidden = false; status('Signed in. Load your projects.');
}
byId('login').addEventListener('submit', async event => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const body = Object.fromEntries(form);
  event.currentTarget.elements.password.value = '';
  try { signedIn((await request('/api/auth/login', body)).data); }
  catch (error) { clear(); status(error.message); }
  finally { body.password = ''; }
});
byId('mfa').addEventListener('submit', async event => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const code = String(form.get('code'));
  event.currentTarget.reset();
  try { signedIn((await request('/api/auth/mfa/verify', { token: challenge, ...(form.get('recovery') ? { recovery_code: code } : { code }) })).data); }
  catch (error) { clear(); status(error.message + ' Sign in again to get a new MFA challenge.'); }
});
byId('projects').addEventListener('click', async () => {
  try { byId('result').textContent = JSON.stringify(await request('/api/projects', undefined, access), null, 2); }
  catch (error) { status(error.message + ' Refresh once if the access token expired, or sign in again.'); }
});
// One in-flight refresh per session. Never retry an ambiguous refresh with an old token.
function rotate() {
  if (refreshing) return refreshing;
  refreshing = (async () => {
    try { signedIn((await request('/api/auth/refresh', { refresh_token: refresh })).data); status('Session refreshed.'); }
    catch (error) { clear(); status(error.message + ' Sign in again; refresh was not retried.'); }
    finally { refreshing = null; }
  })();
  return refreshing;
}
byId('refresh').addEventListener('click', rotate);
byId('logout').addEventListener('click', async () => {
  if (refreshing) await refreshing;
  try { if (refresh) await request('/api/auth/logout', { refresh_token: refresh }, access); status('Signed out.'); }
  catch (error) { status(error.message + ' Local credentials were cleared. Use account management to revoke sessions if necessary.'); }
  finally { clear(); }
});
request('/api/config').then(config => { byId('account').href = config.account_url; }).catch(error => status(error.message));
