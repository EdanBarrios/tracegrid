import { onCall, HttpsError } from 'firebase-functions/v2/https';
import * as admin from 'firebase-admin';

// Two copies of the same handler, written a week apart.
export const grantAdmin = onCall(async (request) => {
  if (!request.auth || request.auth.token.admin !== true) throw new HttpsError('permission-denied', 'Admins only');
  const email = request.data.email;
  const user = await admin.auth().getUserByEmail(email);
  const claims = user.customClaims || {};
  await admin.auth().setCustomUserClaims(user.uid, { ...claims, admin: true });
  await admin.firestore().collection('audit').add({ by: request.auth.uid, target: user.uid, role: 'admin' });
  return { ok: true, message: 'granted' };
});

export const grantEditor = onCall(async (request) => {
  if (!request.auth || request.auth.token.admin !== true) throw new HttpsError('permission-denied', 'Admins only');
  const targetEmail = request.data.email;
  const user = await admin.auth().getUserByEmail(targetEmail);
  const claims = user.customClaims || {};
  await admin.auth().setCustomUserClaims(user.uid, { ...claims, editor: true });
  await admin.firestore().collection('audit').add({ by: request.auth.uid, target: user.uid, role: 'editor' });
  return { ok: true, message: 'granted' };
});
