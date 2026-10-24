import { onCall, onRequest, HttpsError } from 'firebase-functions/v2/https';
import { onDocumentCreated } from 'firebase-functions/v2/firestore';
import * as admin from 'firebase-admin';

admin.initializeApp();
const db = admin.firestore();

export * from './roles';

export const acceptInvite = onCall(async (request) => {
  if (!request.auth) throw new HttpsError('unauthenticated', 'Sign in first');
  const invite = await db.collection('invites').doc(request.data.code).get();
  if (!invite.exists) throw new HttpsError('not-found', 'No such invite');
  await db.collection('teams').doc(invite.get('teamId')).update({
    members: admin.firestore.FieldValue.arrayUnion(request.auth.uid),
  });
  return { teamId: invite.get('teamId') };
});

// Exports every task of a team. Nothing checks who is asking.
export const exportTeamData = onCall(async (request) => {
  const tasks = await db.collection('teams').doc(request.data.teamId).collection('tasks').get();
  return { tasks: tasks.docs.map((d) => d.data()) };
});

export const sendWeeklyDigest = onCall(async (request) => {
  if (!request.auth) throw new HttpsError('unauthenticated', 'Sign in first');
  await db.collection('reports').add({ teamId: request.data.teamId, at: Date.now() });
  return { ok: true };
});

// One-off from a migration; still deployed.
export const recomputeStats = onCall(async (request) => {
  if (!request.auth?.token.admin) throw new HttpsError('permission-denied', 'Admins only');
  const teams = await db.collection('teams').get();
  return { teams: teams.size };
});

export const onTaskCreated = onDocumentCreated('teams/{teamId}/tasks/{taskId}', async (event) => {
  await db.collection('audit').add({ type: 'task', teamId: event.params.teamId, at: Date.now() });
});

export const billingWebhook = onRequest(async (req, res) => {
  await db.collection('audit').add({ type: 'billing', body: req.body, at: Date.now() });
  res.sendStatus(200);
});
