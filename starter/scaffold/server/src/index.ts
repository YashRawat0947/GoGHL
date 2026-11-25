
import express from 'express';
import { createServer } from 'node:http';
import {
  createHmac,
  createHash,
  randomBytes,
  timingSafeEqual,
  createPublicKey,
  verify,
} from 'node:crypto';
import { config } from './config.js';
import { getDb } from './db.js';
import { getRedis } from './redis.js';

const app = express();
const redis = getRedis();
const sessions = 'sb:session:';
const oidc = 'sb:oidc:';

type User = {
  sub: string;
  name: string;
  email: string;
  workspaces: { id: string; role: string }[];
};

const b64 = (v: Buffer) => v.toString('base64url');
const cookie = (req: express.Request) =>
  req.headers.cookie?.split(';').map((v) => v.trim()).find((v) => v.startsWith(`${config.sessionCookie}=`))?.split('=')[1];

async function getUser(req: express.Request): Promise<User | null> {
  const id = cookie(req);
  if (!id) return null;
  const value = await redis.get(sessions + id);
  return value ? JSON.parse(value) : null;
}

async function discovery() {
  const res = await fetch(`${config.oidc.issuer}/.well-known/openid-configuration`);
  if (!res.ok) throw new Error('OIDC discovery failed');
  return res.json() as Promise<{ authorization_endpoint: string; token_endpoint: string; jwks_uri: string; issuer: string }>;
}

type Jwk = import('node:crypto').JsonWebKey & { kid: string };

let keys: { keys: Jwk[] } | undefined;

async function getKey(kid: string, jwksUri: string) {
  if (!keys) {
    const res = await fetch(jwksUri);
    if (!res.ok) throw new Error('JWKS request failed');
    keys = await res.json() as { keys: Jwk[] };
  }

  let jwk = keys.keys.find((key) => key.kid === kid);

  if (!jwk) {
    keys = undefined;
    const res = await fetch(jwksUri);
    if (!res.ok) throw new Error('JWKS request failed');
    keys = await res.json() as { keys: Jwk[] };
    jwk = keys.keys.find((key) => key.kid === kid);
  }

  if (!jwk) throw new Error('Signing key not found');
  return createPublicKey({ key: jwk, format: 'jwk' });
}

app.get('/healthz', (_req, res) => res.json({ ok: true }));

app.get('/auth/login', async (_req, res) => {
  try {
    const provider = await discovery();
    const state = b64(randomBytes(32));
    const nonce = b64(randomBytes(32));
    const verifier = b64(randomBytes(32));
    const challenge = b64(createHash('sha256').update(verifier).digest());

    await redis.set(oidc + state, JSON.stringify({ nonce, verifier }), 'EX', 300);

    const url = new URL(provider.authorization_endpoint);
    url.searchParams.set('client_id', config.oidc.clientId);
    url.searchParams.set('redirect_uri', config.oidc.redirectUri);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', 'openid profile email');
    url.searchParams.set('state', state);
    url.searchParams.set('nonce', nonce);
    url.searchParams.set('code_challenge', challenge);
    url.searchParams.set('code_challenge_method', 'S256');

    res.redirect(url.toString());
  } catch {
    res.sendStatus(502);
  }
});

app.get('/auth/callback', async (req, res) => {
  try {
    const state = String(req.query.state || '');
    const code = String(req.query.code || '');
    const saved = await redis.getdel(oidc + state);

    if (!state || !code || !saved) return res.sendStatus(401);

    const { nonce, verifier } = JSON.parse(saved);
    const provider = await discovery();

    const tokenRes = await fetch(provider.token_endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: config.oidc.redirectUri,
        client_id: config.oidc.clientId,
        client_secret: config.oidc.clientSecret,
        code_verifier: verifier,
      }),
    });

    if (!tokenRes.ok) return res.sendStatus(401);

    const { id_token } = await tokenRes.json() as { id_token: string };
    const [head, body, signature] = id_token.split('.');
    const header = JSON.parse(Buffer.from(head, 'base64url').toString());
    const claims = JSON.parse(Buffer.from(body, 'base64url').toString());

    if (header.alg !== 'RS256' || !header.kid) return res.sendStatus(401);

    const key = await getKey(header.kid, provider.jwks_uri);

    if (!verify('RSA-SHA256', Buffer.from(`${head}.${body}`), key, Buffer.from(signature, 'base64url'))) {
      return res.sendStatus(401);
    }

    if (
      claims.iss !== provider.issuer ||
      claims.aud !== config.oidc.clientId ||
      claims.exp <= Date.now() / 1000 ||
      claims.nonce !== nonce ||
      !claims.sub ||
      !Array.isArray(claims.workspaces)
    ) {
      return res.sendStatus(401);
    }

    const user: User = {
      sub: claims.sub,
      name: claims.name,
      email: claims.email,
      workspaces: claims.workspaces,
    };

    const id = b64(randomBytes(32));
    await redis.set(sessions + id, JSON.stringify(user), 'EX', 86400);

    res.setHeader(
      'Set-Cookie',
      `${config.sessionCookie}=${id}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400`
    );
    res.redirect(config.webOrigin);
  } catch {
    res.sendStatus(401);
  }
});

app.get('/auth/logout', async (req, res) => {
  const id = cookie(req);
  if (id) await redis.del(sessions + id);

  res.setHeader(
    'Set-Cookie',
    `${config.sessionCookie}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`
  );
  res.redirect(config.webOrigin);
});

app.get('/api/me', async (req, res) => {
  const user = await getUser(req);
  if (!user) return res.sendStatus(401);
  res.json(user);
});

app.post('/api/reply', express.json(), async (req, res) => {
  const user = await getUser(req);
  if (!user) return res.sendStatus(401);

  const { workspace, contact, text, client_ref } = req.body ?? {};

  if (
    typeof workspace !== 'string' ||
    typeof contact !== 'string' ||
    typeof text !== 'string' ||
    !text.trim() ||
    typeof client_ref !== 'string' ||
    !client_ref
  ) return res.sendStatus(400);

  if (!user.workspaces.some((w) => w.id === workspace)) return res.sendStatus(403);

  const db = await getDb();
  const jobs = db.collection('outbound_jobs');

  try {
    await jobs.insertOne({
      workspace,
      contact,
      text: text.trim(),
      client_ref,
      status: 'queued',
      attempts: 0,
      nextAttemptAt: new Date(),
      createdAt: new Date(),
    });
  } catch (error: any) {
    if (error.code !== 11000) throw error;
  }

  res.status(202).json({ client_ref, status: 'queued' });
});

app.get('/api/conversations', async (req, res) => {
  const user = await getUser(req);
  if (!user) return res.sendStatus(401);

  const workspace = String(req.query.workspace || '');

  if (!user.workspaces.some((w) => w.id === workspace)) return res.sendStatus(403);

  const db = await getDb();
  const messages = await db.collection('messages')
    .find({ workspace })
    .sort({ occurredAt: -1 })
    .limit(200)
    .toArray();

  const grouped = new Map<string, { contact: string; messages: typeof messages; assignee: string | null }>();

  for (const message of messages.reverse()) {
    let conversation = grouped.get(message.contact);
    if (!conversation) {
      conversation = { contact: message.contact, messages: [], assignee: null };
      grouped.set(message.contact, conversation);
    }
    conversation.messages.push(message);
  }

  res.json([...grouped.values()].reverse());
});

app.post('/webhooks/pigeon', express.raw({ type: 'application/json' }), async (req, res) => {
  const raw = req.body;
  const signature = req.header('x-pigeon-signature');
  const eventId = req.header('x-pigeon-event-id');

  if (!Buffer.isBuffer(raw) || !signature || !eventId) return res.sendStatus(401);

  const parts = Object.fromEntries(signature.split(',').map((v) => v.trim().split('=')));
  const timestamp = parts.t;
  const received = parts.v1;

  if (!timestamp || !received || !/^\d+$/.test(timestamp) || Math.abs(Date.now() / 1000 - Number(timestamp)) > 300) {
    return res.sendStatus(401);
  }

  const expected = createHmac('sha256', config.pigeon.webhookSecret)
    .update(`${timestamp}.${raw}`)
    .digest('hex');

  if (!/^[a-f\d]{64}$/i.test(received) || !timingSafeEqual(Buffer.from(received, 'hex'), Buffer.from(expected, 'hex'))) {
    return res.sendStatus(401);
  }

  let event;
  try {
    event = JSON.parse(raw.toString());
  } catch {
    return res.sendStatus(400);
  }

  if (event.type === 'message.status') {
  const { workspace, data } = event;
  if (!config.pigeon.apiKeys[workspace] || !data?.status) {
    return res.sendStatus(200);
  }

  const db = await getDb();
  await db.collection('messages').updateOne(
    {
      workspace,
      direction: 'outbound',
      $or: [
        { client_ref: data.client_ref },
        { messageId: data.message_id },
      ],
    },
    { $set: { status: data.status, updatedAt: new Date() } }
  );

  return res.sendStatus(200);
}

if (event.type !== 'message.inbound') return res.sendStatus(200);

  const { workspace, occurred_at, data } = event;

  if (!config.pigeon.apiKeys[workspace] || !data?.message_id || !data?.from || typeof data.text !== 'string') {
    return res.sendStatus(200);
  }

  try {
    const db = await getDb();
    await db.collection('messages').insertOne({
      eventId,
      workspace,
      contact: data.from,
      messageId: data.message_id,
      text: data.text,
      direction: 'inbound',
      occurredAt: new Date(occurred_at),
      createdAt: new Date(),
    });
    res.sendStatus(200);
  } catch (error: any) {
    console.error('Webhook insert failed:', error.message, error.code);
    if (error.code === 11000) return res.sendStatus(200);
    res.sendStatus(500);
  }
});

app.post('/__grader/reset', async (req, res) => {
  if (req.headers['x-grader-token'] !== config.graderToken) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  const db = await getDb();
  await db.collection('messages').deleteMany({});
  await db.collection('conversations').deleteMany({});
  await db.collection('outbound_jobs').deleteMany({});

  return res.json({ ok: true });
});
app.post('/__grader/reply',express.json(), async (req, res) => {
  if (req.headers['x-grader-token'] !== config.graderToken) {
    return res.sendStatus(401);
  }

  const { workspace, contact, text, client_ref } = req.body ?? {};
  if (
    typeof workspace !== 'string' ||
    typeof contact !== 'string' ||
    typeof text !== 'string' || !text.trim() ||
    typeof client_ref !== 'string' || !client_ref
  ) return res.sendStatus(400);

  const db = await getDb();
  try {
    await db.collection('outbound_jobs').insertOne({
      workspace, contact, text: text.trim(), client_ref,
      status: 'queued', attempts: 0,
      nextAttemptAt: new Date(), createdAt: new Date(),
    });
  } catch (error: any) {
    if (error.code !== 11000) throw error;
  }

  return res.status(202).json({ client_ref, status: 'queued' });
});

app.post('/__grader/claim',express.json(), async (req, res) => {
  if (req.headers['x-grader-token'] !== config.graderToken) {
    return res.sendStatus(401);
  }

  const { workspace, contact, agent } = req.body ?? {};
  if (
    typeof workspace !== 'string' ||
    typeof contact !== 'string' ||
    typeof agent !== 'string' || !agent
  ) return res.sendStatus(400);

  const db = await getDb();
  try {
    const result = await db.collection('conversations').updateOne(
      { workspace, contact, assignee: null },
      {
        $set: { assignee: agent, updatedAt: new Date() },
        $setOnInsert: { workspace, contact, createdAt: new Date() },
      },
      { upsert: true }
    );

    if (result.matchedCount || result.upsertedCount) {
      return res.json({ ok: true, assignee: agent });
    }
    return res.sendStatus(409);
  } catch (error: any) {
    if (error.code === 11000) return res.sendStatus(409);
    throw error;
  }
});
app.get('/__grader/snapshot', async (req, res) => {
  if (req.headers['x-grader-token'] !== config.graderToken) {
    return res.sendStatus(401);
  }

  const db = await getDb();
  const messages = await db.collection('messages')
    .find({})
    .sort({ occurredAt: 1 })
    .toArray();

  const conversations = await db.collection('conversations').find({}).toArray();
  const workspaces: Record<string, any> = {};

  for (const message of messages) {
    const ws = message.workspace;
    const contact = message.contact;

    workspaces[ws] ??= { contacts: {}, outbound: {} };
    workspaces[ws].contacts[contact] ??= { inbound: [] };

    if (message.direction === 'inbound') {
      workspaces[ws].contacts[contact].inbound.push(message.messageId);
    } else if (message.client_ref) {
      workspaces[ws].outbound[message.client_ref] = message.status || 'sent';
    }
  }

  for (const conversation of conversations) {
    workspaces[conversation.workspace] ??= { contacts: {}, outbound: {} };
    workspaces[conversation.workspace].contacts[conversation.contact] ??= { inbound: [] };
    workspaces[conversation.workspace].contacts[conversation.contact].assignee =
      conversation.assignee ?? null;
  }

  return res.json({ workspaces });
});
app.use(express.json());

const server = createServer(app);

async function processOutbound() {
  const db = await getDb();
  const jobs = db.collection('outbound_jobs');
  const now = new Date();

  const job = await jobs.findOneAndUpdate(
    {
      $or: [
        { status: 'queued', nextAttemptAt: { $lte: now } },
        { status: 'processing', lockUntil: { $lte: now } },
      ],
    },
    {
      $set: { status: 'processing', lockUntil: new Date(Date.now() + 30000) },
      $inc: { attempts: 1 },
    },
    { sort: { nextAttemptAt: 1 }, returnDocument: 'after' }
  );

  if (!job) return;

  try {
    const response = await fetch(`${config.pigeon.url}/v1/messages`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${config.pigeon.apiKeys[job.workspace]}`,
        'content-type': 'application/json',
        'idempotency-key': job.client_ref,
      },
      body: JSON.stringify({
        to: job.contact,
        text: job.text,
        client_ref: job.client_ref,
      }),
      signal: AbortSignal.timeout(10000),
    });

    if (!response.ok) {
      const delay = response.status === 429
        ? Number(response.headers.get('retry-after') || 1) * 1000
        : Math.min(1000 * 2 ** job.attempts, 30000);

      throw Object.assign(new Error(`Pigeon ${response.status}`), { delay });
    }

    const result = await response.json() as { id: string; status: string };

    await db.collection('messages').updateOne(
      { workspace: job.workspace, client_ref: job.client_ref },
      {
        $setOnInsert: {
          eventId: `out:${job.workspace}:${job.client_ref}`,
          workspace: job.workspace,
          contact: job.contact,
          messageId: result.id,
          client_ref: job.client_ref,
          text: job.text,
          direction: 'outbound',
          status: result.status || 'sent',
          occurredAt: new Date(),
          createdAt: new Date(),
        },
      },
      { upsert: true }
    );

    await jobs.updateOne(
      { _id: job._id },
      { $set: { status: 'sent', sentAt: new Date(), providerId: result.id }, $unset: { lockUntil: '' } }
    );
  } catch (error: any) {
    await jobs.updateOne(
      { _id: job._id },
      {
        $set: {
          status: 'queued',
          nextAttemptAt: new Date(Date.now() + (error.delay ?? Math.min(1000 * 2 ** job.attempts, 30000))),
          lastError: error.message,
        },
        $unset: { lockUntil: '' },
      }
    );
  }
}

async function start() {
  const db = await getDb();
  await db.collection('conversations').createIndex({ workspace: 1, contact: 1 }, { unique: true });
  await db.collection('messages').createIndex({ eventId: 1 }, { unique: true });
  await db.collection('messages').createIndex({ workspace: 1, messageId: 1 }, { unique: true });
  await db.collection('messages').createIndex({ workspace: 1, contact: 1, occurredAt: 1 });
  await db.collection('outbound_jobs').createIndex({ workspace: 1, client_ref: 1 }, { unique: true });
  await db.collection('outbound_jobs').createIndex({ status: 1, nextAttemptAt: 1 });
  await db.collection('messages').createIndex({ workspace: 1, client_ref: 1 },{unique: true,partialFilterExpression: { client_ref: { $type: 'string' } },}
);
  setInterval(() => {
    processOutbound().catch((error) => console.error('Outbound worker:', error));
  }, 500);

  server.listen(config.port, () => {
    console.log(`server on http://localhost:${config.port}`);
  });
}

start().catch((error) => {
  console.error('Startup failed:', error);
  process.exit(1);
});
