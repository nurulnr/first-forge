// main.ts — the entrypoint the harness runs.
//
// It wires the forge (app.ts) to the trial env in three steps:
//   1. Bind an ephemeral port and register it with the env.
//   2. Poll the env until the trial is done.
//   3. Shut the server down and exit 0.
//
// The env's origin comes from MAKEFUN_ENV_URL. The server never binds 8080
// (that port belongs to the env), and the process never exits before the env
// says the trial is over.

import { createApp } from './app.ts';

const envOrigin = (process.env.MAKEFUN_ENV_URL ?? '').replace(/\/+$/, '');
if (!envOrigin) {
  process.stderr.write('[entry] MAKEFUN_ENV_URL is not set\n');
  process.exit(1);
}

/** How long one register or done request may run before it is abandoned. */
const REQUEST_TIMEOUT = 30_000;
/** First wait between retries, and the longest wait. */
const FIRST_RETRY = 250;
const MAX_RETRY = 2_000;

const wait = (ms: number): Promise<void> => new Promise((done) => setTimeout(done, ms));

/** Wait after `failures` failed attempts: exponential from FIRST_RETRY, capped. */
function backoff(failures: number): number {
  return Math.min(MAX_RETRY, FIRST_RETRY * 2 ** Math.min(failures, 8));
}

async function postJson(path: string, payload: unknown): Promise<Response> {
  return fetch(`${envOrigin}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(REQUEST_TIMEOUT),
  });
}

/**
 * POST the bound port until the env accepts it. 200 is the normal answer and
 * 409 means a first register already won, so either one is done. 400 and 405
 * are contract errors and end the program; a network error or any other
 * status is retried, since the env may still be starting.
 */
async function register(port: number): Promise<void> {
  for (let failures = 0; ; failures++) {
    let res: Response;
    try {
      res = await postJson('/register', { port });
    } catch {
      await wait(backoff(failures));
      continue;
    }
    if (res.status === 200 || res.status === 409) return;
    if (res.status === 400 || res.status === 405) {
      throw new Error(`register failed: HTTP ${res.status} ${await res.text()}`);
    }
    await wait(backoff(failures));
  }
}

/** Poll GET /done until it answers {"done": true}; never return before that. */
async function waitDone(): Promise<void> {
  for (let failures = 0; ; failures++) {
    try {
      const res = await fetch(`${envOrigin}/done`, { signal: AbortSignal.timeout(REQUEST_TIMEOUT) });
      if (res.ok && ((await res.json()) as { done?: unknown }).done === true) return;
    } catch {
      // The env is not answering yet, or the poll timed out: poll again.
    }
    await wait(backoff(failures));
  }
}

/** Bind the port, register it, then wait for the env: the whole life of the process. */
async function run(): Promise<void> {
  const server = createApp();
  await new Promise<void>((ok, fail) => {
    server.once('error', fail);
    server.listen(0, ok);
  });
  const bound = server.address();
  if (bound === null || typeof bound === 'string') {
    throw new Error('server did not bind an ephemeral TCP port');
  }
  process.stdout.write(`[entry] listening on ${bound.port}\n`);

  await register(bound.port);
  process.stdout.write('[entry] registered; waiting for done\n');

  await waitDone();
  server.close();
  process.stdout.write('[entry] done\n');
}

try {
  await run();
  process.exit(0);
} catch (err) {
  process.stderr.write(`[entry] ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
}
