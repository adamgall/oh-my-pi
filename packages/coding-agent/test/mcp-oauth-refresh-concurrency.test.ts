import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import type { OAuthCredential } from "@oh-my-pi/pi-ai";
import { MCPManager } from "@oh-my-pi/pi-coding-agent/mcp/manager";
import { type MCPStoredOAuthCredential, refreshMCPOAuthToken } from "@oh-my-pi/pi-coding-agent/mcp/oauth-flow";
import type { MCPServerConfig } from "@oh-my-pi/pi-coding-agent/mcp/types";
import { AuthStorage, REMOTE_REFRESH_SENTINEL } from "@oh-my-pi/pi-coding-agent/session/auth-storage";
import { withTimeout } from "@oh-my-pi/pi-utils";

type RefreshClientProcess = Bun.Subprocess<"ignore", "pipe", "pipe">;

type RefreshClientSuccess = {
	ok: true;
	pid: number;
	loaded: Pick<OAuthCredential, "access" | "expires" | "refresh">;
	authorization?: string;
};

type RefreshClientResult =
	| RefreshClientSuccess
	| {
			ok: false;
			pid: number;
			error: string;
	  };

type BarrierArrival = {
	pid: number;
	loaded: Pick<OAuthCredential, "access" | "expires" | "refresh">;
};

const CREDENTIAL_ID = "mcp_oauth_refresh_concurrency";
const OLD_ACCESS = "access-old";
const OLD_REFRESH = "refresh-old";
const NEW_ACCESS = "access-rotated";
const NEW_REFRESH = "refresh-rotated";
const PROCESS_TIMEOUT_MS = 8_000;
const LOCAL_WAIT_TIMEOUT_MS = 2_000;
const repoRoot = path.resolve(import.meta.dir, "..", "..", "..");
const refreshClientPath = path.join(import.meta.dir, "helpers", "mcp-oauth-refresh-client.ts");

let tempRoot = "";
let activeProcesses: Set<RefreshClientProcess>;
let activeServers: Set<Bun.Server<undefined>>;
let activeStorages: Set<AuthStorage>;

function oauthCredential(access: string, refresh: string, expires: number, tokenUrl: string): MCPStoredOAuthCredential {
	return {
		type: "oauth",
		access,
		refresh,
		expires,
		tokenUrl,
		clientId: "test-client",
	};
}

function authorizationHeader(config: MCPServerConfig): string | undefined {
	if (config.type !== "http" && config.type !== "sse") return undefined;
	return config.headers?.Authorization;
}

// These are hard failure deadlines around real subprocess/HTTP integration.
// Fake timers cannot advance another PID or Bun's socket I/O and would make hung regressions stall the suite.
async function within<T>(promise: Promise<T>, timeoutMs: number, label: string, onTimeout?: () => void): Promise<T> {
	const timeoutMessage = `${label} timed out after ${timeoutMs}ms`;
	try {
		return await withTimeout(promise, timeoutMs, timeoutMessage);
	} catch (error) {
		if (error instanceof Error && error.message === timeoutMessage) onTimeout?.();
		throw error;
	}
}

async function openStorage(dbPath: string): Promise<AuthStorage> {
	const storage = await AuthStorage.create(dbPath);
	activeStorages.add(storage);
	await storage.reload();
	return storage;
}

function startServer(fetchHandler: (request: Request) => Response | Promise<Response>): Bun.Server<undefined> {
	const server = Bun.serve({
		hostname: "127.0.0.1",
		port: 0,
		fetch: fetchHandler,
	});
	activeServers.add(server);
	return server;
}

function tokenUrl(server: Bun.Server<undefined>): string {
	return `http://127.0.0.1:${server.port}/token`;
}

function serverConfig(server: Bun.Server<undefined>): MCPServerConfig {
	return {
		type: "http",
		url: `http://127.0.0.1:${server.port}/mcp`,
		auth: { type: "oauth", credentialId: CREDENTIAL_ID },
	};
}

function invalidGrant(): Response {
	return Response.json(
		{ error: "invalid_grant", error_description: "refresh token is no longer active" },
		{ status: 400 },
	);
}

async function refreshTokenFrom(request: Request): Promise<string | null> {
	const params = new URLSearchParams(await request.text());
	return params.get("refresh_token");
}

function spawnRefreshClient(
	dbPath: string,
	barrierUrl: string,
	mcpServerUrl: string,
	mode: "forced" | "proactive" = "proactive",
): RefreshClientProcess {
	const proc = Bun.spawn(
		[process.execPath, refreshClientPath, dbPath, barrierUrl, mcpServerUrl, CREDENTIAL_ID, mode],
		{
			cwd: repoRoot,
			stdin: "ignore",
			stdout: "pipe",
			stderr: "pipe",
			env: { ...process.env, NO_COLOR: "1", PI_NO_TITLE: "1" },
		},
	);
	activeProcesses.add(proc);
	return proc;
}

function killProcess(proc: RefreshClientProcess): void {
	try {
		proc.kill("SIGKILL");
	} catch {
		// The child may have exited between the deadline and cleanup.
	}
}

async function readClientResult(proc: RefreshClientProcess, label: string): Promise<RefreshClientSuccess> {
	const stdout = new Response(proc.stdout).text();
	const stderr = new Response(proc.stderr).text();
	const [exitCode, stdoutText, stderrText] = await within(
		Promise.all([proc.exited, stdout, stderr]),
		PROCESS_TIMEOUT_MS,
		label,
		() => killProcess(proc),
	);
	activeProcesses.delete(proc);

	const lines = stdoutText.trim().split(/\r?\n/).filter(Boolean);
	if (lines.length !== 1) {
		throw new Error(`${label} wrote ${lines.length} stdout records; stderr: ${stderrText}`);
	}
	const result = JSON.parse(lines[0]!) as RefreshClientResult;
	if (exitCode !== 0 || !result.ok) {
		const childError = result.ok ? `exit ${exitCode}` : result.error;
		throw new Error(`${label} failed: ${childError}; stderr: ${stderrText}`);
	}
	return result;
}

// Cleanup is also bounded because the process under test may be wedged in native SQLite/socket work.
async function stopProcess(proc: RefreshClientProcess): Promise<void> {
	killProcess(proc);
	await withTimeout(proc.exited, 1_000, "Refresh client did not exit after SIGKILL").catch(() => undefined);
}

beforeEach(async () => {
	tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "omp-mcp-oauth-refresh-"));
	activeProcesses = new Set();
	activeServers = new Set();
	activeStorages = new Set();
});

afterEach(async () => {
	await Promise.all([...activeProcesses].map(proc => stopProcess(proc)));
	activeProcesses.clear();
	for (const server of activeServers) server.stop(true);
	activeServers.clear();
	for (const storage of activeStorages) storage.close();
	activeStorages.clear();
	await fs.rm(tempRoot, { recursive: true, force: true, maxRetries: 3, retryDelay: 20 });
});

describe("MCP OAuth refresh ownership", () => {
	test("serializes stale refreshes across processes and makes the waiter reuse the rotation", async () => {
		const dbPath = path.join(tempRoot, "shared-auth.db");
		let currentRefresh = OLD_REFRESH;
		const refreshRequests: Array<string | null> = [];
		const tokens = startServer(async request => {
			if (new URL(request.url).pathname !== "/token") return new Response("not found", { status: 404 });
			const suppliedRefresh = await refreshTokenFrom(request);
			refreshRequests.push(suppliedRefresh);
			if (suppliedRefresh !== currentRefresh) return invalidGrant();
			currentRefresh = NEW_REFRESH;
			return Response.json({ access_token: NEW_ACCESS, refresh_token: NEW_REFRESH, expires_in: 3600 });
		});

		const seed = await openStorage(dbPath);
		await seed.set(CREDENTIAL_ID, oauthCredential(OLD_ACCESS, OLD_REFRESH, Date.now() - 60_000, tokenUrl(tokens)));

		const arrivals: BarrierArrival[] = [];
		const bothLoaded = Promise.withResolvers<readonly BarrierArrival[]>();
		const releaseBarrier = Promise.withResolvers<void>();
		const barrier = startServer(async request => {
			if (new URL(request.url).pathname !== "/ready") return new Response("not found", { status: 404 });
			const arrival = (await request.json()) as BarrierArrival;
			arrivals.push(arrival);
			if (arrivals.length === 2) bothLoaded.resolve([...arrivals]);
			await releaseBarrier.promise;
			return Response.json({ released: true });
		});
		const barrierUrl = `http://127.0.0.1:${barrier.port}/ready`;
		const mcpServerUrl = `http://127.0.0.1:${tokens.port}/mcp`;
		const first = spawnRefreshClient(dbPath, barrierUrl, mcpServerUrl);
		const second = spawnRefreshClient(dbPath, barrierUrl, mcpServerUrl);

		try {
			const staleSnapshots = await within(bothLoaded.promise, PROCESS_TIMEOUT_MS, "two stale child loads", () => {
				killProcess(first);
				killProcess(second);
			});
			expect(staleSnapshots).toHaveLength(2);
			expect(new Set(staleSnapshots.map(item => item.pid)).size).toBe(2);
			for (const arrival of staleSnapshots) {
				expect(arrival.loaded).toMatchObject({ access: OLD_ACCESS, refresh: OLD_REFRESH });
				expect(arrival.loaded.expires).toBeLessThan(Date.now());
			}
			releaseBarrier.resolve();

			const [firstResult, secondResult] = await Promise.all([
				readClientResult(first, "first refresh client"),
				readClientResult(second, "second refresh client"),
			]);
			expect(firstResult.authorization).toBe(`Bearer ${NEW_ACCESS}`);
			expect(secondResult.authorization).toBe(`Bearer ${NEW_ACCESS}`);
			expect(refreshRequests).toEqual([OLD_REFRESH]);

			const canonical = await openStorage(dbPath);
			expect(canonical.get(CREDENTIAL_ID)).toMatchObject({
				type: "oauth",
				access: NEW_ACCESS,
				refresh: NEW_REFRESH,
			});
		} finally {
			releaseBarrier.resolve();
		}
	}, 20_000);

	test("keeps a newer canonical credential when a stale owner loses an invalid_grant CAS", async () => {
		const dbPath = path.join(tempRoot, "stale-loser.db");
		const requestStarted = Promise.withResolvers<void>();
		const releaseFailure = Promise.withResolvers<void>();
		const refreshRequests: Array<string | null> = [];
		const tokens = startServer(async request => {
			if (new URL(request.url).pathname !== "/token") return new Response("not found", { status: 404 });
			refreshRequests.push(await refreshTokenFrom(request));
			requestStarted.resolve();
			await releaseFailure.promise;
			return invalidGrant();
		});
		const ownerStorage = await openStorage(dbPath);
		await ownerStorage.set(
			CREDENTIAL_ID,
			oauthCredential(OLD_ACCESS, OLD_REFRESH, Date.now() - 60_000, tokenUrl(tokens)),
		);
		const manager = new MCPManager(tempRoot);
		manager.setAuthStorage(ownerStorage);
		const preparing = manager.prepareConfig(serverConfig(tokens));

		try {
			await within(requestStarted.promise, LOCAL_WAIT_TIMEOUT_MS, "stale refresh request");
			const competingStorage = await openStorage(dbPath);
			await competingStorage.set(
				CREDENTIAL_ID,
				oauthCredential(NEW_ACCESS, NEW_REFRESH, Date.now() + 3_600_000, tokenUrl(tokens)),
			);
			releaseFailure.resolve();

			const prepared = await within(preparing, LOCAL_WAIT_TIMEOUT_MS, "stale loser prepareConfig");
			expect(authorizationHeader(prepared)).toBe(`Bearer ${NEW_ACCESS}`);
			expect(refreshRequests).toEqual([OLD_REFRESH]);
			const canonical = await openStorage(dbPath);
			expect(canonical.get(CREDENTIAL_ID)).toMatchObject({
				type: "oauth",
				access: NEW_ACCESS,
				refresh: NEW_REFRESH,
			});
		} finally {
			releaseFailure.resolve();
		}
	});

	test("disables an unchanged credential after a genuine terminal refresh failure", async () => {
		const dbPath = path.join(tempRoot, "terminal-failure.db");
		const refreshRequests: Array<string | null> = [];
		const tokens = startServer(async request => {
			if (new URL(request.url).pathname !== "/token") return new Response("not found", { status: 404 });
			refreshRequests.push(await refreshTokenFrom(request));
			return invalidGrant();
		});
		const storage = await openStorage(dbPath);
		await storage.set(CREDENTIAL_ID, oauthCredential(OLD_ACCESS, OLD_REFRESH, Date.now() - 60_000, tokenUrl(tokens)));
		const manager = new MCPManager(tempRoot);
		manager.setAuthStorage(storage);

		const prepared = await within(
			manager.prepareConfig(serverConfig(tokens)),
			LOCAL_WAIT_TIMEOUT_MS,
			"terminal refresh failure",
		);

		expect(refreshRequests).toEqual([OLD_REFRESH]);
		expect(authorizationHeader(prepared)).toBeUndefined();
		await storage.reload();
		expect(storage.get(CREDENTIAL_ID)).toBeUndefined();
	});

	test("keeps the credential when a 401 carries safe transient failure evidence", async () => {
		const dbPath = path.join(tempRoot, "transient-401.db");
		const refreshRequests: Array<string | null> = [];
		const tokens = startServer(async request => {
			if (new URL(request.url).pathname !== "/token") return new Response("not found", { status: 404 });
			refreshRequests.push(await refreshTokenFrom(request));
			return Response.json(
				{ error: "gateway_challenge", error_description: "Cloudflare captcha temporarily unavailable" },
				{ status: 401 },
			);
		});
		const storage = await openStorage(dbPath);
		await storage.set(CREDENTIAL_ID, oauthCredential(OLD_ACCESS, OLD_REFRESH, Date.now() - 60_000, tokenUrl(tokens)));
		const manager = new MCPManager(tempRoot);
		manager.setAuthStorage(storage);

		const prepared = await within(
			manager.prepareConfig(serverConfig(tokens)),
			LOCAL_WAIT_TIMEOUT_MS,
			"transient 401 refresh failure",
		);

		expect(refreshRequests).toEqual([OLD_REFRESH]);
		expect(authorizationHeader(prepared)).toBe(`Bearer ${OLD_ACCESS}`);
		expect(storage.get(CREDENTIAL_ID)).toMatchObject({
			type: "oauth",
			access: OLD_ACCESS,
			refresh: OLD_REFRESH,
		});
	});

	test("refreshes a future-valid credential only when the caller forces refresh", async () => {
		const dbPath = path.join(tempRoot, "forced-refresh.db");
		const refreshRequests: Array<string | null> = [];
		const tokens = startServer(async request => {
			if (new URL(request.url).pathname !== "/token") return new Response("not found", { status: 404 });
			const suppliedRefresh = await refreshTokenFrom(request);
			refreshRequests.push(suppliedRefresh);
			if (suppliedRefresh !== OLD_REFRESH) return invalidGrant();
			return Response.json({ access_token: NEW_ACCESS, refresh_token: NEW_REFRESH, expires_in: 3600 });
		});
		const storage = await openStorage(dbPath);
		await storage.set(
			CREDENTIAL_ID,
			oauthCredential(OLD_ACCESS, OLD_REFRESH, Date.now() + 3_600_000, tokenUrl(tokens)),
		);
		const manager = new MCPManager(tempRoot);
		manager.setAuthStorage(storage);

		const proactive = await manager.prepareConfig(serverConfig(tokens));
		expect(authorizationHeader(proactive)).toBe(`Bearer ${OLD_ACCESS}`);
		expect(refreshRequests).toEqual([]);

		const forced = await within(
			manager.prepareConfig(serverConfig(tokens), { forceRefresh: true }),
			LOCAL_WAIT_TIMEOUT_MS,
			"forced refresh",
		);
		expect(authorizationHeader(forced)).toBe(`Bearer ${NEW_ACCESS}`);
		expect(refreshRequests).toEqual([OLD_REFRESH]);
		await storage.reload();
		expect(storage.get(CREDENTIAL_ID)).toMatchObject({
			type: "oauth",
			access: NEW_ACCESS,
			refresh: NEW_REFRESH,
		});
	});

	test("never sends a broker refresh sentinel to an upstream token endpoint", async () => {
		const dbPath = path.join(tempRoot, "broker-sentinel.db");
		const refreshRequests: Array<string | null> = [];
		const tokens = startServer(async request => {
			if (new URL(request.url).pathname !== "/token") return new Response("not found", { status: 404 });
			refreshRequests.push(await refreshTokenFrom(request));
			return invalidGrant();
		});
		const storage = await openStorage(dbPath);
		await storage.set(
			CREDENTIAL_ID,
			oauthCredential(OLD_ACCESS, REMOTE_REFRESH_SENTINEL, Date.now() - 60_000, tokenUrl(tokens)),
		);
		const manager = new MCPManager(tempRoot);
		manager.setAuthStorage(storage);

		const prepared = await within(
			manager.prepareConfig(serverConfig(tokens)),
			LOCAL_WAIT_TIMEOUT_MS,
			"broker sentinel guard",
		);

		expect(refreshRequests).toEqual([]);
		expect(authorizationHeader(prepared)).toBe(`Bearer ${OLD_ACCESS}`);
		expect(storage.get(CREDENTIAL_ID)).toMatchObject({
			type: "oauth",
			access: OLD_ACCESS,
			refresh: REMOTE_REFRESH_SENTINEL,
		});
	});

	test("releases refresh ownership after HTTP failure and caller abort", async () => {
		const dbPath = path.join(tempRoot, "lock-cleanup.db");
		type ServerMode = "abort" | "success" | "throw";
		let mode: ServerMode = "throw";
		const refreshRequests: Array<string | null> = [];
		const abortRequestStarted = Promise.withResolvers<void>();
		const releaseAbortedResponse = Promise.withResolvers<void>();
		const tokens = startServer(async request => {
			if (new URL(request.url).pathname !== "/token") return new Response("not found", { status: 404 });
			refreshRequests.push(await refreshTokenFrom(request));
			const requestMode = mode;
			if (requestMode === "throw") return new Response("temporary upstream failure", { status: 500 });
			if (requestMode === "abort") {
				abortRequestStarted.resolve();
				await releaseAbortedResponse.promise;
			}
			return Response.json({ access_token: NEW_ACCESS, refresh_token: NEW_REFRESH, expires_in: 3600 });
		});
		const storage = await openStorage(dbPath);
		await storage.set(CREDENTIAL_ID, oauthCredential(OLD_ACCESS, OLD_REFRESH, Date.now() - 60_000, tokenUrl(tokens)));
		const stored = storage.listStoredCredentials(CREDENTIAL_ID)[0];
		if (stored?.credential.type !== "oauth") throw new Error("Seeded OAuth row is missing");
		const rowId = stored.id;
		const expectedCredential = stored.credential;
		const refreshThroughHttp = async (credential: OAuthCredential, signal: AbortSignal): Promise<OAuthCredential> => {
			const refreshed = await refreshMCPOAuthToken(tokenUrl(tokens), credential.refresh, undefined, undefined, {
				signal,
			});
			return { ...credential, ...refreshed };
		};

		await expect(
			within(
				storage.refreshStoredOAuthCredential(rowId, expectedCredential, refreshThroughHttp, { timeoutMs: 1_000 }),
				LOCAL_WAIT_TIMEOUT_MS,
				"throwing refresh owner",
			),
		).rejects.toThrow(/500/);

		mode = "abort";
		const abortController = new AbortController();
		const abortedRefresh = storage.refreshStoredOAuthCredential(rowId, expectedCredential, refreshThroughHttp, {
			signal: abortController.signal,
			timeoutMs: 1_000,
		});
		await within(abortRequestStarted.promise, LOCAL_WAIT_TIMEOUT_MS, "post-throw owner acquisition");
		abortController.abort();
		await expect(within(abortedRefresh, LOCAL_WAIT_TIMEOUT_MS, "aborted refresh caller")).rejects.toThrow();

		// Caller cancellation must not abandon a rotating-token exchange that may
		// already have been consumed upstream. Let the shared owner finish, then
		// make the next caller await/reuse that same persisted rotation.
		releaseAbortedResponse.resolve();
		mode = "success";
		const recovered = await within(
			storage.refreshStoredOAuthCredential(rowId, expectedCredential, refreshThroughHttp, { timeoutMs: 1_000 }),
			LOCAL_WAIT_TIMEOUT_MS,
			"post-abort shared refresh",
		);
		expect(recovered).toMatchObject({ access: NEW_ACCESS, refresh: NEW_REFRESH });
		expect(refreshRequests).toEqual([OLD_REFRESH, OLD_REFRESH]);
		await storage.reload();
		expect(storage.get(CREDENTIAL_ID)).toMatchObject({
			type: "oauth",
			access: NEW_ACCESS,
			refresh: NEW_REFRESH,
		});
	});
});
