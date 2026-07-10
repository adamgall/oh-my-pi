import type { OAuthCredential } from "@oh-my-pi/pi-ai";
import { MCPManager } from "@oh-my-pi/pi-coding-agent/mcp/manager";
import type { MCPServerConfig } from "@oh-my-pi/pi-coding-agent/mcp/types";
import { AuthStorage } from "@oh-my-pi/pi-coding-agent/session/auth-storage";

type RefreshMode = "forced" | "proactive";

type LoadedOAuthCredential = Pick<OAuthCredential, "access" | "expires" | "refresh">;

type ClientResult =
	| {
			ok: true;
			pid: number;
			loaded: LoadedOAuthCredential;
			authorization?: string;
	  }
	| {
			ok: false;
			pid: number;
			error: string;
	  };

const BARRIER_TIMEOUT_MS = 5_000;

function requireArgument(value: string | undefined, name: string): string {
	if (!value) throw new Error(`Missing ${name}`);
	return value;
}

function authorizationHeader(config: MCPServerConfig): string | undefined {
	if (config.type !== "http" && config.type !== "sse") return undefined;
	return config.headers?.Authorization;
}

async function run(): Promise<ClientResult> {
	const [dbArg, barrierArg, serverArg, credentialIdArg, modeArg] = Bun.argv.slice(2);
	const dbPath = requireArgument(dbArg, "database path");
	const barrierUrl = requireArgument(barrierArg, "barrier URL");
	const serverUrl = requireArgument(serverArg, "MCP server URL");
	const credentialId = requireArgument(credentialIdArg, "credential ID");
	const mode = requireArgument(modeArg, "refresh mode") as RefreshMode;
	if (mode !== "proactive" && mode !== "forced") throw new Error(`Invalid refresh mode: ${mode}`);

	const authStorage = await AuthStorage.create(dbPath);
	try {
		await authStorage.reload();
		const loaded = authStorage.get(credentialId);
		if (loaded?.type !== "oauth") throw new Error(`OAuth credential not found: ${credentialId}`);
		const loadedSnapshot: LoadedOAuthCredential = {
			access: loaded.access,
			refresh: loaded.refresh,
			expires: loaded.expires,
		};

		const barrierResponse = await fetch(barrierUrl, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ pid: process.pid, loaded: loadedSnapshot }),
			signal: AbortSignal.timeout(BARRIER_TIMEOUT_MS),
		});
		if (!barrierResponse.ok) {
			throw new Error(`Barrier rejected client: ${barrierResponse.status}`);
		}
		await barrierResponse.body?.cancel();

		const manager = new MCPManager(process.cwd());
		manager.setAuthStorage(authStorage);
		const prepared = await manager.prepareConfig(
			{
				type: "http",
				url: serverUrl,
				auth: { type: "oauth", credentialId },
			},
			mode === "forced" ? { forceRefresh: true } : undefined,
		);
		return {
			ok: true,
			pid: process.pid,
			loaded: loadedSnapshot,
			authorization: authorizationHeader(prepared),
		};
	} finally {
		authStorage.close();
	}
}

let result: ClientResult;
try {
	result = await run();
} catch (error) {
	result = {
		ok: false,
		pid: process.pid,
		error: error instanceof Error ? error.message : String(error),
	};
	process.exitCode = 1;
}
await Bun.stdout.write(`${JSON.stringify(result)}\n`);
