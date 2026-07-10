import { Database } from "bun:sqlite";
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { AuthStorage, type OAuthCredential, SqliteAuthCredentialStore } from "@oh-my-pi/pi-ai/auth-storage";

const PROVIDER = "unit-oauth-refresh-lease";

let tempDir = "";
let storage: AuthStorage | undefined;
let store: SqliteAuthCredentialStore | undefined;
let dbPath = "";

function readCredentialData(id: number): string {
	const db = new Database(dbPath, { readonly: true });
	try {
		const row = db.prepare("SELECT data FROM auth_credentials WHERE id = ?").get(id) as { data?: string } | undefined;
		if (!row?.data) throw new Error(`Credential ${id} is missing`);
		return row.data;
	} finally {
		db.close();
	}
}

beforeEach(async () => {
	tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "pi-ai-oauth-refresh-lease-"));
	dbPath = path.join(tempDir, "agent.db");
	store = await SqliteAuthCredentialStore.open(dbPath);
	storage = new AuthStorage(store);
	await storage.reload();
});

afterEach(async () => {
	storage?.close();
	storage = undefined;
	store = undefined;
	await fs.rm(tempDir, { recursive: true, force: true, maxRetries: 3, retryDelay: 20 });
});

describe("SQLite OAuth refresh lease fencing", () => {
	test("rejects update and disable from a stale or expired owner", async () => {
		if (!storage || !store) throw new Error("test setup failed");
		const original: OAuthCredential = {
			type: "oauth",
			access: "access-old",
			refresh: "refresh-old",
			expires: 0,
		};
		await storage.set(PROVIDER, original);
		const row = store.listAuthCredentials(PROVIDER)[0];
		if (row?.credential.type !== "oauth") throw new Error("Seeded OAuth credential is missing");
		const expectedData = readCredentialData(row.id);
		const rotated: OAuthCredential = {
			...row.credential,
			access: "access-rotated",
			refresh: "refresh-rotated",
			expires: 3_600_000,
		};

		expect(store.tryAcquireOAuthRefreshLease(row.id, "owner-a", 1_000, 0)).toBe(true);
		expect(store.tryAcquireOAuthRefreshLease(row.id, "owner-b", 3_000, 1_000)).toBe(true);

		expect(store.tryUpdateAuthCredentialIfMatches(row.id, expectedData, rotated, "owner-a", 1_001)).toBe(false);
		expect(
			store.tryDisableAuthCredentialIfMatchesOrThrow(row.id, expectedData, "stale failure", "owner-a", 1_001),
		).toBe(false);
		expect(store.tryUpdateAuthCredentialIfMatches(row.id, expectedData, rotated, "owner-b", 3_000)).toBe(false);
		expect(
			store.tryDisableAuthCredentialIfMatchesOrThrow(row.id, expectedData, "expired failure", "owner-b", 3_000),
		).toBe(false);

		expect(store.tryUpdateAuthCredentialIfMatches(row.id, expectedData, rotated, "owner-b", 2_999)).toBe(true);
		expect(store.listAuthCredentials(PROVIDER)[0]?.credential).toMatchObject({
			type: "oauth",
			access: "access-rotated",
			refresh: "refresh-rotated",
		});
	});
});
