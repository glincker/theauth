/**
 * Signed audit checkpoints and a portable receipt.
 *
 * The operator signs a checkpoint of the audit log, mints a receipt for one
 * approval decision, and a counterparty verifies it offline with only the
 * public key. Needs the checkpoint exports wired into "@glinr/theauth".
 */
import {
	createCheckpoint,
	createConsistencyProof,
	createReceipt,
	createTheAuth,
	generateCheckpointKeyPair,
	insertAuditRow,
	users,
	verifyConsistencyProof,
	verifyReceipt,
} from "@glinr/theauth";

const OWNER = "user-alice";

function say(text: string): void {
	console.log(text);
}

const auth = await createTheAuth({
	database: { provider: "sqlite", url: ":memory:" },
	agents: { enabled: true, maxPerUser: 10, defaultPermissions: [], auditAll: true },
	audit: { tamperEvident: true, hmacKey: "demo-only-hmac-key" },
});
await auth.db.insert(users).values({
	id: OWNER,
	email: "alice@example.com",
	name: "Alice",
	username: "alice",
	createdAt: new Date(),
	updatedAt: new Date(),
});
const agent = await auth.agent.create({
	ownerId: OWNER,
	name: "refund-worker",
	type: "autonomous",
	permissions: [],
});

const now = Date.now();
const record = (id: string, result: "allowed" | "denied", offsetSec: number) =>
	insertAuditRow(auth.db, {
		id,
		agentId: agent.id,
		userId: OWNER,
		action: "execute",
		resource: "mcp:payments:refund",
		parameters: { orderId: `order-${id}`, amountCents: 4200 },
		result,
		reason: null,
		durationMs: 12,
		timestamp: new Date(now + offsetSec * 1000),
		approverId: OWNER,
	});
await record("decision-1", "allowed", 1);
await record("decision-2", "allowed", 2);
await record("decision-3", "denied", 3);

// Operator side: sign the log head, then mint a receipt for decision-2.
const keys = await generateCheckpointKeyPair("audit-2026-10");
const first = await createCheckpoint(auth.db, { signer: keys.signer });
if (!first.success) throw new Error(first.error.message);
say(`checkpoint: size=${first.data.size} root=${first.data.rootHash.slice(0, 16)}...`);

const receipt = await createReceipt(auth.db, "decision-2", first.data, {
	reveal: ["action", "resource", "result", "timestamp"],
});
if (!receipt.success) throw new Error(receipt.error.message);
const wire = JSON.stringify(receipt.data);
say(`receipt is ${wire.length} bytes and hides the parameters`);

// Counterparty side: only the receipt JSON and the published public key.
const verdict = await verifyReceipt(JSON.parse(wire), keys.publicKey);
say(`receipt verifies: ${verdict.valid}`);

// Later: the log grew. Prove the new head extends the old one.
await record("decision-4", "allowed", 4);
const second = await createCheckpoint(auth.db, { signer: keys.signer });
if (!second.success) throw new Error(second.error.message);
const consistency = await createConsistencyProof(auth.db, first.data, second.data);
if (!consistency.success) throw new Error(consistency.error.message);
const extended = await verifyConsistencyProof(
	consistency.data,
	first.data,
	second.data,
	keys.publicKey,
);
say(`newer checkpoint extends the older: ${extended.valid}`);
