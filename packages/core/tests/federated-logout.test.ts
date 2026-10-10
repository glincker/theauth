import { SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import {
	BACKCHANNEL_LOGOUT_EVENT,
	createBackChannelLogoutReceiver,
} from "../src/auth/federated-logout.js";

const secret = new TextEncoder().encode("0123456789abcdef0123456789abcdef");
const ISS = "https://idp.example.com";
const AUD = "client-1";

async function logoutToken(jti: string): Promise<string> {
	return new SignJWT({ sub: "user-1", events: { [BACKCHANNEL_LOGOUT_EVENT]: {} } })
		.setProtectedHeader({ alg: "HS256", typ: "logout+jwt" })
		.setIssuer(ISS)
		.setAudience(AUD)
		.setIssuedAt()
		.setJti(jti)
		.sign(secret);
}

describe("back-channel logout token verification key forms", () => {
	it("accepts a static key", async () => {
		const receiver = createBackChannelLogoutReceiver({
			issuer: ISS,
			clientId: AUD,
			verificationKey: secret,
			algorithms: ["HS256"],
		});
		const result = await receiver.verifyLogoutToken(await logoutToken("static-1"));
		expect(result.success).toBe(true);
		if (result.success) expect(result.data.sub).toBe("user-1");
	});

	it("accepts a key resolver", async () => {
		const receiver = createBackChannelLogoutReceiver({
			issuer: ISS,
			clientId: AUD,
			verificationKey: async () => secret,
			algorithms: ["HS256"],
		});
		const result = await receiver.verifyLogoutToken(await logoutToken("resolver-1"));
		expect(result.success).toBe(true);
	});

	it("rejects a token signed with a different key", async () => {
		const receiver = createBackChannelLogoutReceiver({
			issuer: ISS,
			clientId: AUD,
			verificationKey: new TextEncoder().encode("fedcba9876543210fedcba9876543210"),
			algorithms: ["HS256"],
		});
		const result = await receiver.verifyLogoutToken(await logoutToken("wrong-1"));
		expect(result.success).toBe(false);
	});
});
