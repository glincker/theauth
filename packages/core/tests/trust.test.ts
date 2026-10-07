import { beforeEach, describe, expect, it } from "vitest";
import type { TheAuth } from "../src/theauth.js";
import { createTestTheAuth } from "./helpers.js";

describe("trust – graduated autonomy scoring", () => {
	let theauth: TheAuth;
	let agentId: string;

	beforeEach(async () => {
		theauth = await createTestTheAuth();

		const agent = await theauth.agent.create({
			ownerId: "user-1",
			name: "Trust Test Agent",
			type: "autonomous",
			permissions: [],
		});
		agentId = agent.id;
	});

	it("computes score 50 for a fresh agent with no audit history", async () => {
		const score = await theauth.trust.computeScore(agentId);

		expect(score.agentId).toBe(agentId);
		expect(score.score).toBe(50);
		// Default thresholds: limited=40, standard=60. Score 50 >= 40 but < 60 → limited
		expect(score.level).toBe("limited");
	});

	it("score for a fresh agent with no calls is exactly 50", async () => {
		const score = await theauth.trust.computeScore(agentId);
		expect(score.score).toBe(50);
		expect(score.factors.totalCalls).toBe(0);
		expect(score.factors.denialRate).toBe(0);
		expect(score.factors.anomalyCount).toBe(0);
	});

	it("persists score and retrieves via getScore", async () => {
		await theauth.trust.computeScore(agentId);

		const stored = await theauth.trust.getScore(agentId);
		expect(stored).not.toBeNull();
		expect(stored?.agentId).toBe(agentId);
		expect(typeof stored?.score).toBe("number");
		expect(stored?.computedAt).toBeDefined();
	});

	it("returns null from getScore before first compute", async () => {
		const score = await theauth.trust.getScore(agentId);
		expect(score).toBeNull();
	});

	it("overwrites previous score on recompute", async () => {
		const first = await theauth.trust.computeScore(agentId);
		const second = await theauth.trust.computeScore(agentId);

		// Same agent, same conditions — score should be the same
		expect(second.score).toBe(first.score);
		// But computedAt should be refreshed
		expect(new Date(second.computedAt).getTime()).toBeGreaterThanOrEqual(
			new Date(first.computedAt).getTime(),
		);
	});

	it("computeAll processes all active agents", async () => {
		// Create a second agent
		await theauth.agent.create({
			ownerId: "user-1",
			name: "Second Agent",
			type: "service",
			permissions: [],
		});

		const scores = await theauth.trust.computeAll();
		expect(scores.length).toBeGreaterThanOrEqual(2);
		expect(scores.every((s) => s.score >= 0 && s.score <= 100)).toBe(true);
	});

	it("getScores returns all stored scores", async () => {
		await theauth.trust.computeScore(agentId);
		const scores = await theauth.trust.getScores();
		expect(scores.length).toBeGreaterThanOrEqual(1);
	});

	it("getScores filters by minScore", async () => {
		await theauth.trust.computeScore(agentId);

		const all = await theauth.trust.getScores();
		const agentScore = all.find((s) => s.agentId === agentId);
		expect(agentScore).toBeDefined();

		// Filter at exactly the computed score should include it
		const filtered = await theauth.trust.getScores({ minScore: agentScore?.score });
		expect(filtered.find((s) => s.agentId === agentId)).toBeDefined();

		// Filter above the computed score should exclude it
		const tooHigh = await theauth.trust.getScores({ minScore: agentScore?.score + 1 });
		expect(tooHigh.find((s) => s.agentId === agentId)).toBeUndefined();
	});

	it("getScores filters by level", async () => {
		await theauth.trust.computeScore(agentId);

		const all = await theauth.trust.getScores();
		const agentScore = all.find((s) => s.agentId === agentId);
		expect(agentScore).toBeDefined();

		const byLevel = await theauth.trust.getScores({ level: agentScore?.level });
		expect(byLevel.find((s) => s.agentId === agentId)).toBeDefined();

		// A different level should not include this agent
		const wrongLevel = await theauth.trust.getScores({ level: "elevated" });
		// Fresh agent won't have elevated score (50 < 95)
		expect(wrongLevel.find((s) => s.agentId === agentId)).toBeUndefined();
	});

	it("score level boundaries respect thresholds", async () => {
		const { createTrustModule } = await import("../src/trust/scoring.js");

		// Access db directly for testing
		const trustWithCustomThresholds = createTrustModule(
			{
				thresholds: {
					untrusted: 10,
					limited: 30,
					standard: 50,
					trusted: 70,
					elevated: 90,
				},
			},
			theauth.db,
		);

		const score = await trustWithCustomThresholds.computeScore(agentId);
		// Fresh agent score is 50 — with standard threshold at 50, should be "standard"
		expect(score.score).toBe(50);
		expect(score.level).toBe("standard");
	});

	it("score is clamped to 0-100", async () => {
		const score = await theauth.trust.computeScore(agentId);
		expect(score.score).toBeGreaterThanOrEqual(0);
		expect(score.score).toBeLessThanOrEqual(100);
	});

	it("factors include all required fields", async () => {
		const score = await theauth.trust.computeScore(agentId);
		expect(score.factors).toHaveProperty("successRate");
		expect(score.factors).toHaveProperty("denialRate");
		expect(score.factors).toHaveProperty("ageInDays");
		expect(score.factors).toHaveProperty("totalCalls");
		expect(score.factors).toHaveProperty("anomalyCount");
		expect(score.factors.ageInDays).toBeGreaterThanOrEqual(0);
	});
});
