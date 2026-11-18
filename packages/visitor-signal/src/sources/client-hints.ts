import { fail, ok } from "../result.js";
import type { Result } from "../types.js";

export interface UaData {
	platform?: string;
	uaBrand?: string;
	uaMajor?: number;
	mobile?: boolean;
}

interface UaBrand {
	brand: string;
	version: string;
}
interface UaDataLike {
	brands?: UaBrand[];
	mobile?: boolean;
	platform?: string;
}

const GREASE = /not.?a.?brand|^chromium$/i;

/** Pick the most specific brand: skip GREASE entries, prefer a non-Chromium brand. */
export const pickBrand = (brands: readonly UaBrand[]): UaBrand | undefined => {
	const real = brands.filter((b) => !/not.?a.?brand/i.test(b.brand));
	return real.find((b) => !GREASE.test(b.brand)) ?? real[0];
};

/** Chromium forks report their own version in the brand, the engine major is stable across them. */
export const pickMajor = (brands: readonly UaBrand[], picked: UaBrand): number | undefined => {
	const chromium = brands.find((b) => b.brand.toLowerCase() === "chromium");
	return parseMajor((chromium ?? picked).version);
};

export const parseMajor = (version: string): number | undefined => {
	const major = Number.parseInt(version.split(".")[0] ?? "", 10);
	return Number.isFinite(major) && major >= 0 && major <= 999 ? major : undefined;
};

/** Fallback for browsers without client hints. */
export const brandFromUserAgent = (ua: string): { brand: string; major: number } | undefined => {
	const patterns: Array<[string, RegExp]> = [
		["Edge", /Edg\/(\d+)/],
		["Firefox", /Firefox\/(\d+)/],
		["Chrome", /Chrome\/(\d+)/],
		["Safari", /Version\/(\d+).*Safari/],
	];
	for (const [brand, re] of patterns) {
		const m = re.exec(ua);
		const major = m?.[1] ? parseMajor(m[1]) : undefined;
		if (major !== undefined) return { brand, major };
	}
	return undefined;
};

export const clientHints = async (): Promise<Result<UaData>> => {
	const nav = globalThis.navigator;
	if (!nav) return fail("unavailable", "navigator missing");
	const data: UaData = {};
	const uad = (nav as Navigator & { userAgentData?: UaDataLike }).userAgentData;
	if (uad) {
		if (typeof uad.mobile === "boolean") data.mobile = uad.mobile;
		if (uad.platform) data.platform = uad.platform.slice(0, 32);
		const picked = uad.brands ? pickBrand(uad.brands) : undefined;
		if (picked) {
			data.uaBrand = picked.brand.slice(0, 32);
			const major = pickMajor(uad.brands ?? [], picked);
			if (major !== undefined) data.uaMajor = major;
		}
	}
	if (data.platform === undefined && nav.platform) data.platform = nav.platform.slice(0, 32);
	if (data.uaBrand === undefined && nav.userAgent) {
		const parsed = brandFromUserAgent(nav.userAgent);
		if (parsed) {
			data.uaBrand = parsed.brand;
			data.uaMajor = parsed.major;
		}
	}
	return Object.keys(data).length > 0 ? ok(data) : fail("unavailable", "no ua data");
};
