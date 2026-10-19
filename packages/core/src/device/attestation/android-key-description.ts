import type { Tlv } from "./der.js";
import {
	bigIntOf,
	boolOf,
	children,
	intOf,
	isUniversal,
	parseOne,
	stringOf,
	TAG,
	toHexLower,
} from "./der.js";

/** OID of the key attestation extension (Android Keystore attestation schema). */
export const KEY_ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";
/** OID of the provisioning information extension present in Remote Key Provisioning chains. */
export const PROVISIONING_INFO_OID = "1.3.6.1.4.1.11129.2.1.30";

export type AttestationSecurityLevel = "software" | "trusted_environment" | "strongbox";
export type VerifiedBootState = "verified" | "self_signed" | "unverified" | "failed";

const LEVELS: AttestationSecurityLevel[] = ["software", "trusted_environment", "strongbox"];
const BOOT_STATES: VerifiedBootState[] = ["verified", "self_signed", "unverified", "failed"];

export interface RootOfTrust {
	verifiedBootKey: string;
	deviceLocked: boolean;
	verifiedBootState: VerifiedBootState;
	verifiedBootHash?: string;
}

export interface ApplicationId {
	packages: Array<{ name: string; version: number }>;
	/** SHA-256 digests of the app signing certificates, lowercase hex. */
	signatureDigests: string[];
}

export interface AuthorizationList {
	purpose?: number[];
	algorithm?: number;
	keySize?: number;
	ecCurve?: number;
	/** 0 GENERATED, 1 DERIVED, 2 IMPORTED, 3 UNKNOWN, 4 SECURELY_IMPORTED. */
	origin?: number;
	rootOfTrust?: RootOfTrust;
	osVersion?: number;
	osPatchLevel?: number;
	vendorPatchLevel?: number;
	bootPatchLevel?: number;
	applicationId?: ApplicationId;
	/** attestationIdBrand, Device, Product, Serial, Manufacturer, Model (tags 710 to 717). */
	ids: Partial<
		Record<"brand" | "device" | "product" | "serial" | "manufacturer" | "model", string>
	>;
}

export interface KeyDescription {
	attestationVersion: number;
	attestationSecurityLevel: AttestationSecurityLevel;
	keymasterVersion: number;
	keymasterSecurityLevel: AttestationSecurityLevel;
	attestationChallenge: Uint8Array;
	uniqueId: Uint8Array;
	softwareEnforced: AuthorizationList;
	/** Called `teeEnforced` before attestation version 100. */
	hardwareEnforced: AuthorizationList;
}

function level(t: Tlv): AttestationSecurityLevel {
	const v = LEVELS[intOf(t)];
	if (!v) throw new Error("unknown security level");
	return v;
}

/** The single universal child of an `EXPLICIT` context tag. */
function inner(t: Tlv): Tlv {
	const [only, ...rest] = children(t);
	if (!only || rest.length > 0) throw new Error("bad explicit tag");
	return only;
}

function parseRootOfTrust(t: Tlv): RootOfTrust {
	const [key, locked, state, hash] = children(t);
	if (!key || !locked || !state) throw new Error("short RootOfTrust");
	const bootState = BOOT_STATES[intOf(state)];
	if (!bootState) throw new Error("unknown verified boot state");
	return {
		verifiedBootKey: toHexLower(key.content),
		deviceLocked: boolOf(locked),
		verifiedBootState: bootState,
		...(hash && { verifiedBootHash: toHexLower(hash.content) }),
	};
}

function parseApplicationId(octets: Tlv): ApplicationId {
	const [pkgs, sigs] = children(parseOne(octets.content));
	if (!pkgs || !sigs) throw new Error("short AttestationApplicationId");
	return {
		packages: children(pkgs).map((p) => {
			const [name, version] = children(p);
			if (!name || !version) throw new Error("short AttestationPackageInfo");
			return { name: stringOf(name), version: intOf(version) };
		}),
		signatureDigests: children(sigs).map((s) => toHexLower(s.content)),
	};
}

const ID_TAGS: Record<number, keyof AuthorizationList["ids"]> = {
	710: "brand",
	711: "device",
	712: "product",
	713: "serial",
	716: "manufacturer",
	717: "model",
};

/** Parse an AuthorizationList. Tags this verifier does not use are ignored. */
export function parseAuthorizationList(seq: Tlv): AuthorizationList {
	const out: AuthorizationList = { ids: {} };
	for (const entry of children(seq)) {
		if (entry.cls !== 2) continue;
		const v = inner(entry);
		switch (entry.tag) {
			case 1:
				out.purpose = children(v).map(intOf);
				break;
			case 2:
				out.algorithm = intOf(v);
				break;
			case 3:
				out.keySize = intOf(v);
				break;
			case 10:
				out.ecCurve = intOf(v);
				break;
			case 702:
				out.origin = intOf(v);
				break;
			case 704:
				out.rootOfTrust = parseRootOfTrust(v);
				break;
			case 705:
				out.osVersion = intOf(v);
				break;
			case 706:
				out.osPatchLevel = intOf(v);
				break;
			case 709:
				out.applicationId = parseApplicationId(v);
				break;
			case 718:
				out.vendorPatchLevel = intOf(v);
				break;
			case 719:
				out.bootPatchLevel = intOf(v);
				break;
			default: {
				const key = ID_TAGS[entry.tag];
				if (key && isUniversal(v, TAG.OCTET_STRING)) out.ids[key] = stringOf(v);
			}
		}
	}
	return out;
}

/** Parse the value of the key attestation extension (the OCTET STRING content). Throws on malformed input. */
export function parseKeyDescription(extensionValue: Uint8Array): KeyDescription {
	const f = children(parseOne(extensionValue));
	const [ver, lvl, kmVer, kmLvl, challenge, uniqueId, sw, hw] = f;
	if (!ver || !lvl || !kmVer || !kmLvl || !challenge || !uniqueId || !sw || !hw) {
		throw new Error("short KeyDescription");
	}
	if (!isUniversal(challenge, TAG.OCTET_STRING) || !isUniversal(uniqueId, TAG.OCTET_STRING)) {
		throw new Error("bad KeyDescription challenge or uniqueId");
	}
	bigIntOf(ver);
	return {
		attestationVersion: intOf(ver),
		attestationSecurityLevel: level(lvl),
		keymasterVersion: intOf(kmVer),
		keymasterSecurityLevel: level(kmLvl),
		attestationChallenge: challenge.content,
		uniqueId: uniqueId.content,
		softwareEnforced: parseAuthorizationList(sw),
		hardwareEnforced: parseAuthorizationList(hw),
	};
}
