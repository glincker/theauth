# @glinr/theauth-visitor-signal

A small browser collector for coarse visitor attributes. It runs only after consent, writes nothing to storage, sets no cookies and makes no network calls. Your page posts the result to your own endpoint.

## What it is, and is not

The output is an advisory hint. It is not an identifier of a person, not an authentication factor and not proof of humanity. Expect false merges (identical phones, managed laptops) and false splits (browser updates, setting changes). Do not use it to gate a security decision.

## Install

```bash
pnpm add @glinr/theauth-visitor-signal
```

ESM only. Web APIs only, so it runs in browsers and in Workers, Deno and Bun (sources that need DOM APIs report themselves as unavailable elsewhere). No runtime dependencies.

## Use

```ts
import { collect, collectSignalV1 } from "@glinr/theauth-visitor-signal";

const result = await collect({
  mode: "analytics",
  consent: () => (cmp.analyticsGranted() ? "granted" : "denied"),
});
if (result.success) await fetch("/signal", { method: "POST", body: JSON.stringify(result.data) });

// Cookieless digest profile, same-origin beacons only:
const digest = await collectSignalV1({ mode: "analytics", consent, pepper: "my-site-pepper" });
```

Every call returns `{ success: true, data } | { success: false, error: { code, message } }` and never throws. Each source runs under its own timeout; a source that hangs or fails is listed in `unavailable` and the payload status becomes `partial`.

## Consent, DNT and GPC

Analytics mode follows the contract matrix:

| Situation | Result |
| --- | --- |
| consent `denied` | `suppressed`, reason `consent_denied`, empty components |
| consent `unknown` (or the hook throws) | `suppressed`, reason `consent_unknown`, empty components |
| `navigator.doNotTrack` is `1`, `yes` or `true` | `suppressed`, reason `dnt` |
| `navigator.globalPrivacyControl === true` | `suppressed`, reason `gpc` |

In every suppressed case no restricted API (screen, hardware, client hints, media queries, storage probes) is read. Consent is evaluated first. DNT and GPC are read only once consent is granted. `fraud_prevention` mode is not implemented yet and returns a `mode_unsupported` error.

## Options and defaults

Timeouts and caps are options. Defaults live in one `DEFAULTS` object: `sourceTimeoutMs` 250, `nonceLength` 22, and the bucket and cap values from the contract. The confidence model is exported as `DEFAULT_CONFIDENCE_MODEL` and overridable through `confidenceModel`.

## What ships in this version

Only the SignalV1 profile exists in the browser for now (`collectSignalV1`, `toSignalV1`). The full payload (`collect`) carries the coarse components. Keyed visitor hashing, key epochs, challenge verification and risk scoring are the server side and live in the Go package. This package has no verifier and no fraud-prevention sources.

## Accuracy limits

Third-party sources put client-only open libraries at roughly 40 to 60 percent accuracy. We have no measured false-positive rate for this library yet, so do not quote one.

## Bundle budget

The built `dist/index.js` is checked against a size budget in tests. Default budget: 16384 bytes. Override with `VISITOR_SIGNAL_BUNDLE_BUDGET_BYTES`.

## License

MIT
