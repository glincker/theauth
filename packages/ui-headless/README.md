# @glinr/theauth-ui-headless

[![npm](https://img.shields.io/npm/v/@glinr/theauth-ui-headless?style=flat&colorA=000000&colorB=000000&label=npm)](https://www.npmjs.com/package/@glinr/theauth-ui-headless) [![downloads](https://img.shields.io/npm/dm/@glinr/theauth-ui-headless?style=flat&colorA=000000&colorB=000000&label=downloads)](https://www.npmjs.com/package/@glinr/theauth-ui-headless) [![docs](https://img.shields.io/badge/docs-docs.theauth.dev-000000?style=flat)](https://docs.theauth.dev/ui-components) [![license](https://img.shields.io/badge/license-MIT-000000?style=flat)](https://github.com/glincker/theauth/blob/main/LICENSE)

[npm](https://www.npmjs.com/package/@glinr/theauth-ui-headless) · [Source](https://github.com/glincker/theauth/tree/main/packages/ui-headless) · [Docs](https://docs.theauth.dev/ui-components) · [All packages](https://github.com/glincker/theauth#packages)

Unstyled, accessible account components for theAuth, built on `@glinr/theauth-react/query`. They ship no product copy and no styles: every string comes from a required `labels` prop, and every part carries a `data-part` attribute plus an optional `classNames` slot, so the host applies its own CSS (Tailwind, for example).

Components: `SessionList`, `ApiTokenList`, `MintTokenForm` (personal or agent tokens, show-once secret with copy), `DeviceApproval`, `StepUpDialog`, and `useStepUpRetry`, which opens the dialog on `auth.recent_auth_required` and retries the action after elevation.

```tsx
const { run, dialogProps } = useStepUpRetry();
const cx = { item: "flex items-center gap-3 py-2", revoke: "text-sm text-red-600 hover:underline" };

<TheAuthQueryProvider client={client}>
  <SessionList labels={t.sessions} classNames={cx} run={run} />
  <MintTokenForm
    labels={t.mint}
    kind="agent"
    abilities={[{ id: "deploy:read", label: t.abilities.deployRead }]}
    expiries={[{ seconds: 3600, label: t.hour }, { seconds: 86400, label: t.day }]}
    classNames={{ input: "rounded border px-2 py-1", submit: "rounded bg-amber-500 px-3 py-1" }}
    run={run}
  />
  <ApiTokenList labels={t.tokens} kind="agent" run={run} />
  <StepUpDialog {...dialogProps} labels={t.stepUp} classNames={{ dialog: "rounded-lg bg-white p-6" }} />
</TheAuthQueryProvider>
```

Error text: each `labels.error(code)` receives a stable code such as `invalid_expiry`, `ability_not_held` or `invalid_credentials`; map it to your copy. Components also set `data-error-code` on the alert element. Peer dependencies: `react`, `@tanstack/react-query`, `@glinr/theauth-react`, `@glinr/theauth-client`.

Part of [theAuth](https://theauth.dev), open-source auth for AI agents and humans. Docs: [docs.theauth.dev](https://docs.theauth.dev).

<!-- theauth:links -->
## Learn more

- [UI components](https://docs.theauth.dev/ui-components)
- [All packages](https://github.com/glincker/theauth#packages)
- [GitHub Discussions](https://github.com/glincker/theauth/discussions) for questions
- [Report a security issue](https://github.com/glincker/theauth/blob/main/SECURITY.md)
