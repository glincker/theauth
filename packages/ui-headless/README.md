# @glinr/theauth-ui-headless

Unstyled, accessible account components for TheAuth, built on `@glinr/theauth-react/query`. They ship no product copy and no styles: every string comes from a required `labels` prop, and every part carries a `data-part` attribute plus an optional `classNames` slot, so the host applies its own CSS (Tailwind, for example).

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
