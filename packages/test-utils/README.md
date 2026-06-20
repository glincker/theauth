# @theauth/test-utils

Test helpers for apps using TheAuth: mock providers, factories, and assertions so your auth tests don't have to spin up a real database or an OAuth round-trip.

```bash
npm install --save-dev @theauth/test-utils
```

## What's in the box

- `MockKavachProvider`: drop-in React provider that returns a fake session, agent, and user. Pair with `@testing-library/react`.
- Factories for `Session`, `User`, `AgentIdentity`, `OrgMembership`. Pass overrides; defaults are filled in.
- Assertion helpers like `expectSignedIn`, `expectAgentScope`, `expectAuditEntry` so test failures read clearly.

## Example

```tsx
import { render, screen } from "@testing-library/react";
import { MockKavachProvider, makeUser } from "@theauth/test-utils";
import { Dashboard } from "../src/dashboard.js";

test("dashboard greets the signed-in user", () => {
  const user = makeUser({ name: "Ada Lovelace" });
  render(
    <MockKavachProvider user={user}>
      <Dashboard />
    </MockKavachProvider>,
  );
  expect(screen.getByText(/welcome, ada/i)).toBeInTheDocument();
});
```

## Peer deps

`react` and `@theauth/react` are optional peers. Install them only if you're testing React UI. Server-side helpers work without either.

## Links

- TheAuth repo: <https://github.com/glincker/theauth>
- Docs: <https://docs.theauth.com>

## License

MIT
