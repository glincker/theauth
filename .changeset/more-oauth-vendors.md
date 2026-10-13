---
"@glinr/theauth": minor
---

Working sign-in providers for Linear, Kick, Vercel, PayPal and Kakao: `createLinearProvider`, `createKickProvider`, `createVercelProvider`, `createPaypalProvider` (with `sandbox`) and `createKakaoProvider`. The older `linearProvider`, `kickProvider`, `vercelProvider`, `paypalProvider` and `kakaoProvider` presets read the wrong userinfo shape or the wrong endpoints and are unchanged. `genericOIDC` gains optional `scopeSeparator`, `defaultScopes`, `userinfoMethod`, `userinfoBody`, `authorizationParams`, `tokenAuth` (`"basic"`) and `pkce`, and `mapProfile` may return `emailVerified`. Existing configs behave as before.
