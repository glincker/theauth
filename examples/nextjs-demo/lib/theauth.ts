import { createTheAuth } from '@glinr/theauth';
import { emailPassword } from '@glinr/theauth-email';

type TheAuthInstance = Awaited<ReturnType<typeof createTheAuth>>;

declare global {
  // eslint-disable-next-line no-var
  var __theauthDemo: TheAuthInstance | undefined;
}

let theAuthPromise: Promise<TheAuthInstance> | undefined;

export function getTheAuth(): Promise<TheAuthInstance> {
  if (globalThis.__theauthDemo) {
    return Promise.resolve(globalThis.__theauthDemo);
  }

  if (!theAuthPromise) {
    theAuthPromise = createTheAuth({
      database: { provider: 'sqlite', url: './theauth-demo.db' },
      agents: {
        enabled: true,
        maxPerUser: 10,
        auditAll: true,
        tokenExpiry: '24h',
      },
      plugins: [
        emailPassword({
          appUrl: 'http://localhost:3002',
          requireVerification: false,
          sendVerificationEmail: async (email, _token, url) => {
            console.log(`\n[TheAuth] Verify email for ${email}:`);
            console.log(`  ${url}\n`);
          },
          sendResetEmail: async (email, _token, url) => {
            console.log(`\n[TheAuth] Reset password for ${email}:`);
            console.log(`  ${url}\n`);
          },
        }),
      ],
    }).then((instance) => {
      globalThis.__theauthDemo = instance;
      return instance;
    });
  }

  return theAuthPromise;
}
