import { createKavach } from '@glinr/theauth';
import { emailPassword } from '@glinr/theauth-email';

type KavachInstance = Awaited<ReturnType<typeof createKavach>>;

declare global {
  // eslint-disable-next-line no-var
  var __kavachDemo: KavachInstance | undefined;
}

let kavachPromise: Promise<KavachInstance> | undefined;

export function getKavach(): Promise<KavachInstance> {
  if (globalThis.__kavachDemo) {
    return Promise.resolve(globalThis.__kavachDemo);
  }

  if (!kavachPromise) {
    kavachPromise = createKavach({
      database: { provider: 'sqlite', url: './kavach-demo.db' },
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
      globalThis.__kavachDemo = instance;
      return instance;
    });
  }

  return kavachPromise;
}
