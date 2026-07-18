'use client';

import { useEffect, useState, Suspense } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import Link from 'next/link';

interface VerifyResult {
  status: 'loading' | 'success' | 'error';
  message: string;
}

function VerifyContent() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const [result, setResult] = useState<VerifyResult>({ status: 'loading', message: 'Verifying...' });

  useEffect(() => {
    const token = searchParams.get('token');
    if (!token) {
      setResult({ status: 'error', message: 'No verification token in URL.' });
      return;
    }

    fetch('/api/theauth/auth/verify-email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token }),
    })
      .then(async (res) => {
        if (res.ok) {
          setResult({ status: 'success', message: 'Email verified. You can now sign in.' });
          setTimeout(() => router.push('/'), 2000);
        } else {
          const json = await res.json() as { error?: { message?: string } };
          setResult({
            status: 'error',
            message: json.error?.message ?? `Verification failed (${res.status})`,
          });
        }
      })
      .catch(() => {
        setResult({ status: 'error', message: 'Network error during verification.' });
      });
  }, [searchParams, router]);

  return (
    <div className="min-h-screen flex items-center justify-center px-4">
      <div className="w-full max-w-sm text-center">
        <h1 className="text-xl font-semibold text-zinc-100 mb-2">Email verification</h1>

        {result.status === 'loading' && (
          <p className="text-zinc-400 text-sm">{result.message}</p>
        )}

        {result.status === 'success' && (
          <div className="mt-4 p-4 bg-emerald-950/40 border border-emerald-900/50 rounded-xl">
            <p className="text-emerald-400 text-sm">{result.message}</p>
            <p className="text-zinc-500 text-xs mt-1">Redirecting to sign in...</p>
          </div>
        )}

        {result.status === 'error' && (
          <div className="mt-4 p-4 bg-red-950/40 border border-red-900/50 rounded-xl">
            <p className="text-red-400 text-sm">{result.message}</p>
            <Link href="/" className="block mt-3 text-xs text-zinc-400 hover:text-zinc-200 transition-colors">
              Back to sign in
            </Link>
          </div>
        )}
      </div>
    </div>
  );
}

export default function VerifyPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-zinc-400 text-sm">Loading...</div>
      </div>
    }>
      <VerifyContent />
    </Suspense>
  );
}
