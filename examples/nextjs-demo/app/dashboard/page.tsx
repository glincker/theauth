'use client';

import { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';

interface Session {
  token: string;
  user: { id: string; email: string; name: string };
}

interface Agent {
  id: string;
  name: string;
  status: 'active' | 'revoked';
  type: string;
  permissions: Array<{ resource: string; actions: string[] }>;
}

interface AuditEntry {
  id: string;
  agentId: string;
  action: string;
  resource: string;
  result: 'allowed' | 'denied' | 'rate_limited';
  timestamp: string;
}

interface AuthorizeResult {
  allowed: boolean;
  reason?: string;
}

export default function Dashboard() {
  const router = useRouter();
  const [session, setSession] = useState<Session | null>(null);

  const [agents, setAgents] = useState<Agent[]>([]);
  const [agentsLoading, setAgentsLoading] = useState(false);
  const [agentsError, setAgentsError] = useState('');

  const [newAgentName, setNewAgentName] = useState('');
  const [newAgentResource, setNewAgentResource] = useState('documents');
  const [newAgentAction, setNewAgentAction] = useState('read');
  const [createError, setCreateError] = useState('');
  const [lastCreatedToken, setLastCreatedToken] = useState('');

  const [authAgentId, setAuthAgentId] = useState('');
  const [authAction, setAuthAction] = useState('read');
  const [authResource, setAuthResource] = useState('documents');
  const [authResult, setAuthResult] = useState<AuthorizeResult | null>(null);
  const [authLoading, setAuthLoading] = useState(false);

  const [auditEntries, setAuditEntries] = useState<AuditEntry[]>([]);
  const [auditLoading, setAuditLoading] = useState(false);

  useEffect(() => {
    const raw = localStorage.getItem('theauth_session');
    if (!raw) {
      router.push('/');
      return;
    }
    setSession(JSON.parse(raw) as Session);
  }, [router]);

  const loadAgents = useCallback(async (userId: string) => {
    setAgentsLoading(true);
    setAgentsError('');
    try {
      const res = await fetch(`/api/theauth/agents?userId=${encodeURIComponent(userId)}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await res.json() as { data: Agent[] };
      setAgents(json.data ?? []);
    } catch (err) {
      setAgentsError(err instanceof Error ? err.message : 'Failed to load agents');
    } finally {
      setAgentsLoading(false);
    }
  }, []);

  const loadAudit = useCallback(async (agentId?: string) => {
    setAuditLoading(true);
    try {
      const params = new URLSearchParams({ limit: '10' });
      if (agentId) params.set('agentId', agentId);
      const res = await fetch(`/api/theauth/audit?${params.toString()}`);
      if (res.ok) {
        const json = await res.json() as { data: AuditEntry[] };
        setAuditEntries(json.data ?? []);
      }
    } finally {
      setAuditLoading(false);
    }
  }, []);

  useEffect(() => {
    if (session) {
      void loadAgents(session.user.id);
      void loadAudit();
    }
  }, [session, loadAgents, loadAudit]);

  async function handleCreateAgent(e: React.FormEvent) {
    e.preventDefault();
    if (!session) return;
    setCreateError('');
    setLastCreatedToken('');

    try {
      const res = await fetch('/api/theauth/agents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ownerId: session.user.id,
          name: newAgentName,
          type: 'autonomous',
          permissions: [{ resource: newAgentResource, actions: [newAgentAction] }],
        }),
      });
      const json = await res.json() as { success: boolean; data?: { token: string }; error?: { message: string } };
      if (json.success && json.data) {
        setLastCreatedToken(json.data.token);
        setNewAgentName('');
        void loadAgents(session.user.id);
        void loadAudit();
      } else {
        setCreateError(json.error?.message ?? 'Failed to create agent');
      }
    } catch (err) {
      setCreateError(err instanceof Error ? err.message : 'Network error');
    }
  }

  async function handleRevoke(agentId: string) {
    if (!session) return;
    try {
      const res = await fetch(`/api/theauth/agents/${agentId}`, { method: 'DELETE' });
      if (!res.ok) {
        const json = await res.json() as { error?: { message: string } };
        alert(`Failed to revoke: ${json.error?.message ?? res.status}`);
      }
      void loadAgents(session.user.id);
      void loadAudit(agentId);
    } catch {
      alert('Network error while revoking agent');
    }
  }

  async function handleRotate(agentId: string) {
    if (!session) return;
    try {
      const res = await fetch(`/api/theauth/agents/${agentId}/rotate`, { method: 'POST' });
      const json = await res.json() as { success: boolean; data?: { token: string }; error?: { message: string } };
      if (json.success && json.data) {
        setLastCreatedToken(json.data.token);
        void loadAgents(session.user.id);
        void loadAudit(agentId);
      } else {
        alert(`Failed to rotate: ${json.error?.message ?? 'Unknown error'}`);
      }
    } catch {
      alert('Network error while rotating token');
    }
  }

  async function handleAuthorize(e: React.FormEvent) {
    e.preventDefault();
    setAuthResult(null);
    setAuthLoading(true);
    try {
      const res = await fetch('/api/theauth/authorize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentId: authAgentId, action: authAction, resource: authResource }),
      });
      const json = await res.json() as { data: AuthorizeResult };
      setAuthResult(json.data);
      void loadAudit(authAgentId);
    } catch {
      setAuthResult({ allowed: false, reason: 'Network error' });
    } finally {
      setAuthLoading(false);
    }
  }

  function handleSignOut() {
    localStorage.removeItem('theauth_session');
    router.push('/');
  }

  if (!session) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-zinc-950">
        <div className="text-zinc-400 text-sm">Loading...</div>
      </div>
    );
  }

  const activeAgents = agents.filter((a) => a.status === 'active');

  return (
    <div className="min-h-screen bg-zinc-950">
      <header className="border-b border-zinc-800 px-6 py-4 flex items-center justify-between">
        <div>
          <span className="text-sm font-medium text-zinc-100">TheAuth</span>
          <span className="ml-2 text-xs text-zinc-500">demo</span>
        </div>
        <div className="flex items-center gap-4">
          <span className="text-xs text-zinc-400">{session.user.email}</span>
          <button
            type="button"
            onClick={handleSignOut}
            className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors"
          >
            Sign out
          </button>
        </div>
      </header>

      <main className="max-w-4xl mx-auto px-6 py-8 space-y-8">
        {/* Session info */}
        <section>
          <h2 className="text-xs font-medium text-zinc-500 uppercase tracking-wider mb-3">Session</h2>
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4 grid grid-cols-2 gap-4 text-sm">
            <div>
              <div className="text-zinc-500 text-xs mb-1">User ID</div>
              <div className="font-mono text-xs text-zinc-300 break-all">{session.user.id}</div>
            </div>
            <div>
              <div className="text-zinc-500 text-xs mb-1">Name</div>
              <div className="text-zinc-300">{session.user.name || '—'}</div>
            </div>
          </div>
        </section>

        {/* Create agent */}
        <section>
          <h2 className="text-xs font-medium text-zinc-500 uppercase tracking-wider mb-3">Create agent</h2>
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
            <form onSubmit={handleCreateAgent} className="flex flex-wrap gap-3 items-end">
              <div className="flex-1 min-w-[160px]">
                <label className="block text-xs text-zinc-500 mb-1">Agent name</label>
                <input
                  type="text"
                  value={newAgentName}
                  onChange={(e) => setNewAgentName(e.target.value)}
                  placeholder="my-agent"
                  required
                  className="w-full px-3 py-2 bg-zinc-800 border border-zinc-700 rounded-lg text-sm text-zinc-100 placeholder-zinc-500 focus:outline-none focus:border-zinc-500"
                />
              </div>
              <div className="w-36">
                <label className="block text-xs text-zinc-500 mb-1">Resource</label>
                <input
                  type="text"
                  value={newAgentResource}
                  onChange={(e) => setNewAgentResource(e.target.value)}
                  placeholder="documents"
                  required
                  className="w-full px-3 py-2 bg-zinc-800 border border-zinc-700 rounded-lg text-sm text-zinc-100 placeholder-zinc-500 focus:outline-none focus:border-zinc-500"
                />
              </div>
              <div className="w-32">
                <label className="block text-xs text-zinc-500 mb-1">Action</label>
                <input
                  type="text"
                  value={newAgentAction}
                  onChange={(e) => setNewAgentAction(e.target.value)}
                  placeholder="read"
                  required
                  className="w-full px-3 py-2 bg-zinc-800 border border-zinc-700 rounded-lg text-sm text-zinc-100 placeholder-zinc-500 focus:outline-none focus:border-zinc-500"
                />
              </div>
              <button
                type="submit"
                className="px-4 py-2 bg-amber-600 hover:bg-amber-500 text-white text-sm font-medium rounded-lg transition-colors"
              >
                Create
              </button>
            </form>

            {createError && <p className="mt-3 text-xs text-red-400">{createError}</p>}

            {lastCreatedToken && (
              <div className="mt-3 p-3 bg-zinc-800 rounded-lg">
                <div className="text-xs text-zinc-400 mb-1">Token (copy now — shown once):</div>
                <code className="text-xs text-amber-400 break-all font-mono">{lastCreatedToken}</code>
              </div>
            )}
          </div>
        </section>

        {/* Agent list */}
        <section>
          <h2 className="text-xs font-medium text-zinc-500 uppercase tracking-wider mb-3">
            Agents ({activeAgents.length} active)
          </h2>
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden">
            {agentsLoading && <div className="p-4 text-zinc-500 text-sm">Loading agents...</div>}
            {agentsError && <div className="p-4 text-red-400 text-sm">{agentsError}</div>}
            {!agentsLoading && agents.length === 0 && (
              <div className="p-4 text-zinc-500 text-sm">No agents yet.</div>
            )}
            {agents.map((agent) => (
              <div key={agent.id} className="px-4 py-3 border-b border-zinc-800 last:border-0 flex items-center justify-between gap-4">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 mb-0.5">
                    <span className="text-sm text-zinc-100 font-medium">{agent.name}</span>
                    <span className={`text-xs px-1.5 py-0.5 rounded font-mono ${
                      agent.status === 'active'
                        ? 'bg-emerald-900/40 text-emerald-400'
                        : 'bg-zinc-800 text-zinc-500'
                    }`}>
                      {agent.status}
                    </span>
                    <span className="text-xs text-zinc-600 font-mono">{agent.type}</span>
                  </div>
                  <div className="text-xs text-zinc-500 font-mono truncate">{agent.id}</div>
                  <div className="text-xs text-zinc-600 mt-0.5">
                    {agent.permissions.map((p) => `${p.actions.join(',')} on ${p.resource}`).join(' · ')}
                  </div>
                </div>
                {agent.status === 'active' && (
                  <div className="flex gap-2 shrink-0">
                    <button
                      type="button"
                      onClick={() => void handleRotate(agent.id)}
                      className="text-xs px-2.5 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded-lg transition-colors"
                    >
                      Rotate
                    </button>
                    <button
                      type="button"
                      onClick={() => void handleRevoke(agent.id)}
                      className="text-xs px-2.5 py-1.5 bg-red-950/40 hover:bg-red-900/60 text-red-400 rounded-lg transition-colors"
                    >
                      Revoke
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>
        </section>

        {/* Authorization check */}
        <section>
          <h2 className="text-xs font-medium text-zinc-500 uppercase tracking-wider mb-3">Authorization check</h2>
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4">
            <form onSubmit={handleAuthorize} className="flex flex-wrap gap-3 items-end">
              <div className="flex-1 min-w-[180px]">
                <label className="block text-xs text-zinc-500 mb-1">Agent ID</label>
                <select
                  value={authAgentId}
                  onChange={(e) => setAuthAgentId(e.target.value)}
                  required
                  className="w-full px-3 py-2 bg-zinc-800 border border-zinc-700 rounded-lg text-sm text-zinc-100 focus:outline-none focus:border-zinc-500 font-mono"
                >
                  <option value="">Select agent...</option>
                  {activeAgents.map((a) => (
                    <option key={a.id} value={a.id}>{a.name}</option>
                  ))}
                </select>
              </div>
              <div className="w-32">
                <label className="block text-xs text-zinc-500 mb-1">Action</label>
                <input
                  type="text"
                  value={authAction}
                  onChange={(e) => setAuthAction(e.target.value)}
                  placeholder="read"
                  required
                  className="w-full px-3 py-2 bg-zinc-800 border border-zinc-700 rounded-lg text-sm text-zinc-100 placeholder-zinc-500 focus:outline-none focus:border-zinc-500"
                />
              </div>
              <div className="w-36">
                <label className="block text-xs text-zinc-500 mb-1">Resource</label>
                <input
                  type="text"
                  value={authResource}
                  onChange={(e) => setAuthResource(e.target.value)}
                  placeholder="documents"
                  required
                  className="w-full px-3 py-2 bg-zinc-800 border border-zinc-700 rounded-lg text-sm text-zinc-100 placeholder-zinc-500 focus:outline-none focus:border-zinc-500"
                />
              </div>
              <button
                type="submit"
                disabled={authLoading}
                className="px-4 py-2 bg-zinc-700 hover:bg-zinc-600 disabled:opacity-50 text-zinc-100 text-sm font-medium rounded-lg transition-colors"
              >
                Check
              </button>
            </form>

            {authResult !== null && (
              <div className={`mt-3 flex items-center gap-2 px-3 py-2 rounded-lg text-sm ${
                authResult.allowed
                  ? 'bg-emerald-950/40 border border-emerald-900/50 text-emerald-400'
                  : 'bg-red-950/40 border border-red-900/50 text-red-400'
              }`}>
                <span className="font-medium">{authResult.allowed ? 'Allowed' : 'Denied'}</span>
                {authResult.reason && <span className="text-xs opacity-75">— {authResult.reason}</span>}
              </div>
            )}
          </div>
        </section>

        {/* Audit trail */}
        <section>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-xs font-medium text-zinc-500 uppercase tracking-wider">Audit trail</h2>
            <button
              type="button"
              onClick={() => void loadAudit(authAgentId || undefined)}
              className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors"
            >
              Refresh
            </button>
          </div>
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden">
            {auditLoading && <div className="p-4 text-zinc-500 text-sm">Loading...</div>}
            {!auditLoading && auditEntries.length === 0 && (
              <div className="p-4 text-zinc-500 text-sm">No audit entries yet.</div>
            )}
            {auditEntries.map((entry) => (
              <div key={entry.id} className="px-4 py-2.5 border-b border-zinc-800 last:border-0 flex items-center gap-3 text-xs">
                <span className={`px-1.5 py-0.5 rounded font-mono shrink-0 ${
                  entry.result === 'allowed'
                    ? 'bg-emerald-900/40 text-emerald-400'
                    : entry.result === 'denied'
                      ? 'bg-red-900/40 text-red-400'
                      : 'bg-amber-900/40 text-amber-400'
                }`}>
                  {entry.result}
                </span>
                <span className="text-zinc-300 font-mono">{entry.action}</span>
                <span className="text-zinc-500">on</span>
                <span className="text-zinc-300 font-mono">{entry.resource}</span>
                <span className="text-zinc-600 ml-auto shrink-0">
                  {new Date(entry.timestamp).toLocaleTimeString()}
                </span>
              </div>
            ))}
          </div>
        </section>
      </main>
    </div>
  );
}
