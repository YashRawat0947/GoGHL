
import { useEffect, useState } from 'react';

type User = {
  name: string;
  email: string;
  workspaces: { id: string; role: string }[];
};

type Message = {
  text: string;
  direction: string;
  occurredAt: string;
};

type Conversation = {
  contact: string;
  messages: Message[];
  assignee: string | null;
};

export function App() {
  const [user, setUser] = useState<User | null>(null);
  const [workspace, setWorkspace] = useState('');
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [selected, setSelected] = useState('');
  const [text, setText] = useState('');
  const [loading, setLoading] = useState(true);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState('');

  async function loadConversations(id: string) {
    const res = await fetch(`/api/conversations?workspace=${encodeURIComponent(id)}`);
    if (!res.ok) throw new Error('Failed to load inbox');
    const data: Conversation[] = await res.json();
    setConversations(data);
    setSelected((current) => data.some((c) => c.contact === current) ? current : data[0]?.contact ?? '');
  }

  useEffect(() => {
    fetch('/api/me')
      .then((r) => {
        if (!r.ok) throw new Error();
        return r.json();
      })
      .then((u: User) => {
        setUser(u);
        setWorkspace(u.workspaces[0]?.id ?? '');
      })
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (!workspace) return;
    setLoading(true);
    setError('');
    loadConversations(workspace)
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, [workspace]);

  async function sendReply(e: React.FormEvent) {
    e.preventDefault();
    if (!text.trim() || !selected || sending) return;

    setSending(true);
    setError('');

    try {
      const res = await fetch('/api/reply', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          workspace,
          contact: selected,
          text: text.trim(),
          client_ref: crypto.randomUUID(),
        }),
      });

      if (!res.ok) throw new Error(await res.text() || 'Reply failed');

      setText('');
      await loadConversations(workspace);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Reply failed');
    } finally {
      setSending(false);
    }
  }

  if (loading && !user) return <main style={{ padding: 40 }}>Loading…</main>;

  if (!user) {
    return (
      <main style={{ margin: '15vh auto', textAlign: 'center', fontFamily: 'system-ui' }}>
        <h1>Switchboard</h1>
        <a href="/auth/login">Sign in</a>
      </main>
    );
  }

  const conversation = conversations.find((c) => c.contact === selected);

  return (
    <main style={{ display: 'flex', height: '100vh', fontFamily: 'system-ui', color: '#202124', background: '#f7f8fa' }}>
      <aside style={{ width: 320, background: '#fff', borderRight: '1px solid #e5e7eb', overflowY: 'auto' }}>
        <header style={{ padding: 20, borderBottom: '1px solid #eee' }}>
          <h2>Switchboard</h2>
          <select value={workspace} onChange={(e) => setWorkspace(e.target.value)} style={{ width: '100%', padding: 10 }}>
            {user.workspaces.map((w) => <option key={w.id} value={w.id}>{w.id} · {w.role}</option>)}
          </select>
          <p style={{ fontSize: 13 }}>{user.name}</p>
          <a href="/auth/logout">Sign out</a>
        </header>
        <div style={{ padding: 12, fontWeight: 600 }}>Inbox · {conversations.length}</div>
        {conversations.map((c) => (
          <button key={c.contact} onClick={() => setSelected(c.contact)} style={{ display: 'block', width: '100%', padding: 16, border: 0, borderBottom: '1px solid #eee', textAlign: 'left', background: selected === c.contact ? '#eef4ff' : '#fff', cursor: 'pointer' }}>
            <strong>{c.contact}</strong>
            <div style={{ color: '#777', fontSize: 13, marginTop: 4 }}>{c.messages.at(-1)?.text}</div>
          </button>
        ))}
      </aside>

      <section style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
        {conversation ? (
          <>
            <header style={{ padding: 20, background: '#fff', borderBottom: '1px solid #eee' }}>
              <h3 style={{ margin: 0 }}>{conversation.contact}</h3>
            </header>
            <div style={{ flex: 1, overflowY: 'auto', padding: 24, display: 'flex', flexDirection: 'column', gap: 12 }}>
              {conversation.messages.map((m, i) => (
                <div key={i} style={{ alignSelf: m.direction === 'outbound' ? 'flex-end' : 'flex-start', background: m.direction === 'outbound' ? '#dcecff' : '#fff', padding: 12, borderRadius: 14, maxWidth: '70%', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>
                  {m.text}
                  <div style={{ fontSize: 11, color: '#777', marginTop: 6 }}>{new Date(m.occurredAt).toLocaleString()}</div>
                </div>
              ))}
            </div>
            <form onSubmit={sendReply} style={{ display: 'flex', gap: 10, padding: 16, background: '#fff', borderTop: '1px solid #eee' }}>
              <textarea value={text} onChange={(e) => setText(e.target.value)} placeholder="Write a reply…" rows={2} style={{ flex: 1, resize: 'vertical', padding: 12, borderRadius: 8, border: '1px solid #ddd' }} />
              <button disabled={sending || !text.trim()} style={{ padding: '0 24px', border: 0, borderRadius: 8, background: '#2563eb', color: '#fff', cursor: 'pointer' }}>{sending ? 'Sending…' : 'Send'}</button>
            </form>
          </>
        ) : (
          <div style={{ margin: 'auto', color: '#777' }}>Select a conversation</div>
        )}
        {error && <div style={{ padding: 12, color: '#b42318', background: '#fff' }}>{error}</div>}
      </section>
    </main>
  );
}
