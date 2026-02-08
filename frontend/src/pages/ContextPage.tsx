import { useEffect, useState, useCallback } from 'react';
import { Routes, Route, Link, useSearchParams, useNavigate } from 'react-router-dom';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { api, type ContextFileData } from '../lib/api';

// ── File Tree Component ──
interface TreeNode {
  dirs: Record<string, TreeNode>;
  files: { name: string; path: string; bytes: number }[];
}

function buildTree(files: ContextFileData[]): TreeNode {
  const root: TreeNode = { dirs: {}, files: [] };
  for (const f of files) {
    const parts = f.path.split('/');
    let node = root;
    for (let i = 0; i < parts.length - 1; i++) {
      if (!node.dirs[parts[i]]) node.dirs[parts[i]] = { dirs: {}, files: [] };
      node = node.dirs[parts[i]];
    }
    node.files.push({ name: parts[parts.length - 1], path: f.path, bytes: f.bytes });
  }
  return root;
}

function formatBytes(b: number) {
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / (1024 * 1024)).toFixed(1)} MB`;
}

function DirNode({ name, node, defaultOpen }: { name: string; node: TreeNode; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen ?? false);
  const dirNames = Object.keys(node.dirs).sort();
  const sortedFiles = [...node.files].sort((a, b) => a.name.localeCompare(b.name));

  return (
    <div>
      <div className="tree-dir-label" onClick={() => setOpen(!open)}>
        <svg className={`tree-chevron ${open ? 'open' : ''}`} viewBox="0 0 16 16" fill="currentColor">
          <path d="M6.22 3.22a.75.75 0 0 1 1.06 0l4.25 4.25a.75.75 0 0 1 0 1.06l-4.25 4.25a.75.75 0 0 1-1.06-1.06L9.94 8 6.22 4.28a.75.75 0 0 1 0-1.06Z"/>
        </svg>
        <svg style={{ width: 16, height: 16, opacity: 0.6, color: 'var(--accent)' }} viewBox="0 0 16 16" fill="currentColor">
          <path d="M1.75 1A1.75 1.75 0 0 0 0 2.75v10.5C0 14.216.784 15 1.75 15h12.5A1.75 1.75 0 0 0 16 13.25v-8.5A1.75 1.75 0 0 0 14.25 3H7.5a.25.25 0 0 1-.2-.1l-.9-1.2C6.07 1.26 5.55 1 5 1H1.75Z"/>
        </svg>
        <span>{name}</span>
      </div>
      {open && (
        <div className="tree-children">
          {dirNames.map((d) => <DirNode key={d} name={d} node={node.dirs[d]} defaultOpen />)}
          {sortedFiles.map((f) => (
            <div className="tree-file" key={f.path}>
              <svg style={{ width: 16, height: 16, opacity: 0.4, color: 'var(--text-secondary)', flexShrink: 0 }} viewBox="0 0 16 16" fill="currentColor">
                <path d="M2 1.75C2 .784 2.784 0 3.75 0h6.586c.464 0 .909.184 1.237.513l2.914 2.914c.329.328.513.773.513 1.237v9.586A1.75 1.75 0 0 1 13.25 16h-9.5A1.75 1.75 0 0 1 2 14.25Zm1.75-.25a.25.25 0 0 0-.25.25v12.5c0 .138.112.25.25.25h9.5a.25.25 0 0 0 .25-.25V6h-2.75A1.75 1.75 0 0 1 9 4.25V1.5Zm6.75.062V4.25c0 .138.112.25.25.25h2.688l-.011-.013-2.914-2.914-.013-.011Z"/>
              </svg>
              <Link className="tree-file-link" to={`/context/view?path=${encodeURIComponent(f.path)}`}>{f.name}</Link>
              <span className="tree-file-size">{formatBytes(f.bytes)}</span>
              <span className="tree-file-actions">
                <Link to={`/context/view?path=${encodeURIComponent(f.path)}`}>View</Link>
                <Link to={`/context/edit?path=${encodeURIComponent(f.path)}`}>Edit</Link>
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function FileTreePage({ files }: { files: ContextFileData[] }) {
  const tree = buildTree(files);
  const dirNames = Object.keys(tree.dirs).sort();
  const sortedFiles = [...tree.files].sort((a, b) => a.name.localeCompare(b.name));

  return (
    <>
      <h2>Context</h2>
      <p className="section-desc">Durable files under <span className="pill">/data/context</span> visible to the agent. Click folders to expand, files to view.</p>
      <div>
        {dirNames.map((d) => <DirNode key={d} name={d} node={tree.dirs[d]} defaultOpen={dirNames.length <= 5} />)}
        {sortedFiles.map((f) => (
          <div className="tree-file" key={f.path} style={{ borderBottom: '1px solid var(--border)' }}>
            <svg style={{ width: 16, height: 16, opacity: 0.4, color: 'var(--text-secondary)', flexShrink: 0 }} viewBox="0 0 16 16" fill="currentColor">
              <path d="M2 1.75C2 .784 2.784 0 3.75 0h6.586c.464 0 .909.184 1.237.513l2.914 2.914c.329.328.513.773.513 1.237v9.586A1.75 1.75 0 0 1 13.25 16h-9.5A1.75 1.75 0 0 1 2 14.25Zm1.75-.25a.25.25 0 0 0-.25.25v12.5c0 .138.112.25.25.25h9.5a.25.25 0 0 0 .25-.25V6h-2.75A1.75 1.75 0 0 1 9 4.25V1.5Zm6.75.062V4.25c0 .138.112.25.25.25h2.688l-.011-.013-2.914-2.914-.013-.011Z"/>
            </svg>
            <Link className="tree-file-link" to={`/context/view?path=${encodeURIComponent(f.path)}`}>{f.name}</Link>
            <span className="tree-file-size">{formatBytes(f.bytes)}</span>
            <span className="tree-file-actions">
              <Link to={`/context/view?path=${encodeURIComponent(f.path)}`}>View</Link>
              <Link to={`/context/edit?path=${encodeURIComponent(f.path)}`}>Edit</Link>
            </span>
          </div>
        ))}
      </div>
    </>
  );
}

// ── File Viewer ──
function FileViewer() {
  const [params] = useSearchParams();
  const path = params.get('path') || '';
  const [content, setContent] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!path) return;
    setLoading(true);
    api.getContextFile(path).then((d) => { setContent(d.content); setLoading(false); }).catch(() => setLoading(false));
  }, [path]);

  const isMarkdown = path.endsWith('.md') || path.endsWith('.markdown');

  return (
    <>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <Link to="/context" style={{ color: 'var(--text-secondary)', fontSize: 14 }}>← Context</Link>
          <span style={{ color: 'var(--text-tertiary)' }}>/</span>
          <h2 style={{ margin: 0, fontSize: 16 }}>{path}</h2>
        </div>
        <Link to={`/context/edit?path=${encodeURIComponent(path)}`} className="btn btn-sm">Edit</Link>
      </div>
      {loading ? <div className="loading">Loading…</div> : (
        isMarkdown ? (
          <div className="md-body">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{content}</ReactMarkdown>
          </div>
        ) : (
          <div className="code-viewer">
            <pre>{content}</pre>
          </div>
        )
      )}
    </>
  );
}

// ── File Editor ──
function FileEditor() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const path = params.get('path') || '';
  const [content, setContent] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!path) return;
    setLoading(true);
    api.getContextFile(path).then((d) => { setContent(d.content); setLoading(false); }).catch(() => setLoading(false));
  }, [path]);

  const save = useCallback(async () => {
    setSaving(true);
    try {
      await api.saveContextFile(path, content);
      navigate(`/context/view?path=${encodeURIComponent(path)}`);
    } catch { /* noop */ }
    setSaving(false);
  }, [path, content, navigate]);

  return (
    <>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <Link to="/context" style={{ color: 'var(--text-secondary)', fontSize: 14 }}>← Context</Link>
          <span style={{ color: 'var(--text-tertiary)' }}>/</span>
          <h2 style={{ margin: 0, fontSize: 16 }}>Editing: {path}</h2>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn btn-primary" onClick={save} disabled={saving}>{saving ? 'Saving…' : 'Save'}</button>
          <Link to={`/context/view?path=${encodeURIComponent(path)}`} className="btn btn-sm" style={{ display: 'inline-flex', alignItems: 'center' }}>Cancel</Link>
        </div>
      </div>
      {loading ? <div className="loading">Loading…</div> : (
        <textarea
          className="form-textarea"
          style={{ width: '100%', minHeight: 500, fontFamily: 'var(--mono)', fontSize: 13, lineHeight: 1.6 }}
          value={content}
          onChange={(e) => setContent(e.target.value)}
        />
      )}
    </>
  );
}

// ── Main Context Page (routes) ──
export function ContextPage() {
  const [files, setFiles] = useState<ContextFileData[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getContext().then((d) => { setFiles(d.files); setLoading(false); }).catch(() => setLoading(false));
  }, []);

  if (loading) return <div className="loading">Loading…</div>;

  return (
    <Routes>
      <Route path="/" element={<FileTreePage files={files} />} />
      <Route path="view" element={<FileViewer />} />
      <Route path="edit" element={<FileEditor />} />
    </Routes>
  );
}
