import { useMemo, useState, type FormEvent, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  AlertTriangle,
  BrainCircuit,
  CheckCircle2,
  ChevronRight,
  Database,
  Download,
  FileDigit,
  Fingerprint,
  FolderKanban,
  LayoutDashboard,
  LockKeyhole,
  LogOut,
  Menu,
  Plus,
  RefreshCw,
  ScanSearch,
  Server,
  ShieldAlert,
  ShieldCheck,
  Upload,
  UserCheck,
  X,
  XCircle,
} from "lucide-react";
import {
  Link,
  Navigate,
  NavLink,
  Route,
  Routes,
  useNavigate,
  useParams,
} from "react-router-dom";
import { ApiError, auth, downloadReport, login, request } from "./api";
import type {
  Artifact,
  CaseRecord,
  DashboardStats,
  Evidence,
  Finding,
  Job,
  ModelVersion,
  User,
  Verdict,
} from "./types";

function formatDate(value?: string | null) {
  if (!value) return "—";
  return new Intl.DateTimeFormat("fr-FR", { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}

function formatBytes(value: number) {
  if (value < 1024) return `${value} o`;
  const units = ["Ko", "Mo", "Go", "To"];
  let amount = value / 1024;
  let index = 0;
  while (amount >= 1024 && index < units.length - 1) {
    amount /= 1024;
    index += 1;
  }
  return `${amount.toFixed(amount >= 10 ? 1 : 2)} ${units[index]}`;
}

function getError(error: unknown) {
  return error instanceof Error ? error.message : "Une erreur inattendue est survenue";
}

const verdictLabels: Record<string, string> = {
  benign: "Bénin",
  suspicious: "Suspect",
  malicious: "Malveillant",
  inconclusive: "Non concluant",
};

const statusLabels: Record<string, string> = {
  open: "Ouvert",
  sealed: "Scellé",
  closed: "Clôturé",
  ingested: "Ingestée",
  verified: "Vérifiée",
  compromised: "Compromise",
  analyzing: "En analyse",
  analyzed: "Analysée",
  queued: "En file",
  running: "En cours",
  awaiting_review: "À valider",
  approved: "Approuvée",
  rejected: "Rejetée",
  failed: "Échec",
};

function Pill({ value }: { value: string }) {
  return <span className={`pill pill-${value}`}>{statusLabels[value] ?? verdictLabels[value] ?? value}</span>;
}

function EmptyState({ icon, title, children }: { icon: ReactNode; title: string; children: ReactNode }) {
  return (
    <div className="empty-state">
      <div className="empty-icon">{icon}</div>
      <h3>{title}</h3>
      <p>{children}</p>
    </div>
  );
}

function Spinner({ label = "Chargement…" }: { label?: string }) {
  return <div className="loading"><RefreshCw size={18} className="spin" /> {label}</div>;
}

function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await login(username, password);
      window.location.assign("/");
    } catch (reason) {
      setError(getError(reason));
      setBusy(false);
    }
  }

  return (
    <main className="login-shell">
      <section className="login-brand">
        <div className="brand-mark large"><Fingerprint /></div>
        <div>
          <span className="eyebrow">Plateforme forensique souveraine</span>
          <h1>MICEPP<br />Scanner</h1>
          <p>Quarantaine intelligente, analyse comportementale et chaîne de conservation vérifiable.</p>
        </div>
        <div className="trust-strip"><LockKeyhole size={16} /> Déploiement intranet · aucune preuve envoyée dans le cloud</div>
      </section>
      <section className="login-panel">
        <form className="login-card" onSubmit={submit}>
          <div className="mobile-brand"><Fingerprint /> MICEPP Scanner</div>
          <span className="eyebrow">Accès sécurisé</span>
          <h2>Ouvrir une session</h2>
          <p className="muted">Utilisez le compte attribué par l’administrateur du laboratoire.</p>
          <label>Identifiant<input autoFocus autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} required /></label>
          <label>Mot de passe<input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required /></label>
          {error && <div className="error-box"><AlertTriangle size={16} />{error}</div>}
          <button className="button primary wide" disabled={busy}>{busy ? "Vérification…" : "Se connecter"}</button>
          <p className="login-note"><ShieldCheck size={15} /> Les connexions et opérations sensibles sont journalisées.</p>
        </form>
      </section>
    </main>
  );
}

function Layout({ user }: { user: User }) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const nav: Array<{ to: string; label: string; Icon: typeof LayoutDashboard }> = [
    { to: "/", label: "Vue d’ensemble", Icon: LayoutDashboard },
    { to: "/cases", label: "Dossiers", Icon: FolderKanban },
    { to: "/jobs", label: "Analyses", Icon: ScanSearch },
    { to: "/models", label: "Modèles IA", Icon: BrainCircuit },
  ];
  if (user.role !== "analyst") nav.push({ to: "/audit", label: "Journal d’audit", Icon: ShieldCheck });
  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobileOpen ? "open" : ""}`}>
        <button className="sidebar-close" onClick={() => setMobileOpen(false)} aria-label="Fermer"><X /></button>
        <Link to="/" className="logo"><span className="brand-mark"><Fingerprint /></span><span>MICEPP<small>SCANNER</small></span></Link>
        <nav>
          {nav.map(({ to, label, Icon }) => <NavLink key={to} to={to} end={to === "/"} onClick={() => setMobileOpen(false)}><Icon size={19} />{label}</NavLink>)}
        </nav>
        <div className="sidebar-foot">
          <div className="user-card"><div className="avatar">{user.full_name.split(" ").map((p) => p[0]).slice(0, 2).join("")}</div><div><strong>{user.full_name}</strong><span>{user.role}</span></div></div>
          <button className="logout" onClick={() => { auth.clear(); window.location.assign("/"); }}><LogOut size={17} /> Déconnexion</button>
        </div>
      </aside>
      <div className="main-column">
        <header className="topbar">
          <button className="menu-button" onClick={() => setMobileOpen(true)} aria-label="Menu"><Menu /></button>
          <div className="secure-label"><span className="live-dot" /> Environnement intranet sécurisé</div>
          <div className="classification"><LockKeyhole size={14} /> DONNÉES SENSIBLES</div>
        </header>
        <main className="content"><Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/cases" element={<CasesPage />} />
          <Route path="/cases/:caseId" element={<CaseDetail />} />
          <Route path="/jobs" element={<JobsPage />} />
          <Route path="/jobs/:jobId" element={<JobDetail user={user} />} />
          <Route path="/models" element={<ModelsPage user={user} />} />
          <Route path="/audit" element={user.role === "analyst" ? <Navigate to="/" /> : <AuditPage />} />
          <Route path="*" element={<Navigate to="/" />} />
        </Routes></main>
      </div>
    </div>
  );
}

function PageHeader({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: ReactNode }) {
  return <div className="page-header"><div><span className="eyebrow">{eyebrow}</span><h1>{title}</h1><p>{description}</p></div>{action}</div>;
}

function Dashboard() {
  const stats = useQuery({ queryKey: ["dashboard"], queryFn: () => request<DashboardStats>("/dashboard") });
  const jobs = useQuery({ queryKey: ["jobs", "recent"], queryFn: () => request<Job[]>("/jobs?limit=6"), refetchInterval: 10_000 });
  if (stats.isLoading) return <Spinner />;
  if (stats.error || !stats.data) return <div className="error-box">{getError(stats.error)}</div>;
  const cards = [
    ["Dossiers ouverts", stats.data.open_cases, FolderKanban, "navy"],
    ["Preuves préservées", stats.data.evidence_count, Database, "blue"],
    ["À valider", stats.data.awaiting_review, UserCheck, "amber"],
    ["Détections malveillantes", stats.data.malicious_jobs, ShieldAlert, "red"],
  ] as const;
  return <>
    <PageHeader eyebrow="Centre d’opérations" title="Vue d’ensemble" description="État de la quarantaine et des analyses du laboratoire." action={<Link className="button primary" to="/cases"><Plus size={17} /> Nouveau dossier</Link>} />
    <section className="stat-grid">{cards.map(([label, value, Icon, color]) => <div className={`stat-card ${color}`} key={label}><div className="stat-icon"><Icon /></div><div><span>{label}</span><strong>{value}</strong></div></div>)}</section>
    <section className="grid-two">
      <div className="panel">
        <div className="panel-title"><div><span className="eyebrow">Activité</span><h2>Analyses récentes</h2></div><Link to="/jobs">Tout afficher <ChevronRight size={15} /></Link></div>
        {!jobs.data?.length ? <EmptyState icon={<ScanSearch />} title="Aucune analyse">Les analyses lancées depuis un dossier apparaîtront ici.</EmptyState> : <div className="list">{jobs.data.map((job) => <Link to={`/jobs/${job.id}`} className="list-row" key={job.id}><div className={`severity-dot verdict-${job.verdict ?? "pending"}`} /><div className="grow"><strong>Analyse {job.id.slice(0, 8).toUpperCase()}</strong><span>{formatDate(job.requested_at)}</span></div>{job.verdict ? <Pill value={job.verdict} /> : <Pill value={job.status} />}<ChevronRight size={17} /></Link>)}</div>}
      </div>
      <div className="panel system-panel">
        <div className="panel-title"><div><span className="eyebrow">Capacités</span><h2>État des moteurs</h2></div><Activity size={19} /></div>
        <div className="system-row"><span><Server /> Analyse statique</span><b className="ok"><CheckCircle2 /> ClamAV + YARA</b></div>
        <div className="system-row"><span><BrainCircuit /> Modèle supervisé</span><b className={stats.data.model_active ? "ok" : "warn"}>{stats.data.model_active ? <><CheckCircle2 /> Actif</> : <><AlertTriangle /> À entraîner</>}</b></div>
        <div className="system-row"><span><ScanSearch /> Sandbox CAPE</span><b className={stats.data.sandbox_configured ? "ok" : "warn"}>{stats.data.sandbox_configured ? <><CheckCircle2 /> Configurée</> : <><AlertTriangle /> Non configurée</>}</b></div>
        <p className="system-note">Le système ne remplace jamais une analyse indisponible par une donnée simulée.</p>
      </div>
    </section>
  </>;
}

function CasesPage() {
  const client = useQueryClient();
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ reference: "", title: "", description: "", classification: "Interne" });
  const cases = useQuery({ queryKey: ["cases"], queryFn: () => request<CaseRecord[]>("/cases") });
  const create = useMutation({
    mutationFn: () => request<CaseRecord>("/cases", { method: "POST", body: JSON.stringify(form) }),
    onSuccess: () => { client.invalidateQueries({ queryKey: ["cases"] }); setShowForm(false); setForm({ reference: "", title: "", description: "", classification: "Interne" }); },
  });
  return <>
    <PageHeader eyebrow="Chaîne de conservation" title="Dossiers" description="Organisez les pièces à conviction par affaire judiciaire." action={<button className="button primary" onClick={() => setShowForm(true)}><Plus size={17} /> Nouveau dossier</button>} />
    {showForm && <div className="modal-backdrop"><form className="modal" onSubmit={(e) => { e.preventDefault(); create.mutate(); }}><div className="modal-head"><div><span className="eyebrow">Création</span><h2>Nouveau dossier</h2></div><button type="button" className="icon-button" onClick={() => setShowForm(false)}><X /></button></div><div className="form-grid"><label>Référence officielle<input value={form.reference} onChange={(e) => setForm({ ...form, reference: e.target.value })} placeholder="AFF-2026-001" required /></label><label>Classification<select value={form.classification} onChange={(e) => setForm({ ...form, classification: e.target.value })}><option>Interne</option><option>Confidentiel</option><option>Secret</option></select></label><label className="full">Intitulé<input value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} required /></label><label className="full">Contexte<textarea value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} rows={4} /></label></div>{create.error && <div className="error-box">{getError(create.error)}</div>}<div className="modal-actions"><button type="button" className="button ghost" onClick={() => setShowForm(false)}>Annuler</button><button className="button primary" disabled={create.isPending}>Créer et journaliser</button></div></form></div>}
    {cases.isLoading ? <Spinner /> : !cases.data?.length ? <EmptyState icon={<FolderKanban />} title="Aucun dossier">Créez le premier dossier pour enregistrer une pièce à conviction.</EmptyState> : <div className="case-grid">{cases.data.map((item) => <Link className="case-card" to={`/cases/${item.id}`} key={item.id}><div className="case-card-top"><span className="case-ref">{item.reference}</span><Pill value={item.status} /></div><h3>{item.title}</h3><p>{item.description || "Aucune description."}</p><div className="case-meta"><span><LockKeyhole /> {item.classification}</span><span>{formatDate(item.created_at)}</span></div></Link>)}</div>}
  </>;
}

function CaseDetail() {
  const { caseId = "" } = useParams();
  const client = useQueryClient();
  const navigate = useNavigate();
  const [showUpload, setShowUpload] = useState(false);
  const [upload, setUpload] = useState<{ file: File | null; label: string; kind: string; notes: string; source: string }>({ file: null, label: "", kind: "file", notes: "", source: "" });
  const caseQuery = useQuery({ queryKey: ["case", caseId], queryFn: () => request<CaseRecord>(`/cases/${caseId}`) });
  const evidence = useQuery({ queryKey: ["evidence", caseId], queryFn: () => request<Evidence[]>(`/cases/${caseId}/evidence`) });
  const uploadMutation = useMutation({
    mutationFn: async () => {
      if (!upload.file) throw new Error("Sélectionnez un fichier");
      const data = new FormData();
      data.append("file", upload.file); data.append("case_id", caseId); data.append("label", upload.label); data.append("kind", upload.kind); data.append("acquisition_notes", upload.notes); if (upload.source) data.append("source_identifier", upload.source);
      return request<Evidence>("/evidence", { method: "POST", body: data });
    },
    onSuccess: () => { client.invalidateQueries({ queryKey: ["evidence", caseId] }); setShowUpload(false); setUpload({ file: null, label: "", kind: "file", notes: "", source: "" }); },
  });
  const analyze = useMutation({ mutationFn: (id: string) => request<Job>(`/evidence/${id}/analyze`, { method: "POST" }), onSuccess: (job) => navigate(`/jobs/${job.id}`) });
  if (caseQuery.isLoading) return <Spinner />;
  if (!caseQuery.data) return <div className="error-box">Dossier introuvable</div>;
  const record = caseQuery.data;
  return <>
    <div className="breadcrumbs"><Link to="/cases">Dossiers</Link><ChevronRight /><span>{record.reference}</span></div>
    <PageHeader eyebrow={`${record.classification} · ${record.reference}`} title={record.title} description={record.description || "Dossier sans description."} action={record.status === "open" ? <button className="button primary" onClick={() => setShowUpload(true)}><Upload size={17} /> Ajouter une preuve</button> : <Pill value={record.status} />} />
    <div className="integrity-banner"><Fingerprint /><div><strong>Préservation active</strong><span>Chaque pièce est hachée pendant l’ingestion, stockée en lecture seule et vérifiée avant analyse.</span></div></div>
    {showUpload && <div className="modal-backdrop"><form className="modal wide-modal" onSubmit={(e) => { e.preventDefault(); uploadMutation.mutate(); }}><div className="modal-head"><div><span className="eyebrow">Ingestion forensique</span><h2>Ajouter une pièce à conviction</h2></div><button type="button" className="icon-button" onClick={() => setShowUpload(false)}><X /></button></div><div className="form-grid"><label className="full file-drop"><Upload /><strong>{upload.file?.name ?? "Sélectionner la preuve ou l’image forensique"}</strong><span>Le transfert est haché en flux, sans charger le fichier en mémoire.</span><input type="file" onChange={(e) => setUpload({ ...upload, file: e.target.files?.[0] ?? null, label: upload.label || e.target.files?.[0]?.name || "" })} required /></label><label>Libellé de la preuve<input value={upload.label} onChange={(e) => setUpload({ ...upload, label: e.target.value })} required /></label><label>Type<select value={upload.kind} onChange={(e) => setUpload({ ...upload, kind: e.target.value })}><option value="file">Fichier individuel</option><option value="archive">Archive</option><option value="raw_image">Image brute (DD/IMG/RAW)</option><option value="ewf_image">Image EWF (E01)</option></select></label><label className="full">Identifiant du support / scellé<input value={upload.source} onChange={(e) => setUpload({ ...upload, source: e.target.value })} placeholder="N° scellé, série du support…" /></label><label className="full">Notes d’acquisition<textarea value={upload.notes} onChange={(e) => setUpload({ ...upload, notes: e.target.value })} rows={3} /></label></div>{uploadMutation.error && <div className="error-box"><AlertTriangle />{getError(uploadMutation.error)}</div>}<div className="modal-actions"><button type="button" className="button ghost" onClick={() => setShowUpload(false)}>Annuler</button><button className="button primary" disabled={uploadMutation.isPending}>{uploadMutation.isPending ? "Ingestion et hachage…" : "Préserver la preuve"}</button></div></form></div>}
    <section className="panel"><div className="panel-title"><div><span className="eyebrow">Inventaire</span><h2>Pièces à conviction</h2></div><span className="count">{evidence.data?.length ?? 0}</span></div>{evidence.isLoading ? <Spinner /> : !evidence.data?.length ? <EmptyState icon={<FileDigit />} title="Aucune preuve enregistrée">Ajoutez une image forensique, une archive ou un fichier isolé.</EmptyState> : <div className="evidence-table"><div className="table-head"><span>Pièce</span><span>Type / taille</span><span>Intégrité</span><span>État</span><span /></div>{evidence.data.map((item) => <div className="table-row" key={item.id}><div><strong>{item.label}</strong><small>{item.original_filename}</small></div><div><span>{item.kind.replace("_", " ")}</span><small>{formatBytes(item.size_bytes)}</small></div><code title={item.sha256}>{item.sha256.slice(0, 14)}…</code><Pill value={item.status} /><button className="button small" onClick={() => analyze.mutate(item.id)} disabled={analyze.isPending || item.status === "compromised" || item.status === "analyzing"}><ScanSearch size={15} /> Analyser</button></div>)}</div>}</section>
    {analyze.error && <div className="error-box"><AlertTriangle />{getError(analyze.error)}</div>}
  </>;
}

function JobsPage() {
  const [filter, setFilter] = useState("");
  const jobs = useQuery({ queryKey: ["jobs", filter], queryFn: () => request<Job[]>(`/jobs?limit=200${filter ? `&status=${filter}` : ""}`), refetchInterval: 10_000 });
  return <>
    <PageHeader eyebrow="Orchestration multi-agents" title="Analyses" description="Suivez le pipeline, les verdicts automatisés et les validations expertes." action={<select className="filter-select" value={filter} onChange={(e) => setFilter(e.target.value)}><option value="">Tous les états</option><option value="queued">En file</option><option value="running">En cours</option><option value="awaiting_review">À valider</option><option value="approved">Approuvées</option><option value="failed">Échecs</option></select>} />
    <section className="panel">{jobs.isLoading ? <Spinner /> : !jobs.data?.length ? <EmptyState icon={<ScanSearch />} title="Aucune analyse">Lancez une analyse depuis une pièce à conviction.</EmptyState> : <div className="job-table"><div className="table-head"><span>Analyse</span><span>État</span><span>Verdict</span><span>Risque</span><span>Date</span><span /></div>{jobs.data.map((job) => <Link className="table-row" to={`/jobs/${job.id}`} key={job.id}><div><strong>{job.id.slice(0, 8).toUpperCase()}</strong><small>Pipeline {job.pipeline_version}</small></div><Pill value={job.status} /><div>{job.verdict ? <Pill value={job.verdict} /> : "—"}</div><strong className={`risk-text risk-${job.verdict ?? "pending"}`}>{job.risk_score == null ? "—" : `${job.risk_score}/100`}</strong><span>{formatDate(job.requested_at)}</span><ChevronRight /></Link>)}</div>}</section>
  </>;
}

function RiskGauge({ score, verdict }: { score: number | null; verdict: Verdict | null }) {
  const value = score ?? 0;
  return <div className={`risk-gauge risk-${verdict ?? "pending"}`} style={{ "--risk": `${value * 3.6}deg` } as React.CSSProperties}><div><strong>{score ?? "—"}</strong><span>/100</span></div></div>;
}

function JobDetail({ user }: { user: User }) {
  const { jobId = "" } = useParams();
  const client = useQueryClient();
  const [decision, setDecision] = useState("approve");
  const [comments, setComments] = useState("");
  const job = useQuery({ queryKey: ["job", jobId], queryFn: () => request<Job>(`/jobs/${jobId}`), refetchInterval: (q) => ["queued", "running"].includes(q.state.data?.status ?? "") ? 3000 : false });
  const artifacts = useQuery({
    queryKey: ["artifacts", job.data?.evidence_id],
    queryFn: () => request<Artifact[]>(`/evidence/${job.data!.evidence_id}/artifacts`),
    enabled: Boolean(job.data?.evidence_id) && !["queued", "running"].includes(job.data?.status ?? ""),
  });
  const labelArtifact = useMutation({
    mutationFn: ({ id, label }: { id: string; label: "benign" | "malicious" }) => request<void>(`/artifacts/${id}/ground-truth`, { method: "PUT", body: JSON.stringify({ label, notes: `Qualification depuis l'analyse ${jobId}` }) }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["artifacts", job.data?.evidence_id] }),
  });
  const review = useMutation({ mutationFn: () => request<Job>(`/jobs/${jobId}/review`, { method: "POST", body: JSON.stringify({ decision, comments }) }), onSuccess: () => client.invalidateQueries({ queryKey: ["job", jobId] }) });
  if (job.isLoading) return <Spinner label="Chargement du dossier d’analyse…" />;
  if (!job.data) return <div className="error-box">Analyse introuvable</div>;
  const data = job.data;
  const findings = [...(data.findings ?? [])].sort((a, b) => b.severity - a.severity);
  const complete = data.summary.analysis_complete !== false;
  return <>
    <div className="breadcrumbs"><Link to="/jobs">Analyses</Link><ChevronRight /><span>{data.id.slice(0, 8).toUpperCase()}</span></div>
    <PageHeader eyebrow={`Pipeline ${data.pipeline_version}`} title={`Analyse ${data.id.slice(0, 8).toUpperCase()}`} description={`Demandée le ${formatDate(data.requested_at)}`} action={<div className="header-actions"><Pill value={data.status} />{!["queued", "running", "failed"].includes(data.status) && <button className="button" onClick={() => downloadReport(data.id)}><Download size={16} /> Rapport PDF</button>}</div>} />
    {(data.status === "queued" || data.status === "running") && <div className="progress-card"><div className="radar"><ScanSearch /></div><div><strong>{data.status === "queued" ? "Analyse en attente d’un worker" : "Les agents spécialisés travaillent"}</strong><span>Intégrité → Extraction → Statique → IA → Sandbox → Consolidation</span></div><RefreshCw className="spin" /></div>}
    {data.status === "failed" && <div className="error-box"><XCircle />{data.error_message}</div>}
    {!complete && <div className="warning-banner"><AlertTriangle /><div><strong>Couverture dynamique incomplète</strong><span>La sandbox n’a produit aucun résultat de substitution. Le verdict tient compte de cette limite et doit être examiné par un expert.</span></div></div>}
    <section className="analysis-hero"><RiskGauge score={data.risk_score} verdict={data.verdict} /><div className="verdict-block"><span className="eyebrow">Verdict automatisé</span><h2>{data.verdict ? verdictLabels[data.verdict] : "En cours"}</h2><p>Ce résultat assiste l’expert ; il ne constitue jamais une décision judiciaire autonome.</p></div><div className="summary-metrics"><div><span>Artefacts</span><strong>{String(data.summary.artifacts_analyzed ?? "—")}</strong></div><div><span>Sandbox</span><strong>{String(data.summary.sandbox_completed ?? 0)} / {String(data.summary.sandbox_requested ?? 0)}</strong></div><div><span>Modèle IA</span><strong>{data.summary.ml_model ? "Actif" : "Non entraîné"}</strong></div></div></section>
    <section className="grid-analysis">
      <div className="panel"><div className="panel-title"><div><span className="eyebrow">Observations corrélées</span><h2>Constats techniques</h2></div><span className="count">{findings.length}</span></div>{!findings.length ? <EmptyState icon={<ShieldCheck />} title="Aucun constat">Aucun indicateur notable n’a été enregistré.</EmptyState> : <div className="findings">{findings.map((finding) => <FindingCard finding={finding} key={finding.id} />)}</div>}</div>
      <aside className="review-column">
        <div className="panel"><div className="panel-title"><div><span className="eyebrow">Traçabilité</span><h2>Étapes du pipeline</h2></div></div><div className="timeline"><div className="done"><CheckCircle2 /><span><b>Intégrité</b>Empreintes vérifiées</span></div><div className={data.started_at ? "done" : ""}><CheckCircle2 /><span><b>Extraction</b>Copie de travail isolée</span></div><div className={data.finished_at ? "done" : ""}><CheckCircle2 /><span><b>Analyse</b>Moteurs spécialisés</span></div><div className={["approved", "rejected"].includes(data.status) ? "done" : ""}><UserCheck /><span><b>Validation</b>Décision humaine</span></div></div></div>
        {(user.role === "admin" || user.role === "reviewer") && !["queued", "running", "failed"].includes(data.status) && <form className="panel review-form" onSubmit={(e) => { e.preventDefault(); review.mutate(); }}><span className="eyebrow">Human in the loop</span><h2>Décision de l’expert</h2>{data.review && <div className="previous-review"><CheckCircle2 /> Dernière décision : <b>{data.review.decision}</b></div>}<label>Décision<select value={decision} onChange={(e) => setDecision(e.target.value)}><option value="approve">Approuver</option><option value="reject">Rejeter</option><option value="needs_more_analysis">Analyse complémentaire</option></select></label><label>Justification<textarea rows={5} value={comments} onChange={(e) => setComments(e.target.value)} required minLength={3} placeholder="Motifs techniques et appréciation de l’expert…" /></label>{review.error && <div className="error-box">{getError(review.error)}</div>}<button className="button primary wide" disabled={review.isPending}><UserCheck size={16} /> Enregistrer la décision</button></form>}
      </aside>
    </section>
    {!['queued', 'running'].includes(data.status) && <ArtifactLabelPanel artifacts={artifacts.data ?? []} canLabel={user.role === "admin" || user.role === "reviewer"} pendingId={labelArtifact.isPending ? labelArtifact.variables?.id : undefined} error={labelArtifact.error} onLabel={(id, label) => labelArtifact.mutate({ id, label })} />}
  </>;
}

function ArtifactLabelPanel({ artifacts, canLabel, pendingId, error, onLabel }: { artifacts: Artifact[]; canLabel: boolean; pendingId?: string; error: Error | null; onLabel: (id: string, label: "benign" | "malicious") => void }) {
  return <section className="panel artifact-panel">
    <div className="panel-title"><div><span className="eyebrow">Apprentissage supervisé</span><h2>Qualification des artefacts</h2></div><span className="count">{artifacts.length}</span></div>
    {error && <div className="error-box"><AlertTriangle />{getError(error)}</div>}
    {!artifacts.length ? <EmptyState icon={<Database />} title="Aucun artefact exploitable">Le pipeline n’a extrait aucun fichier qualifiable.</EmptyState> : <div className="artifact-list">{artifacts.map((artifact) => <div className="artifact-row" key={artifact.id}>
      <div className="artifact-file"><FileDigit /><div><strong title={artifact.relative_path}>{artifact.relative_path}</strong><span>{artifact.mime_type} · {formatBytes(artifact.size_bytes)}</span><code title={artifact.sha256}>{artifact.sha256.slice(0, 22)}…</code></div></div>
      {artifact.ground_truth_label && <Pill value={artifact.ground_truth_label} />}
      {canLabel ? <div className="label-actions"><button className="button small" disabled={pendingId === artifact.id} onClick={() => onLabel(artifact.id, "benign")}><ShieldCheck size={14} /> Bénin</button><button className="button small danger" disabled={pendingId === artifact.id} onClick={() => onLabel(artifact.id, "malicious")}><ShieldAlert size={14} /> Malveillant</button></div> : <span className="readonly-label">Qualification réservée aux experts</span>}
    </div>)}</div>}
  </section>;
}

function FindingCard({ finding }: { finding: Finding }) {
  const level = finding.severity >= 80 ? "critical" : finding.severity >= 50 ? "medium" : "low";
  return <article className={`finding ${level}`}><div className="finding-score">{finding.severity}</div><div className="grow"><div className="finding-head"><div><span>{finding.agent.replace("agent-", "Agent ")}</span><h3>{finding.title}</h3></div><span className="category">{finding.category}</span></div><p>{finding.description}</p>{finding.confidence != null && <small>Confiance : {Math.round(finding.confidence * 100)} %</small>}</div></article>;
}

function ModelsPage({ user }: { user: User }) {
  const client = useQueryClient();
  const models = useQuery({ queryKey: ["models"], queryFn: () => request<ModelVersion[]>("/models") });
  const train = useMutation({ mutationFn: () => request<ModelVersion>("/models/train", { method: "POST" }), onSuccess: () => client.invalidateQueries({ queryKey: ["models"] }) });
  return <>
    <PageHeader eyebrow="Apprentissage continu contrôlé" title="Modèles IA" description="Versions entraînées uniquement sur les verdicts réellement validés par les experts." action={(user.role === "admin" || user.role === "reviewer") ? <button className="button primary" onClick={() => train.mutate()} disabled={train.isPending}><BrainCircuit size={17} /> {train.isPending ? "Entraînement…" : "Entraîner une version"}</button> : undefined} />
    <div className="integrity-banner"><ShieldCheck /><div><strong>Aucune donnée synthétique de production</strong><span>Un entraînement est refusé tant que chaque classe ne possède pas le nombre minimal d’artefacts réels validés.</span></div></div>
    {train.error && <div className="error-box"><AlertTriangle />{getError(train.error)}</div>}
    <section className="panel">{models.isLoading ? <Spinner /> : !models.data?.length ? <EmptyState icon={<BrainCircuit />} title="Aucun modèle entraîné">Labellisez des artefacts bénins et malveillants, puis lancez un entraînement contrôlé.</EmptyState> : <div className="model-list">{models.data.map((model) => <div className="model-card" key={model.id}><div className="model-icon"><BrainCircuit /></div><div className="grow"><div className="model-title"><h3>{model.version}</h3>{model.is_active && <span className="active-label">ACTIF</span>}</div><p>{model.algorithm} · créé le {formatDate(model.created_at)}</p><code>{model.training_manifest_hash}</code></div><div className="model-metric"><span>Exactitude</span><strong>{typeof model.metrics.accuracy === "number" ? `${Math.round(model.metrics.accuracy * 100)} %` : "—"}</strong></div><div className="model-metric"><span>Échantillons</span><strong>{String((model.metrics.training_samples as number | undefined) ?? "—")}</strong></div></div>)}</div>}</section>
  </>;
}

interface AuditRow { sequence: number; actor_id: string | null; action: string; target_type: string; target_id: string; created_at: string; event_hash: string; previous_hash: string; payload: Record<string, unknown> }
function AuditPage() {
  const audit = useQuery({ queryKey: ["audit"], queryFn: () => request<AuditRow[]>("/audit?limit=500") });
  const verify = useQuery({ queryKey: ["audit-verify"], queryFn: () => request<{ valid: boolean; events_checked: number; first_invalid_hash: string | null }>("/audit/verify") });
  return <>
    <PageHeader eyebrow="Preuve de traçabilité" title="Journal d’audit" description="Événements append-only liés par une chaîne HMAC vérifiable." action={verify.data && <div className={`chain-status ${verify.data.valid ? "valid" : "invalid"}`}>{verify.data.valid ? <ShieldCheck /> : <ShieldAlert />}<div><strong>{verify.data.valid ? "Chaîne valide" : "Chaîne invalide"}</strong><span>{verify.data.events_checked} événements vérifiés</span></div></div>} />
    <section className="panel">{audit.isLoading ? <Spinner /> : <div className="audit-list">{audit.data?.map((event) => <div className="audit-row" key={event.sequence}><div className="audit-seq">#{event.sequence}</div><div className="audit-line" /><div className="grow"><div className="audit-title"><strong>{event.action}</strong><span>{formatDate(event.created_at)}</span></div><p>{event.target_type} · {event.target_id}</p><code title={event.event_hash}>{event.event_hash.slice(0, 24)}…</code></div></div>)}</div>}</section>
  </>;
}

export default function App() {
  const token = auth.token();
  const user = useQuery({ queryKey: ["me"], queryFn: () => request<User>("/auth/me"), enabled: Boolean(token), retry: false });
  if (!token || user.isError) return <LoginPage />;
  if (user.isLoading || !user.data) return <div className="splash"><div className="brand-mark large"><Fingerprint /></div><Spinner label="Ouverture de l’espace sécurisé…" /></div>;
  return <Layout user={user.data} />;
}
