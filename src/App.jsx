
import { useEffect, useState } from "react";
import {
  ShieldCheck,
  LayoutDashboard,
  Network,
  Fingerprint,
  LockKeyhole,
  Activity,
  Bell,
  ShieldAlert,
  CheckCircle2,
  ArrowUpRight,
  Menu,
  RotateCcw,
} from "lucide-react";
import "./App.css";

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000").replace(/\/+$/, "");

async function fetchSummary() {
  const response = await fetch(`${API_BASE_URL}/api/summary`);
  if (!response.ok) {
    let message = `Backend request failed (${response.status})`;
    try {
      const body = await response.json();
      if (typeof body.detail === "string") message = body.detail;
    } catch {
      // Keep the status-based message when the response is not JSON.
    }
    throw new Error(message);
  }
  const data = await response.json();
  if (
    data === null
    || typeof data !== "object"
    || Array.isArray(data)
    || data.status !== "SUCCESS"
    || !Array.isArray(data.organizations)
    || data.organizations.some((organization) => (
      organization === null
      || typeof organization !== "object"
      || Array.isArray(organization)
    ))
  ) {
    throw new Error("Backend returned an incomplete summary.");
  }
  return data;
}

export default function App() {
  const [activePage, setActivePage] = useState("Overview");
  const [menuOpen, setMenuOpen] = useState(false);
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadSummary = async () => {
    setLoading(true);
    setError("");
    try {
      setSummary(await fetchSummary());
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to load backend summary.");
      setSummary(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    let active = true;
    fetchSummary()
      .then((data) => { if (active) setSummary(data); })
      .catch((requestError) => {
        if (active) setError(requestError instanceof Error ? requestError.message : "Unable to load backend summary.");
      })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, []);

  const navigation = [
    { name: "Overview", icon: LayoutDashboard },
    { name: "Threat Detection", icon: ShieldAlert },
    { name: "Privacy & Sharing", icon: LockKeyhole },
    { name: "Threat Matches", icon: Fingerprint },
  ];

  const organizations = summary?.organizations ?? [];
  const commonCategories = summary?.common_categories ?? [];
  const matches = typeof summary?.fingerprint_matches === "number" ? summary.fingerprint_matches : null;
  const privacyPassed = organizations.length > 0 && organizations.every((organization) => organization.privacy_check === "PASSED" && organization.leak_count === 0);

  return (
    <div className="app-shell">
      <aside className={`sidebar ${menuOpen ? "sidebar-open" : ""}`}>
        <div className="brand">
          <div className="brand-icon"><ShieldCheck size={25} /></div>
          <div>
            <h2>TRUSTNET</h2>
            <span>COLLABORATIVE DEFENSE</span>
          </div>
        </div>

        <div className="nav-label">WORKSPACE</div>
        <nav>
          {navigation.map(({ name, icon: Icon }) => (
            <button
              key={name}
              className={`nav-item ${activePage === name ? "active" : ""}`}
              onClick={() => {
                setActivePage(name);
                setMenuOpen(false);
              }}
            >
              <Icon size={19} />
              <span>{name}</span>
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="secure-indicator">
            <span className="status-dot" />
            <div>
              <strong>System Status</strong>
                <p>{loading ? "Connecting to backend" : error ? "Backend unavailable" : "Summary connected"}</p>
            </div>
          </div>
          <p className="sidebar-footer">TRUSTNET · DATATHON</p>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <button
            className="mobile-menu"
            onClick={() => setMenuOpen(!menuOpen)}
            aria-label="Toggle menu"
          >
            <Menu size={22} />
          </button>
          <div className="breadcrumb">
            Workspace <span>/</span> <strong>{activePage}</strong>
          </div>
          <div className="topbar-right">
              <span className="environment">
              <span className="status-dot" /> {loading ? "CONNECTING" : error ? "API UNAVAILABLE" : "LIVE API SUMMARY"}
            </span>
            <button className="icon-button" aria-label="Notifications">
              <Bell size={19} />
            </button>
            <div className="avatar">TN</div>
          </div>
        </header>

        <div className="page-container">
          <section className="welcome-row">
            <div>
              <div className="eyebrow">
                <Activity size={15} /> CYBER THREAT INTELLIGENCE
              </div>
              <h1>{activePage}</h1>
              <p>Collaborative threat intelligence, with privacy at its core.</p>
            </div>
            <div className="protection-badge">
              <ShieldCheck size={18} /> Privacy-first workflow
            </div>
          </section>

          {error && (
            <div className="notice api-error" role="alert">
              <ShieldAlert size={19} />
              <p>{error}</p>
              <button type="button" className="reset-button" onClick={loadSummary} disabled={loading}>
                <RotateCcw size={15} /> Retry
              </button>
            </div>
          )}

          {activePage === "Overview" && (
            <>
              <section className="stats-grid">
                <StatCard icon={Network} label="Connected Organizations" value={loading ? "—" : summary?.organizations_connected ?? "—"} note="Backend summary" color="blue" />
                <StatCard icon={ShieldAlert} label="Threats Detected" value={loading ? "—" : summary?.total_alerts ?? "—"} note="Across both organizations" color="red" />
                <StatCard icon={Fingerprint} label="Fingerprint Matches" value={loading ? "—" : matches ?? "—"} note={summary?.match_type === "CATEGORY_MATCH" ? "Shared category matches" : "From backend summary"} color="purple" />
                <StatCard icon={LockKeyhole} label="Privacy Checks" value={loading || !summary ? "—" : privacyPassed ? "Passed" : "Review"} note={loading ? "Checking backend" : summary ? "Backend validation status" : "Unavailable"} color="green" />
              </section>

              <section className="content-grid">
                <div className="panel threat-panel">
                  <div className="panel-heading">
                    <div>
                      <h3>Recent Threat Activity</h3>
                      <p>Alert totals reported by the backend</p>
                    </div>
                    <button className="text-button" onClick={() => setActivePage("Threat Detection")}>
                      View all <ArrowUpRight size={15} />
                    </button>
                  </div>
                  {loading ? <p className="empty-state">Loading organization summary…</p> : <OrganizationSummary organizations={organizations} />}
                </div>

                <div className="panel collaboration-panel">
                  <div className="panel-heading">
                    <div>
                      <h3>Collaboration Network</h3>
                      <p>Organizations analyzed by the backend</p>
                    </div>
                    <Network size={19} className="muted-icon" />
                  </div>

                  <Organization name={organizations[0]?.name ?? "Organization A"} alertCount={organizations[0]?.alert_count} loading={loading} />
                  <div className="connection-line">
                    <span />
                    <div><LockKeyhole size={15} /> {loading ? "Checking privacy status" : privacyPassed ? "Privacy checks passed" : "Privacy status unavailable"}</div>
                    <span />
                  </div>
                  <Organization name={organizations[1]?.name ?? "Organization B"} alertCount={organizations[1]?.alert_count} loading={loading} purple />

                  <div className="summary-detail">
                    <strong>VirusTotal lookups</strong>
                    <span>{loading ? "Loading…" : summary?.virustotal ? `${summary.virustotal.integration_enabled ? "Enabled" : "Disabled"} · ${summary.virustotal.successful_lookups} successful · ${summary.virustotal.lookup_errors} errors · ${summary.virustotal.public_ip_lookups} public IPs checked · ${summary.virustotal.skipped_non_public_indicators} non-public skipped` : "Unavailable"}</span>
                  </div>

                  <div className="privacy-note">
                    <ShieldCheck size={18} />
                    <p>{summary?.note ?? "The backend summary reports aggregate results. Raw security logs are not displayed here."}</p>
                  </div>
                </div>
              </section>

              <section className="panel workflow-panel">
                <div className="panel-heading">
                  <div>
                    <h3>How TRUSTNET Works</h3>
                    <p>Four stages of privacy-aware collaboration</p>
                  </div>
                </div>
                <div className="workflow-grid">
                  {[
                    { icon: Activity, title: "Local Detection", desc: "Analyze threats locally" },
                    { icon: LockKeyhole, title: "Privacy Filtering", desc: "Remove sensitive fields" },
                    { icon: Fingerprint, title: "Fingerprinting", desc: "Create shareable indicators" },
                    { icon: Network, title: "Threat Matching", desc: "Identify related patterns" },
                  ].map(({ icon: Icon, title, desc }, index) => (
                    <div className="workflow-step" key={title}>
                      <div className="workflow-icon"><Icon size={21} /></div>
                      <span className="step-number">STEP 0{index + 1}</span>
                      <h4>{title}</h4>
                      <p>{desc}</p>
                    </div>
                  ))}
                </div>
              </section>
            </>
          )}

          {activePage === "Threat Detection" && (
            <section className="panel page-panel">
              <div className="panel-heading">
                <div>
                  <h3>Organization Alert Summary</h3>
                    <p>Summary API provides organization totals and shared categories, not individual alert records.</p>
                </div>
                <span className="record-count">{loading ? "Loading…" : `${summary?.total_alerts ?? 0} alerts`}</span>
              </div>

              {loading ? <p className="empty-state">Loading organization summary…</p> : <OrganizationSummary organizations={organizations} />}
            </section>
          )}

          {activePage === "Privacy & Sharing" && (
            <section className="panel page-panel">
              <div className="panel-heading">
                <div>
                  <h3>Privacy & Sharing</h3>
                  <p>Privacy validation results returned by the backend summary.</p>
                </div>
                <LockKeyhole size={22} className="muted-icon" />
              </div>
              <div className="privacy-grid">
                {loading ? <p className="empty-state">Loading privacy checks…</p> : organizations.map((organization) => <PrivacyItem key={organization.name} title={organization.name} status={organization.privacy_check ?? "Unavailable"} desc={`${organization.leak_count ?? "Unknown"} potential leaks reported by backend validation.`} />)}
              </div>
              <div className="notice">
                <ShieldAlert size={19} />
                <p>These statuses reflect the backend's privacy validation result for this analysis. They do not guarantee complete anonymization.</p>
              </div>
            </section>
          )}

          {activePage === "Threat Matches" && (
            <section className="panel page-panel">
              <div className="panel-heading">
                <div>
                  <h3>Cross-Organization Threat Matches</h3>
                  <p>Backend-reported category matches across organizations.</p>
                </div>
                <Fingerprint size={23} className="muted-icon" />
              </div>
              <div className="match-card">
                <div className="match-icon"><Fingerprint size={25} /></div>
                <div className="match-content">
                  <span className="match-label">BACKEND SUMMARY</span>
                  <h3>{loading ? "Loading matches…" : `${matches ?? "—"} fingerprint matches`}</h3>
                  <p>{summary?.note ?? "The API reports aggregate fingerprint-match counts only; it does not provide per-match details."}</p>
                </div>
              </div>
              <div className="category-list">
                <h4>Shared categories ({loading ? "—" : commonCategories.length})</h4>
                {loading ? <p className="empty-state">Loading categories…</p> : commonCategories.length ? commonCategories.map((category) => <span className="category-chip" key={category}>{category}</span>) : <p className="empty-state">No shared categories reported.</p>}
              </div>
              <div className="notice">
                <Activity size={19} />
                <p>Fingerprint matches indicate shared categories; the API does not provide event-level evidence or prove a shared attack.</p>
              </div>
            </section>
          )}

          <footer className="page-footer">
            <span>TRUSTNET <span className="footer-dot">•</span> Privacy-preserving threat intelligence</span>
            <span>Datathon prototype · {loading ? "Loading backend" : error ? "Backend unavailable" : "Backend summary"}</span>
          </footer>
        </div>
      </main>
    </div>
  );
}

function Organization({ name, alertCount, loading, purple = false }) {
  return (
    <div className="organization">
      <div className={`org-icon ${purple ? "purple" : ""}`}><Network size={20} /></div>
      <div className="org-details">
        <strong>{name}</strong>
        <span>{loading ? "Loading summary…" : `${alertCount ?? "—"} alerts reported`}</span>
      </div>
      <span className="connected">{loading ? "…" : alertCount == null ? "—" : "ANALYZED"}</span>
    </div>
  );
}

function StatCard({ icon: Icon, label, value, note, color }) {
  return (
    <div className="stat-card">
      <div className={`stat-icon ${color}`}><Icon size={21} /></div>
      <span className="stat-label">{label}</span>
      <div className="stat-value">{value}</div>
      <span className="stat-note">{note}</span>
    </div>
  );
}

function OrganizationSummary({ organizations }) {
  if (!organizations.length) return <p className="empty-state">Organization summary unavailable.</p>;

  return (
    <div className="organization-summary">
      {organizations.map((organization) => (
        <div className="organization-summary-row" key={organization.name}>
          <strong>{organization.name}</strong>
          <span>{organization.alert_count ?? "—"} alerts</span>
        </div>
      ))}
    </div>
  );
}

function PrivacyItem({ title, status, desc }) {
  return (
    <div className="privacy-item">
      <div className="privacy-item-icon">{status === "PASSED" ? <CheckCircle2 size={19} /> : <ShieldAlert size={19} />}</div>
      <div>
        <h4>{title}</h4>
        <span>{status}</span>
        <p>{desc}</p>
      </div>
    </div>
  );
}
