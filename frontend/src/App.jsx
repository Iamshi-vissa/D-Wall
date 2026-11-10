/**
 * D-WALL — Scam QR Code & Payment Link Analyzer
 * Frontend: React + Vite (plain JSX, no TypeScript)
 */
import { useState, useRef, useEffect } from "react";
import {
  ShieldCheck,
  AlertTriangle,
  XCircle,
  Upload,
  Link,
  QrCode,
  ScanSearch,
  Loader2,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  FileText,
  Image,
  AlertCircle,
  CheckCircle,
  Info,
  Flag,
  Brain,
  ListChecks,
} from "lucide-react";
import "./App.css";

const API_BASE = (import.meta.env.VITE_API_URL || "http://localhost:8000").replace(/\/$/, "");

function App() {
  const [inputMode, setInputMode] = useState("link"); // "link" | "qr" | "bulk"
  const [bulkInput, setBulkInput] = useState("");
  const [bulkResult, setBulkResult] = useState(null);
  const [urlInput, setUrlInput] = useState("");
  const [qrFile, setQrFile] = useState(null);
  const [qrPreview, setQrPreview] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [expanded, setExpanded] = useState(false);
  const fileInputRef = useRef(null);

  const handleAnalyze = async () => {
    setError(null);
    setResult(null);

    if (inputMode === "link") {
      const raw = urlInput.trim();
      if (!raw) {
        setError("Please paste a URL or UPI string.");
        return;
      }
      setIsAnalyzing(true);
      try {
        const res = await fetch(`${API_BASE}/analyze/link`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ input: raw }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(errorText(data));
        setResult(data);
      } catch (err) {
        setError(friendlyError(err));
      } finally {
        setIsAnalyzing(false);
      }
    } else if (inputMode === "bulk") {
      const urls = bulkInput.split(/\r?\n/).map((u) => u.trim()).filter(Boolean);
      if (urls.length === 0) {
        setError("Paste one link per line.");
        return;
      }
      if (urls.length > 1000) {
        setError("Bulk check takes up to 1000 links at a time.");
        return;
      }
      setIsAnalyzing(true);
      try {
        const res = await fetch(`${API_BASE}/analyze/batch`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ urls }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(errorText(data));
        setBulkResult(data);
      } catch (err) {
        setError(friendlyError(err));
      } finally {
        setIsAnalyzing(false);
      }
    } else {
      if (!qrFile) {
        setError("Please select a QR code image first.");
        return;
      }
      setIsAnalyzing(true);
      try {
        const form = new FormData();
        form.append("file", qrFile);
        const res = await fetch(`${API_BASE}/analyze/qr`, {
          method: "POST",
          body: form,
        });
        const data = await res.json();
        if (!res.ok) throw new Error(errorText(data));
        setResult(data);
      } catch (err) {
        setError(friendlyError(err));
      } finally {
        setIsAnalyzing(false);
      }
    }
  };

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    if (!file.type.startsWith("image/")) {
      setError("Please select an image file (PNG, JPG, etc.).");
      return;
    }
    if (file.size > 5 * 1024 * 1024) {
      setError("That image is larger than 5 MB.");
      return;
    }
    setQrFile(file);
    setError(null);
    const reader = new FileReader();
    reader.onload = (ev) => setQrPreview(ev.target.result);
    reader.readAsDataURL(file);
  };

  const handlePaste = (e) => {
    if (inputMode === "bulk" || e.target.tagName === "TEXTAREA") return;
    const text = e.clipboardData.getData("text").trim();
    if (text) {
      setUrlInput(text);
      setInputMode("link");
    }
  };

  const clearAll = () => {
    setUrlInput("");
    setBulkInput("");
    setBulkResult(null);
    setQrFile(null);
    setQrPreview(null);
    setResult(null);
    setError(null);
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  const getVerdictClass = (verdict) => {
    if (verdict === "Safe") return "verdict-safe";
    if (verdict === "Suspicious") return "verdict-suspicious";
    return "verdict-dangerous";
  };

  const getVerdictIcon = (verdict) => {
    if (verdict === "Safe") return <ShieldCheck className="verdict-icon" />;
    if (verdict === "Suspicious") return <AlertTriangle className="verdict-icon" />;
    return <XCircle className="verdict-icon" />;
  };

  return (
    <div className="app" onPaste={handlePaste}>
      <header className="header">
        <div className="header-left">
          <ShieldCheck className="logo-icon" />
          <h1>D-WALL</h1>
          <span className="tagline">Scam QR & Payment Link Analyzer</span>
        </div>
        <div className="header-right">
          <Info className="header-icon" title="Scores combine a trained machine-learning model with expert rules" />
        </div>
      </header>

      <main className="main">
        {bulkResult ? (
          <BulkResultView data={bulkResult} clearAll={clearAll} getVerdictClass={getVerdictClass} />
        ) : !result ? (
          <ScannerForm
            inputMode={inputMode}
            setInputMode={setInputMode}
            urlInput={urlInput}
            setUrlInput={setUrlInput}
            bulkInput={bulkInput}
            setBulkInput={setBulkInput}
            qrFile={qrFile}
            qrPreview={qrPreview}
            handleFileChange={handleFileChange}
            fileInputRef={fileInputRef}
            isAnalyzing={isAnalyzing}
            handleAnalyze={handleAnalyze}
            error={error}
            clearAll={clearAll}
          />
        ) : (
          <ResultView
            result={result}
            expanded={expanded}
            setExpanded={setExpanded}
            handleAnalyze={handleAnalyze}
            clearAll={clearAll}
            getVerdictClass={getVerdictClass}
            getVerdictIcon={getVerdictIcon}
          />
        )}
      </main>

      <footer className="footer">
        <p>No data is stored. Scores come from a trained ML model plus expert rules — always double-check before you pay.</p>
      </footer>
    </div>
  );
}

/* =========================== ScannerForm =========================== */
function ScannerForm({
  inputMode,
  setInputMode,
  urlInput,
  setUrlInput,
  bulkInput,
  setBulkInput,
  qrFile,
  qrPreview,
  handleFileChange,
  fileInputRef,
  isAnalyzing,
  handleAnalyze,
  error,
  clearAll,
}) {
  return (
    <div className="scanner-form">
      <div className="mode-tabs">
        <button
          className={inputMode === "link" ? "active" : ""}
          onClick={() => setInputMode("link")}
        >
          <Link className="tab-icon" />
          <span>Paste Link / UPI</span>
        </button>
        <button
          className={inputMode === "qr" ? "active" : ""}
          onClick={() => setInputMode("qr")}
        >
          <QrCode className="tab-icon" />
          <span>Upload QR Image</span>
        </button>
        <button
          className={inputMode === "bulk" ? "active" : ""}
          onClick={() => setInputMode("bulk")}
        >
          <ListChecks className="tab-icon" />
          <span>Bulk Check</span>
        </button>
      </div>

      {inputMode === "bulk" && (
        <div className="input-area link-input">
          <textarea
            className="url-textarea"
            value={bulkInput}
            onChange={(e) => setBulkInput(e.target.value)}
            placeholder={"Paste up to 1000 links, one per line\nexample.com\npaytm-kyc-refund.xyz/claim.php"}
            rows={8}
            spellCheck={false}
            disabled={isAnalyzing}
          />
          <p className="hint">Bulk check uses the ML model and offline rules only, so it is very fast.</p>
        </div>
      )}

      {inputMode === "link" && (
        <div className="input-area link-input">
          <textarea
            className="url-textarea"
            value={urlInput}
            onChange={(e) => setUrlInput(e.target.value)}
            placeholder="Paste a URL, UPI string (upi://...), or any text from a QR code here…"
            rows={3}
            spellCheck={false}
            disabled={isAnalyzing}
          />
          <p className="hint">Tip: You can also paste directly anywhere on this page (Ctrl+V).</p>
        </div>
      )}

      {inputMode === "qr" && (
        <div className="input-area qr-input">
          <label className="file-dropzone" htmlFor="qr-file-input">
            <input
              ref={fileInputRef}
              id="qr-file-input"
              type="file"
              accept="image/*"
              onChange={handleFileChange}
              className="file-input"
              disabled={isAnalyzing}
            />
            {qrPreview ? (
              <>
                <Image className="dropzone-icon" />
                <img src={qrPreview} alt="QR preview" className="qr-preview-img" />
                <p className="dropzone-text">QR code loaded — click to change</p>
              </>
            ) : (
              <>
                <Upload className="dropzone-icon" />
                <p className="dropzone-text">Drag & drop a QR code image, or click to browse</p>
                <p className="dropzone-hint">PNG, JPG, WebP · max 5 MB</p>
              </>
            )}
          </label>
        </div>
      )}

      {error && <div className="error-banner">{error}</div>}

      <div className="action-buttons">
        <button
          className="btn btn-primary btn-scan"
          onClick={handleAnalyze}
          disabled={
            isAnalyzing ||
            (inputMode === "link" && !urlInput.trim()) ||
            (inputMode === "qr" && !qrFile) ||
            (inputMode === "bulk" && !bulkInput.trim())
          }
        >
          {isAnalyzing ? (
            <>
              <Loader2 className="btn-spinner" />
              Analyzing…
            </>
          ) : (
            <>
              <ScanSearch className="btn-icon" />
              Scan & Analyze
            </>
          )}
        </button>
        {(urlInput.trim() || bulkInput.trim() || qrFile) && (
          <button className="btn btn-secondary" onClick={clearAll}>
            Clear
          </button>
        )}
      </div>
    </div>
  );
}

/* =========================== ResultView =========================== */
function ResultView({
  result,
  expanded,
  setExpanded,
  handleAnalyze,
  clearAll,
  getVerdictClass,
  getVerdictIcon,
}) {
  const { score, verdict, verdict_detail, reasons, redirect_chain, decoded_text, notes, landing_page_check, ml, rule_score, upi } = result;

  return (
    <div className="result-view">
      <div className="result-header">
        <div className={`verdict-badge ${getVerdictClass(verdict)}`}>
          {getVerdictIcon(verdict)}
          <div className="verdict-text">
            <span className="verdict-label">{verdict}</span>
            <span className="verdict-score">Score: {score}/100</span>
          </div>
        </div>
        <p className="verdict-detail">{verdict_detail}</p>
      </div>

      <div className="ml-section">
        <h3>
          <Brain className="section-icon" />
          How the score was made
        </h3>
        <div className="score-split">
          <div className="score-box">
            <span className="score-box-label">ML model</span>
            <span className="score-box-value">
              {ml && ml.available ? `${Math.round(ml.probability * 100)}%` : "n/a"}
            </span>
            <span className="score-box-hint">
              {ml && ml.available ? "chance this is phishing" : upi ? "UPI requests use rules" : "model not loaded"}
            </span>
          </div>
          <div className="score-box">
            <span className="score-box-label">Expert rules</span>
            <span className="score-box-value">{rule_score ?? "–"}</span>
            <span className="score-box-hint">rule points (0–100)</span>
          </div>
        </div>
        <p className="hint">The final score is the higher of the two, so either check can raise the alarm.</p>
      </div>

      {upi && (
        <div className="decoded-section">
          <h3>
            <FileText className="section-icon" />
            UPI Payment Request
          </h3>
          <code className="decoded-text">
            Payee: {upi.payee || "—"}
            {upi.name ? ` (${upi.name})` : ""} · Amount: {upi.amount ? `₹${upi.amount}` : "not set"}
          </code>
        </div>
      )}

      {landing_page_check && landing_page_check.screenshot_b64 && (
        <div className="decoded-section">
          <h3>
            <Image className="section-icon" />
            Landing Page Snapshot
          </h3>
          <img
            src={`data:image/png;base64,${landing_page_check.screenshot_b64}`}
            alt="Landing page screenshot"
            style={{ width: "100%", borderRadius: "8px", border: "1px solid var(--border)", marginTop: "10px" }}
          />
        </div>
      )}

      {decoded_text && (
        <div className="decoded-section">
          <h3>
            <QrCode className="section-icon" />
            Decoded from QR
          </h3>
          <code className="decoded-text">{decoded_text}</code>
        </div>
      )}

      <div className="reasons-section">
        <h3>
          <FileText className="section-icon" />
          Analysis Reasons
          <button
            className="expand-btn"
            onClick={() => setExpanded(!expanded)}
            aria-expanded={expanded}
          >
            {expanded ? <ChevronUp /> : <ChevronDown />}
          </button>
        </h3>
        <ul className={`reasons-list ${expanded ? "expanded" : ""}`}>
          {reasons.map((reason, i) => (
            <li key={i} className="reason-item">
              <AlertCircle className="reason-icon" />
              <span>{reason}</span>
            </li>
          ))}
        </ul>
      </div>

      {redirect_chain.length > 1 && (
        <div className="redirect-section">
          <h3>
            <ExternalLink className="section-icon" />
            Redirect Chain ({redirect_chain.length - 1} hop{redirect_chain.length > 2 ? "s" : ""})
          </h3>
          <ol className="redirect-chain">
            {redirect_chain.map((url, i) => (
              <li key={i} className="redirect-hop">
                <span className="hop-number">{i === 0 ? "①" : "→"}</span>
                <code className="hop-url">{url}</code>
              </li>
            ))}
          </ol>
        </div>
      )}

      {notes && notes.length > 0 && (
        <div className="stubs-notice">
          <Info className="stubs-icon" />
          <div>
            <strong>Notes:</strong>
            <ul>
              {notes.map((s, i) => <li key={i}>{s}</li>)}
            </ul>
          </div>
        </div>
      )}

      <div className="result-actions">
        <button className="btn btn-danger" onClick={() => console.log("Don't Open clicked")}>
          <XCircle className="btn-icon" />
          Don't Open
        </button>
        <button className="btn btn-warning" onClick={() => console.log("Report clicked")}>
          <Flag className="btn-icon" />
          Report
        </button>
        <button className="btn btn-secondary" onClick={clearAll}>
          Scan Another
        </button>
      </div>
    </div>
  );
}

/* =========================== BulkResultView =========================== */
function BulkResultView({ data, clearAll, getVerdictClass }) {
  const counts = data.results.reduce((acc, r) => ({ ...acc, [r.verdict]: (acc[r.verdict] || 0) + 1 }), {});
  return (
    <div className="result-view">
      <div className="result-header">
        <h3 className="bulk-title">
          <ListChecks className="section-icon" />
          Bulk check: {data.count} link{data.count === 1 ? "" : "s"}
        </h3>
        <p className="verdict-detail">
          Safe {counts.Safe || 0} · Suspicious {counts.Suspicious || 0} · Dangerous {counts.Dangerous || 0}
          {!data.model_loaded && " · ML model not loaded, rules only"}
        </p>
      </div>
      <div className="bulk-table-wrap">
        <table className="bulk-table">
          <thead>
            <tr>
              <th>Link</th>
              <th>ML</th>
              <th>Score</th>
              <th>Verdict</th>
            </tr>
          </thead>
          <tbody>
            {[...data.results]
              .sort((a, b) => b.score - a.score)
              .map((r, i) => (
                <tr key={i}>
                  <td>
                    <code className="hop-url">{r.url}</code>
                  </td>
                  <td>{r.ml_probability == null ? "–" : `${Math.round(r.ml_probability * 100)}%`}</td>
                  <td>{r.score}</td>
                  <td>
                    <span className={`bulk-pill ${getVerdictClass(r.verdict)}`}>{r.verdict}</span>
                  </td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>
      <div className="result-actions">
        <button className="btn btn-secondary" onClick={clearAll}>
          Check More
        </button>
      </div>
    </div>
  );
}

function errorText(data) {
  if (!data || !data.detail) return "Analysis failed";
  if (typeof data.detail === "string") return data.detail;
  if (Array.isArray(data.detail)) return data.detail.map((d) => d.msg).join("; ");
  return "Analysis failed";
}

function friendlyError(err) {
  if (err instanceof TypeError) return `Can't reach the D-WALL API at ${API_BASE}. Is the backend running?`;
  return err.message;
}

export default App;