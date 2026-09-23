/**
 * X-Wall — Scam QR Code & Payment Link Analyzer
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
} from "lucide-react";
import "./App.css";

const API_BASE = "http://localhost:8000";

function App() {
  const [inputMode, setInputMode] = useState("link"); // "link" | "qr"
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
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ url: raw }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Analysis failed");
        setResult(data);
      } catch (err) {
        setError(err.message);
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
        if (!res.ok) throw new Error(data.detail || "Analysis failed");
        setResult(data);
      } catch (err) {
        setError(err.message);
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
    setQrFile(file);
    setError(null);
    const reader = new FileReader();
    reader.onload = (ev) => setQrPreview(ev.target.result);
    reader.readAsDataURL(file);
  };

  const handlePaste = (e) => {
    const text = e.clipboardData.getData("text").trim();
    if (text) {
      setUrlInput(text);
      setInputMode("link");
    }
  };

  const clearAll = () => {
    setUrlInput("");
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
          <h1>X-Wall</h1>
          <span className="tagline">Scam QR & Payment Link Analyzer</span>
        </div>
        <div className="header-right">
          <Info className="header-icon" title="Prototype — checks are rule-based with stubbed domain age / threat feeds" />
        </div>
      </header>

      <main className="main">
        {!result ? (
          <ScannerForm
            inputMode={inputMode}
            setInputMode={setInputMode}
            urlInput={urlInput}
            setUrlInput={setUrlInput}
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
        <p>Prototype — no data stored or transmitted. Domain age & threat feeds are stubbed.</p>
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
      </div>

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
          disabled={isAnalyzing || (inputMode === "link" && !urlInput.trim()) || (inputMode === "qr" && !qrFile)}
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
        {(urlInput.trim() || qrFile) && (
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
  const { score, verdict, verdict_detail, reasons, redirect_chain, final_url, decoded_text, stubs_active, landing_page_check } = result;

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

      {stubs_active && stubs_active.length > 0 && (
        <div className="stubs-notice">
          <Info className="stubs-icon" />
          <div>
            <strong>Note:</strong> The following checks are <em>stubbed</em> for this prototype:
            <ul>
              {stubs_active.map((s, i) => <li key={i}>{s}</li>)}
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

export default App;