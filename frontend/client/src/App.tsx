import { useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowDown,
  ArrowRight,
  Ban,
  BadgeCheck,
  BrainCircuit,
  Check,
  ChevronDown,
  Circle,
  CircleDot,
  ClipboardCheck,
  Clock3,
  Copy,
  DatabaseZap,
  FileImage,
  Flag,
  Globe2,
  Info,
  Link2,
  LockKeyhole,
  Menu,
  QrCode,
  Radar,
  RefreshCw,
  Route,
  ScanLine,
  ScanSearch,
  ServerCog,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  UploadCloud,
  X,
  Zap,
} from "lucide-react";
import { analyzeLink, analyzeQR, type NormalizedAnalysis, type Verdict } from "./api/analyze";
import "./index.css";

type InputMode = "qr" | "link";
type ScanState = "idle" | "analyzing" | "complete" | "error";
type DemoKey = "safe" | "suspicious" | "dangerous";

type Signal = {
  label: string;
  status: string;
  detail: string;
  icon: typeof Globe2;
  tone: "cyan" | "amber" | "red" | "green" | "muted";
};

const DEMOS: Record<DemoKey, NormalizedAnalysis> = {
  dangerous: {
    verdict: "Dangerous",
    score: 92,
    target: "https://paytm-refund-verify.example/claim",
    reasons: [
      "Domain registered 2 days ago.",
      "Domain resembles a known payment brand.",
      "Suspicious URL keywords: refund, verify, claim.",
      "3 redirects detected before the final destination.",
    ],
    redirectChain: [
      "https://paytm-refund-verify.example/claim",
      "https://secure-check.example/verify",
      "https://offer-center.example/collect",
      "http://198.51.100.24/payment",
    ],
    upi: null,
    source: "demo",
  },
  suspicious: {
    verdict: "Suspicious",
    score: 58,
    target: "https://quick-invoice.example/pay?id=18402",
    reasons: [
      "Domain age could not be independently verified.",
      "Payment request uses an unfamiliar merchant domain.",
      "Amount and payee should be confirmed through another channel.",
    ],
    redirectChain: ["https://quick-invoice.example/pay?id=18402", "https://checkout.example/session/18402"],
    upi: { payee: "billing@upi", name: "Quick Invoice Services", amount: "1,299", currency: "INR" },
    source: "demo",
  },
  safe: {
    verdict: "Safe",
    score: 12,
    target: "https://merchant.example/checkout/order-18402",
    reasons: [
      "No major risk indicators were detected.",
      "Destination uses HTTPS with a consistent domain.",
      "Payment payload is complete and internally consistent.",
    ],
    redirectChain: ["https://merchant.example/checkout/order-18402"],
    upi: { payee: "merchant@upi", name: "Demo Store", amount: "499", currency: "INR" },
    source: "demo",
  },
};

const STAGES = [
  "Input received",
  "QR / URL decoded",
  "Inspecting domain",
  "Checking redirects",
  "Analyzing payment payload",
  "Calculating risk",
];

const SIGNALS: Signal[] = [
  { label: "DOMAIN AGE", status: "Demo Stub", detail: "Domain history adapter ready for backend data.", icon: Clock3, tone: "amber" },
  { label: "LOOK-ALIKE DETECTION", status: "Checked", detail: "Brand similarity rules are active.", icon: ShieldCheck, tone: "green" },
  { label: "URL KEYWORDS", status: "Checked", detail: "Refund and urgency language is scored.", icon: ScanSearch, tone: "green" },
  { label: "REDIRECT ANALYSIS", status: "Checked", detail: "Redirect hops are mapped before verdict.", icon: Route, tone: "green" },
  { label: "UPI VALIDATION", status: "Demo Stub", detail: "Payee validation is shown as a prototype check.", icon: BadgeCheck, tone: "amber" },
  { label: "THREAT INTELLIGENCE", status: "Not Connected", detail: "Connect a threat feed in the FastAPI layer.", icon: DatabaseZap, tone: "muted" },
];

function verdictClass(verdict: Verdict) {
  return verdict.toLowerCase();
}

function verdictLabel(verdict: Verdict) {
  return verdict === "Dangerous" ? "Do not open or continue with this payment." : verdict === "Suspicious" ? "Proceed with caution. Review the detected warnings." : "No major risk indicators were detected.";
}

function formatBytes(bytes: number) {
  if (!bytes) return "0 KB";
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}

function App() {
  const [inputMode, setInputMode] = useState<InputMode>("qr");
  const [linkInput, setLinkInput] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const [scanState, setScanState] = useState<ScanState>("idle");
  const [result, setResult] = useState<NormalizedAnalysis | null>(null);
  const [error, setError] = useState<{ title: string; detail: string } | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [stageIndex, setStageIndex] = useState(0);
  const [pendingDemo, setPendingDemo] = useState<DemoKey | null>(null);
  const [displayScore, setDisplayScore] = useState(0);
  const [chainOpen, setChainOpen] = useState(true);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const currentVerdict = result?.verdict;
  const hasInput = inputMode === "qr" ? Boolean(file) : Boolean(linkInput.trim());

  useEffect(() => {
    if (!preview) return;
    return () => URL.revokeObjectURL(preview);
  }, [preview]);

  useEffect(() => {
    if (scanState !== "analyzing") return;
    setStageIndex(0);
    const timer = window.setInterval(() => setStageIndex((current) => Math.min(current + 1, STAGES.length - 1)), 260);
    return () => window.clearInterval(timer);
  }, [scanState]);

  useEffect(() => {
    if (scanState !== "analyzing") return;
    const timer = window.setTimeout(async () => {
      if (pendingDemo) {
        setResult(DEMOS[pendingDemo]);
        setPendingDemo(null);
        setScanState("complete");
        setChainOpen(true);
        return;
      }

      try {
        const analysis = inputMode === "qr" && file ? await analyzeQR(file) : await analyzeLink(linkInput.trim());
        setResult(analysis);
        setScanState("complete");
        setChainOpen(true);
      } catch {
        setError({ title: "X-Wall analysis service is unavailable.", detail: "Make sure the FastAPI backend is running at the configured API URL." });
        setScanState("error");
      }
    }, 1680);
    return () => window.clearTimeout(timer);
  }, [scanState, pendingDemo, inputMode, file, linkInput]);

  useEffect(() => {
    if (!result) {
      setDisplayScore(0);
      return;
    }
    let frame = 0;
    const start = performance.now();
    const duration = 850;
    const from = 0;
    const to = result.score;
    const tick = (time: number) => {
      const progress = Math.min((time - start) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setDisplayScore(Math.round(from + (to - from) * eased));
      if (progress < 1) frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [result]);

  useEffect(() => {
    if (!notice) return;
    const timer = window.setTimeout(() => setNotice(null), 3200);
    return () => window.clearTimeout(timer);
  }, [notice]);

  const derivedSignals = useMemo(() => {
    if (!result) return SIGNALS;
    return SIGNALS.map((signal, index) => ({
      ...signal,
      tone: result.verdict === "Dangerous" && index === 0 ? "red" : signal.tone,
      status: result.verdict === "Dangerous" && index === 0 ? "Flagged" : signal.status,
    }));
  }, [result]);

  const selectFile = (selected: File | undefined) => {
    if (!selected) return;
    if (!selected.type.match(/image\/(png|jpeg|jpg)/i)) {
      setError({ title: "Unsupported QR image.", detail: "Upload a PNG, JPG, or JPEG image." });
      setScanState("error");
      return;
    }
    if (selected.size > 10 * 1024 * 1024) {
      setError({ title: "This file is too large.", detail: "Choose a QR image smaller than 10 MB." });
      setScanState("error");
      return;
    }
    setFile(selected);
    setPreview(URL.createObjectURL(selected));
    setError(null);
    setScanState("idle");
    setResult(null);
  };

  const switchMode = (mode: InputMode) => {
    setInputMode(mode);
    setError(null);
    setScanState("idle");
    setResult(null);
  };

  const handleScan = () => {
    if (!hasInput) {
      setError(inputMode === "qr" ? { title: "Add a QR code to continue.", detail: "Upload a clear image so X-Wall can decode it safely." } : { title: "Enter a valid URL or UPI payment string.", detail: "Paste a payment link or UPI string before scanning." });
      setScanState("error");
      return;
    }
    if (inputMode === "link" && linkInput.trim() && !/^(https?:\/\/|upi:\/\/)/i.test(linkInput.trim())) {
      setError({ title: "Enter a valid URL or UPI payment string.", detail: "Start with https://, http://, or upi://." });
      setScanState("error");
      return;
    }
    setError(null);
    setResult(null);
    setPendingDemo(null);
    setScanState("analyzing");
  };

  const runDemo = (demo: DemoKey) => {
    setInputMode("link");
    setLinkInput(DEMOS[demo].target);
    setError(null);
    setResult(null);
    setPendingDemo(demo);
    setScanState("analyzing");
    window.setTimeout(() => document.getElementById("scanner")?.scrollIntoView({ behavior: "smooth", block: "center" }), 40);
  };

  const resetScan = () => {
    setResult(null);
    setError(null);
    setNotice(null);
    setScanState("idle");
    setPendingDemo(null);
    setStageIndex(0);
  };

  const copyDestination = async () => {
    if (!result) return;
    try {
      await navigator.clipboard.writeText(result.target);
      setNotice("Destination copied to clipboard.");
    } catch {
      setNotice("Copy is unavailable in this browser.");
    }
  };

  const reportResult = () => {
    console.log("X-Wall report placeholder", result);
    setNotice("Report feature coming soon.");
  };

  return (
    <div className="app-shell">
      <div className="ambient ambient-one" />
      <div className="ambient ambient-two" />
      <Navbar mobileNavOpen={mobileNavOpen} setMobileNavOpen={setMobileNavOpen} />
      <main>
        <Hero />
        <section className="scanner-section section-wrap" id="scanner">
          <div className="section-kicker"><span className="kicker-line" /> CORE ANALYZER <span className="kicker-dim">/ 01</span></div>
          <div className="scanner-heading-row">
            <div>
              <h2>Check before you connect.</h2>
              <p>Inspect a QR code, payment link, or UPI request without opening the destination.</p>
            </div>
            <div className="scanner-status"><span className="status-pulse" /> ANALYSIS ENGINE READY</div>
          </div>

          <div className="scanner-layout">
            <div className="scanner-card glass-panel">
              <div className="scanner-card-top">
                <div>
                  <div className="eyebrow"><ShieldCheck size={14} /> SCAN &amp; ANALYZE</div>
                  <div className="scanner-card-title">Choose your input surface</div>
                </div>
                <div className="input-badge"><LockKeyhole size={13} /> NO CREDENTIALS</div>
              </div>

              <div className="mode-tabs" role="tablist" aria-label="Input type">
                <button className={inputMode === "qr" ? "mode-tab active" : "mode-tab"} onClick={() => switchMode("qr")} role="tab" aria-selected={inputMode === "qr"}><QrCode size={17} /> QR CODE</button>
                <button className={inputMode === "link" ? "mode-tab active" : "mode-tab"} onClick={() => switchMode("link")} role="tab" aria-selected={inputMode === "link"}><Link2 size={17} /> LINK / UPI</button>
              </div>

              {inputMode === "qr" ? (
                <div className="qr-drop-zone" onClick={() => fileInputRef.current?.click()} onDragOver={(event) => event.preventDefault()} onDrop={(event) => { event.preventDefault(); selectFile(event.dataTransfer.files?.[0]); }}>
                  <input ref={fileInputRef} type="file" accept="image/png,image/jpeg" onChange={(event) => selectFile(event.target.files?.[0])} hidden />
                  {file && preview ? (
                    <div className="file-preview" onClick={(event) => event.stopPropagation()}>
                      <div className="qr-preview-frame"><img src={preview} alt="Selected QR code preview" /></div>
                      <div className="file-copy"><span className="file-label"><FileImage size={15} /> SELECTED QR IMAGE</span><strong>{file.name}</strong><span>{formatBytes(file.size)} <span className="dot-separator">•</span> ready to inspect</span></div>
                      <div className="file-actions"><button className="icon-button" aria-label="Change image" onClick={() => fileInputRef.current?.click()}><RefreshCw size={16} /></button><button className="icon-button danger-icon" aria-label="Remove image" onClick={() => { setFile(null); setPreview(null); setResult(null); }}><X size={17} /></button></div>
                    </div>
                  ) : (
                    <div className="drop-content"><div className="upload-orbit"><QrCode size={31} /><div className="orbit-ring" /></div><strong>Drop your QR code here</strong><span>or <b>click to browse</b></span><small>PNG <i>•</i> JPG <i>•</i> JPEG <em>MAX 10 MB</em></small></div>
                  )}
                </div>
              ) : (
                <div className="link-input-wrap">
                  <label htmlFor="payment-link">PAYMENT LINK OR UPI STRING</label>
                  <textarea id="payment-link" value={linkInput} onChange={(event) => { setLinkInput(event.target.value); setError(null); setScanState("idle"); }} placeholder={'https://example.com/payment\n\nupi://pay?pa=merchant@upi&am=499&cu=INR'} spellCheck={false} />
                  <div className="input-helper"><Info size={14} /> We inspect the destination and payment payload without requesting payment credentials.</div>
                </div>
              )}

              {scanState === "analyzing" && <ScanAnimation stageIndex={stageIndex} />}
              {scanState === "error" && error && <ErrorState error={error} onDismiss={() => { setError(null); setScanState("idle"); }} />}
              {scanState === "idle" && !hasInput && <div className="empty-state"><CircleDot size={15} /> Nothing scanned yet. <span>Upload a QR code or paste a payment link to begin.</span></div>}

              <button className="scan-button" onClick={handleScan} disabled={scanState === "analyzing"}>
                {scanState === "analyzing" ? <><Activity size={19} className="spin" /> ANALYZING THREAT...</> : <><Shield size={19} /> SCAN &amp; ANALYZE <ArrowRight size={17} /></>}
              </button>
              <div className="privacy-lock"><LockKeyhole size={14} /><strong>YOUR PAYMENT CREDENTIALS ARE NEVER REQUIRED</strong><span>X-Wall never asks for your UPI PIN, OTP, password, or card details.</span></div>
            </div>

            <aside className="scanner-rail">
              <div className="rail-card demo-card">
                <div className="rail-topline"><span className="demo-dot" /> DEMO MODE <span className="demo-tag">SYNTHETIC</span></div>
                <p>Preview realistic verdicts for your hackathon walkthrough. These examples never contact a real payment service.</p>
                <div className="demo-list"><button onClick={() => runDemo("dangerous")}><span className="demo-swatch red" /><span><strong>Dangerous demo</strong><small>Brand impersonation</small></span><ArrowRight size={15} /></button><button onClick={() => runDemo("suspicious")}><span className="demo-swatch amber" /><span><strong>Suspicious demo</strong><small>Unfamiliar payee</small></span><ArrowRight size={15} /></button><button onClick={() => runDemo("safe")}><span className="demo-swatch green" /><span><strong>Safe demo</strong><small>Consistent destination</small></span><ArrowRight size={15} /></button></div>
              </div>
              <div className="rail-card signal-card"><div className="rail-topline"><Activity size={14} /> LIVE TELEMETRY</div><div className="telemetry-line"><span>LOCAL API</span><b><i className="status-pulse" /> STANDBY</b></div><div className="telemetry-line"><span>DATA RETENTION</span><b>NONE</b></div><div className="telemetry-line"><span>URL NAVIGATION</span><b>BLOCKED</b></div></div>
            </aside>
          </div>
        </section>

        <section className="trust-strip section-wrap" id="security"><div className="trust-intro"><span className="section-kicker">WHY IT MATTERS <span className="kicker-dim">/ 02</span></span><h2>Pause the payment.<br /><span>See the signal.</span></h2></div><div className="trust-points"><div><ShieldCheck size={19} /><strong>BEFORE THE CLICK</strong><p>Destination analysis happens before a browser or payment app is opened.</p></div><div><LockKeyhole size={19} /><strong>PRIVATE BY DESIGN</strong><p>No UPI PIN, OTP, password, or card details are ever part of the flow.</p></div><div><Radar size={19} /><strong>EXPLAINABLE RISK</strong><p>Every verdict is paired with plain-language reasons a user can act on.</p></div></div></section>

        {result && <ResultView result={result} displayScore={displayScore} chainOpen={chainOpen} setChainOpen={setChainOpen} copyDestination={copyDestination} reportResult={reportResult} resetScan={resetScan} derivedSignals={derivedSignals} />}

        <section className="pipeline-section section-wrap" id="how-it-works"><div className="section-kicker"><span className="kicker-line" /> HOW X-WALL ANALYZES A PAYMENT <span className="kicker-dim">/ 03</span></div><div className="pipeline-heading"><div><h2>A verdict you can follow.</h2><p>Signals are collected, scored, and translated into one clear next step.</p></div><div className="pipeline-chip"><Sparkles size={15} /> RULE ENGINE + ML RISK MODEL</div></div><AnalysisPipeline /></section>

        <section className="about-section section-wrap" id="about"><div className="about-card glass-panel"><div className="about-mark"><Shield size={26} /><span>X</span></div><div><span className="section-kicker">X-WALL / PROTOTYPE</span><h2>Security should be<br /><span>visible before it is urgent.</span></h2><p>Built for a cybersecurity + AI hackathon to make scam signals understandable at the moment they matter most.</p></div><div className="about-stat"><span>DESIGNED FOR</span><strong>THE MOMENT<br />BEFORE PAY</strong></div></div></section>
      </main>
      <Footer />
      {notice && <div className="toast"><Check size={15} /> {notice}</div>}
    </div>
  );
}

function Navbar({ mobileNavOpen, setMobileNavOpen }: { mobileNavOpen: boolean; setMobileNavOpen: (value: boolean) => void }) {
  return <header className="top-nav"><a className="brand" href="#top" aria-label="X-Wall home"><span className="brand-mark"><Shield size={22} /><b>X</b></span><span className="brand-copy"><strong>X-WALL</strong><small>SECURITY ANALYZER</small></span></a><button className="mobile-menu" aria-label="Toggle navigation" onClick={() => setMobileNavOpen(!mobileNavOpen)}><Menu size={20} /></button><nav className={mobileNavOpen ? "nav-links open" : "nav-links"}><a href="#how-it-works" onClick={() => setMobileNavOpen(false)}>How It Works</a><a href="#security" onClick={() => setMobileNavOpen(false)}>Security</a><a href="#about" onClick={() => setMobileNavOpen(false)}>About</a></nav><div className="system-status"><span className="status-pulse" /> SYSTEM ONLINE</div></header>;
}

function Hero() {
  return <section className="hero section-wrap" id="top"><div className="hero-grid" /><div className="hero-copy"><div className="hero-badge"><span /> CYBERSECURITY <b>×</b> AI</div><h1>DON'T TRUST<br /><span>THE SCAN.</span><br /><em>VERIFY IT FIRST.</em></h1><p>Analyze QR codes, payment links, and UPI payment requests for scam indicators <strong>before you open or pay.</strong></p><a href="#scanner" className="hero-cta">START A CHECK <ArrowRight size={17} /></a></div><div className="hero-visual"><div className="hero-visual-label"><span>THREAT SURFACE</span><b>01 / 03</b></div><div className="hero-shield"><Shield size={150} strokeWidth={0.7} /><div className="hero-crosshair"><span /><span /></div><div className="hero-scan-line" /></div><div className="hero-visual-footer"><span><i className="status-pulse" /> PRE-PAYMENT INSPECTION</span><span>v0.9.4 / LOCAL</span></div></div><div className="hero-steps"><div><span>01</span><strong>SCAN</strong><small>Capture the input</small></div><ArrowRight size={17} /><div><span>02</span><strong>ANALYZE</strong><small>Inspect the signals</small></div><ArrowRight size={17} /><div><span>03</span><strong>VERIFY</strong><small>Choose with context</small></div></div></section>;
}

function ScanAnimation({ stageIndex }: { stageIndex: number }) {
  return <div className="scan-animation"><div className="scan-animation-top"><span className="scan-loader"><ScanLine size={22} /><i /></span><div><strong>ANALYZING THREAT...</strong><small>SAFE MODE / NO NAVIGATION</small></div><span className="scan-progress">{String(Math.min(99, Math.round(((stageIndex + 1) / STAGES.length) * 100))).padStart(2, "0")}%</span></div><div className="stage-list">{STAGES.map((stage, index) => <div key={stage} className={index < stageIndex ? "stage complete" : index === stageIndex ? "stage current" : "stage"}><span>{index < stageIndex ? <Check size={12} /> : index === stageIndex ? <i /> : <Circle size={11} />}</span>{stage}</div>)}</div></div>;
}

function ErrorState({ error, onDismiss }: { error: { title: string; detail: string }; onDismiss: () => void }) {
  return <div className="error-state"><div className="error-icon"><AlertTriangle size={18} /></div><div><strong>{error.title}</strong><span>{error.detail}</span></div><button className="icon-button" onClick={onDismiss} aria-label="Dismiss error"><X size={16} /></button></div>;
}

function RiskScore({ result, displayScore }: { result: NormalizedAnalysis; displayScore: number }) {
  const tone = verdictClass(result.verdict);
  return <div className="risk-score-stack"><div className={`risk-score-card ${tone}`}><div className="risk-ring" style={{ "--score": `${displayScore * 3.6}deg` } as React.CSSProperties}><div className="risk-ring-inner"><span>{displayScore}</span><small>/ 100</small></div></div><div className="risk-copy"><span className="verdict-label"><span className="verdict-dot" /> {result.verdict.toUpperCase()}</span><strong>RISK SCORE</strong><p>{verdictLabel(result.verdict)}</p></div></div><div className={`metric-meter ${tone}`}><div className="metric-meter-head"><span><Activity size={13} /> RISK METRIC METER</span><strong>{displayScore} / 100</strong></div><div className="metric-track"><div className="metric-fill" style={{ width: `${displayScore}%` }} /><span className="metric-marker" style={{ left: `${displayScore}%` }} /></div><div className="metric-labels"><span>0 <b>SAFE</b></span><span>31 <b>SUSPICIOUS</b></span><span>71 <b>DANGEROUS</b></span><span>100</span></div></div></div>;
}

function ResultView({ result, displayScore, chainOpen, setChainOpen, copyDestination, reportResult, resetScan, derivedSignals }: { result: NormalizedAnalysis; displayScore: number; chainOpen: boolean; setChainOpen: (value: boolean) => void; copyDestination: () => void; reportResult: () => void; resetScan: () => void; derivedSignals: Signal[] }) {
  const tone = verdictClass(result.verdict);
  return <section className={`result-section section-wrap ${tone}`} id="analysis-result"><div className="result-heading"><div><span className="section-kicker"><span className="kicker-line" /> ANALYSIS COMPLETE <span className="kicker-dim">/ REPORT 01</span></span><h2>Threat report <span>ready.</span></h2></div><div className="source-tag"><span className="source-dot" /> {result.source === "demo" ? "DEMO MODE / SYNTHETIC" : "LIVE API RESPONSE"}</div></div><div className="result-layout"><div className="result-main"><RiskScore result={result} displayScore={displayScore} /><div className="destination-card"><div className="card-label-row"><span><Globe2 size={14} /> DETECTED DESTINATION</span><button className="copy-button" onClick={copyDestination}><Copy size={14} /> COPY</button></div><code>{result.target}</code><div className="destination-meta"><span>HTTPS</span><span>DOMAIN</span><span>{Math.max(0, result.redirectChain.length - 1)} REDIRECTS</span></div></div><div className="result-actions"><button className={`primary-action ${tone}`} onClick={() => { if (result.verdict === "Dangerous") alert("Don't open: X-Wall will never navigate to this destination."); else setTimeout(() => undefined, 0); }}><Ban size={17} /> {result.verdict === "Dangerous" ? "DON'T OPEN" : "KEEP CLOSED"}</button><button className="secondary-action" onClick={reportResult}><Flag size={16} /> REPORT</button><button className="reset-action" onClick={resetScan}><RefreshCw size={15} /> NEW CHECK</button></div></div><div className="result-side"><div className="side-section"><div className="side-title"><span>WHY THIS WAS FLAGGED</span><small>{result.reasons.length} SIGNALS</small></div><div className="reason-list">{result.reasons.map((reason, index) => <ReasonCard key={`${reason}-${index}`} reason={reason} index={index} verdict={result.verdict} />)}</div></div>{result.upi && <UPIResult upi={result.upi} />}</div></div><div className="report-lower-grid"><div className="signals-panel"><div className="side-title"><span>SECURITY SIGNALS</span><small>PROTOTYPE STATUS VISIBLE</small></div><div className="signals-grid">{derivedSignals.map((signal) => <SignalCard key={signal.label} signal={signal} />)}</div></div><div className="redirect-panel"><button className="redirect-header" onClick={() => setChainOpen(!chainOpen)}><span><Route size={15} /> REDIRECT CHAIN</span><ChevronDown size={17} className={chainOpen ? "rotated" : ""} /></button>{chainOpen && <div className="redirect-list">{result.redirectChain.map((url, index) => <div className="redirect-node-wrap" key={`${url}-${index}`}><div className="redirect-node"><span>{index === result.redirectChain.length - 1 ? <ShieldCheck size={14} /> : <Link2 size={14} />}</span><code>{url}</code></div>{index < result.redirectChain.length - 1 && <ArrowDown size={15} />}</div>)}</div>}</div></div></section>;
}

function ReasonCard({ reason, index, verdict }: { reason: string; index: number; verdict: Verdict }) {
  const icons = [Clock3, Globe2, Zap, Route];
  const Icon = icons[index % icons.length];
  return <div className={`reason-card ${verdictClass(verdict)}`}><div className="reason-icon"><Icon size={16} /></div><div><strong>{index === 0 ? "SIGNAL DETECTED" : index === 1 ? "DESTINATION PATTERN" : index === 2 ? "PAYMENT CONTEXT" : "REDIRECT PATH"}</strong><span>{reason}</span></div></div>;
}

function UPIResult({ upi }: { upi: NonNullable<NormalizedAnalysis["upi"]> }) {
  return <div className="upi-card"><div className="card-label-row"><span><BadgeCheck size={14} /> UPI PAYMENT PAYLOAD</span><span className="verified-chip">STRUCTURED</span></div><div className="upi-grid"><div><small>PAYEE</small><code>{upi.payee || "Not supplied"}</code></div><div><small>NAME</small><strong>{upi.name || "Not supplied"}</strong></div><div><small>AMOUNT</small><strong>{upi.amount ? `₹${upi.amount}` : "Not supplied"}</strong></div><div><small>CURRENCY</small><strong>{upi.currency || "INR"}</strong></div></div><p><LockKeyhole size={13} /> Payment credentials were not requested.</p></div>;
}

function SignalCard({ signal }: { signal: Signal }) {
  const Icon = signal.icon;
  return <div className={`signal-card-item ${signal.tone}`}><div className="signal-icon"><Icon size={16} /></div><div><strong>{signal.label}</strong><span className="signal-status">{signal.status === "Checked" ? <Check size={12} /> : signal.status === "Flagged" ? <AlertTriangle size={12} /> : <Circle size={10} />} {signal.status}</span><small>{signal.detail}</small></div></div>;
}

function AnalysisPipeline() {
  const nodes = [{ icon: UploadCloud, label: "INPUT", detail: "QR / URL" }, { icon: ScanSearch, label: "PARSE", detail: "Decode safely" }, { icon: Radar, label: "SIGNALS", detail: "6 checks" }, { icon: BrainCircuit, label: "SCORE", detail: "Rules + ML" }, { icon: ShieldAlert, label: "VERDICT", detail: "Next step" }];
  return <div className="pipeline"><div className="pipeline-track" />{nodes.map((node, index) => { const Icon = node.icon; return <div className={`pipeline-node ${index === 3 ? "highlight" : ""}`} key={node.label}><div className="pipeline-icon"><Icon size={20} /></div><span>{node.label}</span><small>{node.detail}</small>{index < nodes.length - 1 && <ArrowRight className="pipeline-arrow" size={16} />}</div>; })}</div>;
}

function Footer() {
  return <footer className="footer section-wrap"><div className="footer-brand"><div className="footer-mark"><Shield size={20} /><b>X</b></div><div><strong>X-WALL</strong><span>Scam QR Code &amp; Payment Link Analyzer</span></div></div><div className="footer-tagline">“Scan. Analyze. Verify — before you pay.”</div><div className="footer-meta"><span>PROTOTYPE <b>•</b> CYBERSECURITY × AI</span><small>Built for demonstration purposes.</small></div></footer>;
}

export default App;
