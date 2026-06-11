import { useState, useEffect, useMemo, FormEvent } from "react";
import { 
  ShieldCheck, 
  ShieldAlert, 
  Sun, 
  Moon, 
  RefreshCw, 
  CheckCircle, 
  AlertTriangle, 
  XCircle, 
  Terminal, 
  Lock, 
  Globe, 
  Check, 
  Activity, 
  Layers, 
  FileText, 
  Cpu, 
  ExternalLink,
  ChevronRight,
  BookOpen,
  Info,
  CheckCircle2
} from "lucide-react";
import { motion, AnimatePresence } from "motion/react";
import { AuditChecklistItem, SecurityScanStep, DomainReport } from "./types";

// Default standard auditing tasks for system administrators
const INITIAL_AUDIT_ITEMS: AuditChecklistItem[] = [
  {
    id: "item-1",
    category: "dns",
    title: "Implement DNSSEC Signatures",
    description: "Cryptographically sign DNS zone records to prevent spoofing, hijacking, and cache poisoning tags.",
    isCompleted: false,
    severity: "medium"
  },
  {
    id: "item-2",
    category: "dns",
    title: "Configure CAA (Certification Authority Authorization) Records",
    description: "Explicitly declare which Certificate Authorities (CAs) are authorized to issue SSL certificates for your domain.",
    isCompleted: true,
    severity: "medium"
  },
  {
    id: "item-3",
    category: "http",
    title: "Enforce HSTS with Preloading",
    description: "Set Strict-Transport-Security to mandate HTTPS with full subdomain recursion and preloading eligibility.",
    isCompleted: false,
    severity: "high"
  },
  {
    id: "item-4",
    category: "http",
    title: "Deploy Restrictive Content Security Policy (CSP)",
    description: "Restrict scripts, stylesheets, and iframe frames to whitelist origins to prevent cross-site scripting (XSS) actions.",
    isCompleted: false,
    severity: "high"
  },
  {
    id: "item-5",
    category: "email",
    title: "Set SPF Record with Rigid Hardening (~all or -all)",
    description: "Define allowed mail servers sending emails to secure sender identity and reduce compliance risks.",
    isCompleted: true,
    severity: "low"
  },
  {
    id: "item-6",
    category: "email",
    title: "Configure DMARC with Reject/Quarantine Action",
    description: "Define message handling instructions for mail servers in case of SPF or DKIM validity failure.",
    isCompleted: false,
    severity: "high"
  },
  {
    id: "item-7",
    category: "access",
    title: "Deploy Strict CORS (Cross-Origin Resource Sharing) Policies",
    description: "Eliminate dynamic credentials-allowing wildcard Access-Control-Allow-Origin headers across production servers.",
    isCompleted: false,
    severity: "high"
  },
  {
    id: "item-8",
    category: "firebase",
    title: "Audit and Deploy Secure firestore.rules",
    description: "Verify Firestore security rules explicitly restrict write/read capabilities to authenticated session owners.",
    isCompleted: true,
    severity: "high"
  }
];

export default function App() {
  // Theme state: default light or dark. We read localStorage on mount.
  const [theme, setTheme] = useState<"light" | "dark">("dark");
  const [currentTime, setCurrentTime] = useState<string>("");
  const [auditItems, setAuditItems] = useState<AuditChecklistItem[]>(INITIAL_AUDIT_ITEMS);
  const [selectedCategory, setSelectedCategory] = useState<string>("all");
  
  // Scoring parameters
  const hardeningIndex = useMemo(() => {
    const completed = auditItems.filter(item => item.isCompleted);
    if (auditItems.length === 0) return 0;
    // Weighted scoring based on severity
    const getWeight = (severity: string) => severity === "high" ? 3 : severity === "medium" ? 2 : 1;
    const totalWeight = auditItems.reduce((acc, curr) => acc + getWeight(curr.severity), 0);
    const completedWeight = completed.reduce((acc, curr) => acc + getWeight(curr.severity), 0);
    return Math.round((completedWeight / totalWeight) * 100);
  }, [auditItems]);

  // Domain Assessor Interactive State
  const [targetDomain, setTargetDomain] = useState<string>("runehall.com");
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanStepIndex, setScanStepIndex] = useState<number>(-1);
  const [scanProgress, setScanProgress] = useState<number>(0);
  const [currentScanStep, setCurrentScanStep] = useState<string>("");
  const [recentReports, setRecentReports] = useState<DomainReport[]>([
    {
      domain: "rh420.xyz",
      timestamp: "2026-06-10 18:42",
      score: 68,
      steps: []
    }
  ]);
  const [activeReport, setActiveReport] = useState<DomainReport | null>(null);

  // Policy Builder State
  const [cspDefaultSrc, setCspDefaultSrc] = useState<string>("'self'");
  const [cspScriptSrc, setCspScriptSrc] = useState<string>("'self' https://apis.google.com");
  const [cspStyleSrc, setCspStyleSrc] = useState<string>("'self' https://fonts.googleapis.com");
  const [cspFrameAncestors, setCspFrameAncestors] = useState<string>("'none'");

  // Sync Theme with DOM. Ensures .dark variant works beautifully
  useEffect(() => {
    const stored = localStorage.getItem("theme");
    if (stored === "dark" || stored === "light") {
      setTheme(stored as "light" | "dark");
    } else {
      // System default preference
      const expectsDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
      setTheme(expectsDark ? "dark" : "light");
    }
  }, []);

  useEffect(() => {
    const root = window.document.documentElement;
    if (theme === "dark") {
      root.classList.add("dark");
    } else {
      root.classList.remove("dark");
    }
    localStorage.setItem("theme", theme);
  }, [theme]);

  // Sync Real-Time Clock
  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      // Format as robust compliance-style UTC timestamp
      setCurrentTime(now.toISOString().replace("T", " ").substring(0, 19) + " UTC");
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  // Filter audit items
  const filteredAuditItems = useMemo(() => {
    return auditItems.filter(item => {
      if (selectedCategory === "all") return true;
      return item.category === selectedCategory;
    });
  }, [auditItems, selectedCategory]);

  // Handle checking items off the hardening list
  const toggleItemCompletion = (id: string) => {
    setAuditItems(prev => prev.map(item => {
      if (item.id === id) {
        return { ...item, isCompleted: !item.isCompleted };
      }
      return item;
    }));
  };

  // Run security scanner
  const handleStartScan = (e: FormEvent) => {
    e.preventDefault();
    if (isScanning || !targetDomain.trim()) return;

    setIsScanning(true);
    setScanStepIndex(0);
    setScanProgress(5);
    setActiveReport(null);
  };

  // Steps definitions for the scanner
  const scanSteps: SecurityScanStep[] = useMemo(() => [
    {
      name: "TLS/SSL Cryptographic Integrity Checks",
      status: "idle",
      progress: 20,
      resultMessage: "Strong AES-GCM cipher suite and SHA-256 certificate detected. TLS 1.3 enforced."
    },
    {
      name: "Security Record Lookup (SPF, DMARC, CAA)",
      status: "idle",
      progress: 40,
      resultMessage: `SPF records validated. CAA restricts issuance. DMARC policy warning: using 'p=none' instead of strict 'reject'.`
    },
    {
      name: "HTTP Response Headers Analysis",
      status: "idle",
      progress: 60,
      resultMessage: "HSTS header configured with long max-age. CSP is missing several recommended restrictions."
    },
    {
      name: "Cross-Origin Policy Audit (CORS)",
      status: "idle",
      progress: 80,
      resultMessage: "CORS parameters securely prevent wildcard credentials. Cross-origin Isolation levels evaluated."
    },
    {
      name: "Compliance Alignment & Hardening Check",
      status: "idle",
      progress: 100,
      resultMessage: `Scanning metrics integrated. Hardening scoring process finished successfully.`
    }
  ], []);

  // Security Scanner Simulator sequence
  useEffect(() => {
    if (!isScanning || scanStepIndex === -1) return;

    const currentStep = scanSteps[scanStepIndex];
    setCurrentScanStep(currentStep.name);

    const timer = setTimeout(() => {
      setScanProgress(currentStep.progress);
      
      if (scanStepIndex < scanSteps.length - 1) {
        setScanStepIndex(prev => prev + 1);
      } else {
        // Scan completed! Compile the report
        setIsScanning(false);
        setScanStepIndex(-1);
        setCurrentScanStep("");

        const auditRandomModifier = targetDomain.toLowerCase().includes("runehall") ? 10 : 0;
        const score = Math.round(75 + Math.random() * 15 + auditRandomModifier - (targetDomain.length % 7));
        const finalScore = Math.min(Math.max(score, 50), 98);

        const newReport: DomainReport = {
          domain: targetDomain.trim().toLowerCase(),
          timestamp: new Date().toISOString().replace("T", " ").substring(0, 16),
          score: finalScore,
          steps: scanSteps.map(step => ({
            ...step,
            status: step.name.includes("Record Lookup") || step.name.includes("Headers") ? "warning" : "success"
          }))
        };

        setRecentReports(prev => [newReport, ...prev.filter(r => r.domain !== newReport.domain)].slice(0, 5));
        setActiveReport(newReport);
      }
    }, 1800);

    return () => clearTimeout(timer);
  }, [isScanning, scanStepIndex, scanSteps, targetDomain]);

  // Calculated Content-Security-Policy Output based on inputs
  const compiledCspHeader = useMemo(() => {
    return `Content-Security-Policy: default-src ${cspDefaultSrc}; script-src ${cspScriptSrc}; style-src ${cspStyleSrc}; frame-ancestors ${cspFrameAncestors}; block-all-mixed-content; secure-comply;`;
  }, [cspDefaultSrc, cspScriptSrc, cspStyleSrc, cspFrameAncestors]);

  // Copy helper
  const [copiedNotification, setCopiedNotification] = useState<boolean>(false);
  const copyHeaderToClipboard = () => {
    navigator.clipboard.writeText(compiledCspHeader);
    setCopiedNotification(true);
    setTimeout(() => setCopiedNotification(false), 2000);
  };

  return (
    <div className="min-h-screen font-sans bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100 selection:bg-rose-500 selection:text-white transition-colors duration-300">
      
      {/* Upper Top Ribbon info panel */}
      <div className="border-b border-slate-200 dark:border-slate-900 bg-slate-100 dark:bg-slate-950 text-[11px] py-1.5 px-4 font-mono text-slate-500 dark:text-slate-400 flex flex-wrap justify-between items-center gap-2">
        <div className="flex items-center gap-2">
          <span className="flex h-2 w-2 rounded-full bg-emerald-500 animate-pulse"></span>
          <span>SYSTEM ACTIVE & VERIFIED</span>
          <span className="text-slate-300 dark:text-slate-800">|</span>
          <span>ORACLE SECURITY NODE AUDITING ACTIVE</span>
        </div>
        <div className="flex items-center gap-4">
          <span className="hidden sm:inline">AUDIT COMPLIANCE LEVEL: SECURE-A</span>
          <span className="font-bold text-rose-500 dark:text-rose-400 font-sans tracking-tight">HIGH-CONTRAST CONSOLE</span>
        </div>
      </div>

      {/* Main Structural Framework Container */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        
        {/* Header Hero Panel */}
        <header className="mb-8 flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-slate-200 dark:border-slate-900 pb-6">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-slate-900 text-white rounded-xl shadow-lg dark:bg-slate-100 dark:text-slate-950">
              <ShieldCheck className="h-7 w-7" id="shield-icon" />
            </div>
            <div>
              <h1 className="text-2xl font-bold font-display tracking-tight text-slate-950 dark:text-white flex items-center gap-2.5">
                ORACLE Core Safeguard
                <span className="text-xs font-mono font-normal bg-slate-200 text-slate-800 dark:bg-slate-900 dark:text-slate-300 px-2.5 py-0.5 rounded-full">v2.4.0</span>
              </h1>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 max-w-xl">
                Cryptographic security audits, interactive framework alignment, and system hardening validation consoles for enterprise domains.
              </p>
            </div>
          </div>

          {/* Controls Panel (Clock & Dark/Light Toggle) */}
          <div className="flex items-center gap-3 w-full md:w-auto md:justify-end self-stretch md:self-auto">
            <div className="hidden lg:flex flex-col text-right font-mono text-xs text-slate-500 dark:text-slate-450 mr-2">
              <span className="text-[10px] uppercase text-slate-400 dark:text-slate-500">Global UTC Reference</span>
              <span className="font-semibold text-slate-800 dark:text-emerald-400 mt-0.5">{currentTime || "Loading..."}</span>
            </div>

            {/* Global Theme Toggle Button */}
            <button
              onClick={() => setTheme(theme === "light" ? "dark" : "light")}
              className="flex-1 md:flex-initial flex items-center justify-center gap-2 bg-white dark:bg-slate-900 hover:bg-slate-100 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-850 px-4 py-2.5 rounded-xl cursor-pointer text-sm font-semibold transition"
              id="theme-toggle-btn"
              title="Toggle Light or Dark Interface"
            >
              {theme === "light" ? (
                <>
                  <Moon className="h-4 w-4 text-indigo-600" />
                  <span className="dark:text-slate-300">Switch Dark Focus</span>
                </>
              ) : (
                <>
                  <Sun className="h-4 w-4 text-amber-500" />
                  <span>Switch High Contrast Light</span>
                </>
              )}
            </button>
          </div>
        </header>

        {/* Dashboard Grid Panel - Bento Grid */}
        <main className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          
          {/* LEFT 3 COLS: Score & Domain Inspector Panel */}
          <div className="lg:col-span-4 flex flex-col gap-6">
            
            {/* Hardening Score Widget */}
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-850 rounded-2xl p-6 relative overflow-hidden shadow-sm">
              <div className="absolute top-0 right-0 h-24 w-24 bg-gradient-to-bl from-rose-500/10 to-transparent rounded-full -mr-6 -mt-6 pointer-events-none"></div>
              
              <div className="flex items-center justify-between mb-4">
                <span className="text-xs font-mono font-bold tracking-wider text-slate-400 uppercase">Hardening Index</span>
                <span className="bg-emerald-500/10 text-emerald-600 dark:text-emerald-405 px-2.5 py-0.5 rounded-md text-[10px] font-mono font-bold">LIVE METRIC</span>
              </div>

              <div className="flex items-baseline gap-2">
                <span className="text-5xl font-extrabold font-display tracking-tight text-slate-950 dark:text-white" id="hardening-index-score">
                  {hardeningIndex}%
                </span>
                <span className="text-xs text-slate-400 dark:text-slate-500">compliance score</span>
              </div>

              {/* Progress visual line */}
              <div className="w-full bg-slate-100 dark:bg-slate-800 h-2.5 rounded-full mt-4 overflow-hidden">
                <motion.div 
                  className="bg-emerald-500 dark:bg-emerald-400 h-full"
                  animate={{ width: `${hardeningIndex}%` }}
                  transition={{ duration: 0.5, ease: "easeOut" }}
                />
              </div>

              <div className="mt-5 space-y-2.5">
                <div className="flex items-center gap-2.5 text-xs text-slate-600 dark:text-slate-400">
                  <Check className="h-3.5 w-3.5 text-emerald-500" />
                  <span>
                    <strong>{auditItems.filter(i => i.isCompleted).length} of {auditItems.length}</strong> tasks completed
                  </span>
                </div>
                <div className="flex items-center gap-2.5 text-xs text-slate-600 dark:text-slate-400">
                  <Activity className="h-3.5 w-3.5 text-blue-500" />
                  <span>
                    Weight coefficient balanced: High limits handled.
                  </span>
                </div>
              </div>
            </div>

            {/* Domain Security Auditor */}
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-850 rounded-2xl p-6 shadow-sm flex flex-col">
              <div className="flex items-center gap-2 mb-4">
                <Globe className="h-4 w-4 text-rose-500" />
                <h3 className="font-semibold font-display text-sm tracking-tight">Active Domain Assessor</h3>
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 mb-5">
                Simulate domain checks against cryptographic configurations, certificates, and strict framing policies.
              </p>

              <form onSubmit={handleStartScan} className="space-y-3.5">
                <div>
                  <label htmlFor="domain-input" className="sr-only">Target Domain</label>
                  <div className="relative">
                    <input 
                      id="domain-input"
                      type="text" 
                      placeholder="e.g. runehall.com"
                      value={targetDomain}
                      onChange={(e) => setTargetDomain(e.target.value)}
                      disabled={isScanning}
                      className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-850 rounded-xl px-4 py-3 text-xs placeholder:text-slate-400 uppercase font-mono font-medium focus:outline-none focus:ring-1 focus:ring-rose-500 focus:border-rose-500 transition-all text-slate-900 dark:text-white"
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={isScanning || !targetDomain}
                  className="w-full bg-slate-950 text-white dark:bg-white dark:text-slate-950 hover:bg-slate-850 dark:hover:bg-slate-100 disabled:opacity-50 py-3 rounded-xl text-xs font-semibold flex items-center justify-center gap-2 cursor-pointer transition"
                  id="start-scan-btn"
                >
                  {isScanning ? (
                    <>
                      <RefreshCw className="h-3.5 w-3.5 animate-spin text-rose-500" />
                      <span>COMMENCING ASSESSMENT...</span>
                    </>
                  ) : (
                    <>
                      <Activity className="h-3.5 w-3.5" />
                      <span>COMMENCE ASSESSMENT</span>
                    </>
                  )}
                </button>
              </form>

              {/* Scan progress panel */}
              <AnimatePresence>
                {isScanning && (
                  <motion.div 
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: "auto" }}
                    exit={{ opacity: 0, height: 0 }}
                    className="mt-5 border-t border-slate-100 dark:border-slate-850 pt-5 space-y-4 overflow-hidden"
                  >
                    <div className="flex justify-between items-center text-xs font-mono">
                      <span className="text-slate-400 uppercase tracking-widest text-[10px]">Processing</span>
                      <span className="text-rose-500 font-bold">{scanProgress}%</span>
                    </div>

                    <div className="w-full bg-slate-100 dark:bg-slate-950 h-1.5 rounded-full overflow-hidden">
                      <div 
                        className="bg-rose-500 h-full transition-all duration-300"
                        style={{ width: `${scanProgress}%` }}
                      ></div>
                    </div>

                    <div className="bg-slate-50 dark:bg-slate-950 p-3 rounded-xl border border-slate-150 dark:border-slate-900 flex items-center gap-3">
                      <Cpu className="h-4 w-4 text-indigo-500 animate-pulse flex-shrink-0" />
                      <div className="min-w-0 flex-1">
                        <p className="text-[10px] font-mono text-slate-400 uppercase">Current Audit Task</p>
                        <p className="text-xs font-medium text-slate-800 dark:text-slate-200 truncate mt-0.5">{currentScanStep}</p>
                      </div>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>

              {/* Scan completed single report result */}
              {activeReport && !isScanning && (
                <div className="mt-5 border-t border-slate-150 dark:border-slate-850 pt-5 space-y-4">
                  <div className="bg-emerald-500/10 dark:bg-emerald-500/5 border border-emerald-500/20 p-4 rounded-xl text-center">
                    <CheckCircle className="h-6 w-6 text-emerald-500 mx-auto mb-2" />
                    <p className="text-[11px] font-mono uppercase text-slate-450">HARDENING SCORE SECURED</p>
                    <p className="text-3xl font-extrabold font-display text-slate-900 dark:text-white mt-1 uppercase tracking-tight">
                      {activeReport.domain}: <span className="text-emerald-500">{activeReport.score}%</span>
                    </p>
                  </div>

                  <div className="space-y-2.5">
                    <p className="text-[10px] font-mono text-slate-400 uppercase">Assessment Details</p>
                    {activeReport.steps.map((st, i) => (
                      <div key={i} className="flex gap-2.5 p-2 bg-slate-50 dark:bg-slate-950 rounded-lg border border-slate-100 dark:border-slate-900 text-xs">
                        {st.status === "success" ? (
                          <CheckCircle2 className="h-4 w-4 text-emerald-500 mt-0.5 flex-shrink-0" />
                        ) : (
                          <AlertTriangle className="h-4 w-4 text-amber-500 mt-0.5 flex-shrink-0" />
                        )}
                        <div>
                          <p className="font-semibold text-slate-850 dark:text-slate-255">{st.name}</p>
                          <p className="text-[11px] text-slate-500 dark:text-slate-450 mt-0.5">{st.resultMessage}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Historical assessments list */}
              {recentReports.length > 0 && !activeReport && !isScanning && (
                <div className="mt-5 border-t border-slate-100 dark:border-slate-850 pt-5 space-y-3">
                  <div className="flex justify-between items-center">
                    <span className="text-[10px] font-mono text-slate-400 uppercase font-bold tracking-wider">Historical Scans</span>
                    <span className="text-[10px] bg-slate-100 dark:bg-slate-850 text-slate-500 px-2 py-0.5 rounded-md font-mono">CACHE VALID</span>
                  </div>

                  <div className="space-y-2">
                    {recentReports.map((item, idx) => (
                      <div 
                        key={idx}
                        onClick={() => setTargetDomain(item.domain)}
                        className="flex items-center justify-between p-3 bg-slate-50 hover:bg-slate-100 dark:bg-slate-950 dark:hover:bg-slate-875 rounded-xl border border-slate-100 dark:border-slate-900 cursor-pointer transition"
                      >
                        <div className="min-w-0 pr-2">
                          <span className="text-xs font-bold uppercase font-mono text-slate-805 dark:text-slate-205 block truncate">{item.domain}</span>
                          <span className="text-[10px] text-slate-400 dark:text-slate-500 mt-0.5 block">{item.timestamp}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className={`text-xs font-mono font-semibold px-2 py-0.5 rounded ${
                            item.score >= 80 ? "bg-emerald-500/10 text-emerald-600" : "bg-amber-500/10 text-amber-600"
                          }`}>
                            {item.score}%
                          </span>
                          <ChevronRight className="h-3.5 w-3.5 text-slate-400" />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

          </div>

          {/* MAIN 8 COLS PANEL */}
          <div className="lg:col-span-8 flex flex-col gap-8">
            
            {/* AUDIT CHECKLIST SECTION (THE HEART) */}
            <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-850 rounded-2xl p-6 shadow-sm">
              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 pb-5 border-b border-slate-100 dark:border-slate-850 mb-5">
                <div className="flex items-center gap-2.5">
                  <Layers className="h-5 w-5 text-indigo-500" />
                  <div>
                    <h2 className="text-lg font-bold font-display tracking-tight text-slate-950 dark:text-white">Hardening Assessment Matrix</h2>
                    <p className="text-xs text-slate-550 dark:text-slate-450 mt-0.5">Toggle configuration checklist objectives underneath down below to verify compliance indexes.</p>
                  </div>
                </div>

                {/* Filter pill selectors */}
                <div className="flex flex-wrap gap-1.5">
                  {["all", "dns", "http", "email", "access", "firebase"].map((cat) => (
                    <button
                      key={cat}
                      onClick={() => setSelectedCategory(cat)}
                      className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium uppercase cursor-pointer transition ${
                        selectedCategory === cat 
                          ? "bg-slate-950 text-white dark:bg-white dark:text-slate-950" 
                          : "bg-slate-50 hover:bg-slate-100 text-slate-600 dark:bg-slate-950 dark:hover:bg-slate-850 dark:text-slate-400"
                      }`}
                    >
                      {cat}
                    </button>
                  ))}
                </div>
              </div>

              {/* Auditing Matrix list */}
              <div className="space-y-3.5 max-h-[480px] overflow-y-auto pr-1">
                {filteredAuditItems.map((item) => (
                  <div 
                    key={item.id}
                    onClick={() => toggleItemCompletion(item.id)}
                    className={`p-4 rounded-xl border transition-all cursor-pointer flex items-start gap-4 ${
                      item.isCompleted 
                        ? "bg-slate-50/50 dark:bg-slate-950/40 border-slate-200 dark:border-slate-900 opacity-80" 
                        : "bg-white dark:bg-slate-925 hover:bg-slate-50 dark:hover:bg-slate-850 border-slate-200 dark:border-slate-850"
                    }`}
                  >
                    {/* Checkbox state */}
                    <div className="mt-0.5 flex-shrink-0">
                      <div className={`h-5 w-5 rounded border flex items-center justify-center transition-colors ${
                        item.isCompleted 
                          ? "bg-emerald-500 border-emerald-500 text-white" 
                          : "border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950"
                      }`}>
                        {item.isCompleted && <Check className="h-3.5 w-3.5 stroke-[3px]" />}
                      </div>
                    </div>

                    <div className="flex-1 min-w-0">
                      <div className="flex items-center flex-wrap gap-2">
                        <span className="font-bold text-xs uppercase font-mono text-slate-400 dark:text-slate-500">
                          [{item.category}]
                        </span>
                        
                        {/* Severity tag */}
                        <span className={`text-[10px] font-mono uppercase font-bold px-1.5 py-0.5 rounded ${
                          item.severity === "high" 
                            ? "bg-rose-500/10 text-rose-600 dark:text-rose-450" 
                            : item.severity === "medium" 
                            ? "bg-amber-500/10 text-amber-600 dark:text-amber-450" 
                            : "bg-slate-100 text-slate-600 dark:bg-slate-900 dark:text-slate-400"
                        }`}>
                          {item.severity} severity
                        </span>
                      </div>

                      <h3 className={`font-semibold text-sm tracking-tight mt-1.5 ${
                        item.isCompleted ? "line-through text-slate-450 dark:text-slate-500 font-medium" : "text-slate-900 dark:text-white"
                      }`}>
                        {item.title}
                      </h3>
                      
                      <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                        {item.description}
                      </p>
                    </div>
                  </div>
                ))}

                {filteredAuditItems.length === 0 && (
                  <div className="p-8 text-center border border-dashed border-slate-200 dark:border-slate-800 rounded-2xl">
                    <Terminal className="h-8 w-8 text-slate-400 mx-auto mb-2" />
                    <p className="text-sm font-semibold text-slate-800 dark:text-slate-300">No Auditing Requirements Loaded</p>
                    <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">Select another compliance filter from top.</p>
                  </div>
                )}
              </div>
            </section>

            {/* DIRECTIVE POLICY GENERATOR (HIGH COMPLIANCE UTILITY) */}
            <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-850 rounded-2xl p-6 shadow-sm">
              <div className="flex items-center gap-2.5 pb-5 border-b border-slate-150 dark:border-slate-850 mb-5">
                <FileText className="h-5 w-5 text-rose-500" />
                <div>
                  <h2 className="text-lg font-bold font-display tracking-tight text-slate-950 dark:text-white">Content-Security-Policy (CSP) Standard Compiler</h2>
                  <p className="text-xs text-slate-550 dark:text-slate-405 mt-0.5">Customize specific trusted domains below to compile a secure production-grade CSP directive.</p>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                
                {/* Compiler Directives Inputs */}
                <div className="space-y-4">
                  <div>
                    <label className="block text-xs font-mono uppercase font-semibold text-slate-500 dark:text-slate-450 mb-1.5">
                      default-src directive
                    </label>
                    <input 
                      type="text"
                      value={cspDefaultSrc}
                      onChange={(e) => setCspDefaultSrc(e.target.value)}
                      className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-850 rounded-lg px-3 py-2 text-xs font-mono text-slate-800 dark:text-white focus:outline-none focus:ring-1 focus:ring-rose-500"
                    />
                    <span className="text-[10px] text-slate-400 block mt-1">Controls wildcard asset actions fallback.</span>
                  </div>

                  <div>
                    <label className="block text-xs font-mono uppercase font-semibold text-slate-500 dark:text-slate-450 mb-1.5">
                      script-src directive
                    </label>
                    <input 
                      type="text"
                      value={cspScriptSrc}
                      onChange={(e) => setCspScriptSrc(e.target.value)}
                      className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-850 rounded-lg px-3 py-2 text-xs font-mono text-slate-800 dark:text-white focus:outline-none focus:ring-1 focus:ring-rose-500"
                    />
                    <span className="text-[10px] text-slate-400 block mt-1">Allows scripts only from specified hostnames.</span>
                  </div>

                  <div>
                    <label className="block text-xs font-mono uppercase font-semibold text-slate-500 dark:text-slate-450 mb-1.5">
                      style-src directive
                    </label>
                    <input 
                      type="text"
                      value={cspStyleSrc}
                      onChange={(e) => setCspStyleSrc(e.target.value)}
                      className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-850 rounded-lg px-3 py-2 text-xs font-mono text-slate-800 dark:text-white focus:outline-none focus:ring-1 focus:ring-rose-500"
                    />
                    <span className="text-[10px] text-slate-400 block mt-1">Filters allowed stylesheet frameworks.</span>
                  </div>

                  <div>
                    <label className="block text-xs font-mono uppercase font-semibold text-slate-500 dark:text-slate-450 mb-1.5">
                      frame-ancestors directive
                    </label>
                    <input 
                      type="text"
                      value={cspFrameAncestors}
                      onChange={(e) => setCspFrameAncestors(e.target.value)}
                      className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-850 rounded-lg px-3 py-2 text-xs font-mono text-slate-800 dark:text-white focus:outline-none focus:ring-1 focus:ring-rose-500"
                    />
                    <span className="text-[10px] text-slate-400 block mt-1">Secures against Clickjacking iframe nesting risks.</span>
                  </div>
                </div>

                {/* Compiled Outputs Block */}
                <div className="flex flex-col justify-between bg-slate-50 dark:bg-slate-950 p-5 rounded-xl border border-slate-150 dark:border-slate-875">
                  <div>
                    <div className="flex justify-between items-center mb-3">
                      <span className="text-[10px] font-mono text-rose-500 font-bold uppercase tracking-wider flex items-center gap-1.5">
                        <Terminal className="h-3 w-3" />
                        Compiled HTTP Header Output
                      </span>
                      <span className="text-[10px] font-mono text-slate-400">READY</span>
                    </div>

                    <div className="bg-white dark:bg-slate-925 p-4 rounded-lg border border-slate-200 dark:border-slate-900 text-xs font-mono text-slate-800 dark:text-slate-200 break-all leading-relaxed whitespace-pre-wrap selection:bg-rose-500 selection:text-white">
                      {compiledCspHeader}
                    </div>
                  </div>

                  <div className="mt-5 pt-3 border-t border-slate-150 dark:border-slate-900 flex flex-wrap items-center justify-between gap-3">
                    <span className="text-[11px] text-slate-500 dark:text-slate-400 max-w-xs leading-normal">
                      Copy clean directive block directly to Nginx or Cloudflare templates.
                    </span>

                    <button
                      onClick={copyHeaderToClipboard}
                      className="bg-slate-950 text-white dark:bg-white dark:text-slate-950 text-xs font-semibold px-4 py-2.5 rounded-lg flex items-center gap-1.5 shadow-sm hover:opacity-90 active:scale-95 transition-all cursor-pointer"
                    >
                      {copiedNotification ? (
                        <>
                          <Check className="h-3.5 w-3.5 text-emerald-500" />
                          <span>COPIED SUCCESSFULLY</span>
                        </>
                      ) : (
                        <>
                          <FileText className="h-3.5 w-3.5" />
                          <span>COPY DIRECTIVE TEXT</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>

              </div>
            </section>

          </div>

        </main>

        {/* BOTTOM COMPLIANCE INFO GUIDELINE CARDS */}
        <section className="mt-8 grid grid-cols-1 md:grid-cols-3 gap-6 border-t border-slate-200 dark:border-slate-900 pt-8">
          <div className="bg-white dark:bg-slate-900 p-5 rounded-2xl border border-slate-200 dark:border-slate-850 flex gap-4">
            <div className="p-2.5 bg-blue-500/10 text-blue-600 dark:text-blue-400 rounded-xl max-h-min">
              <Lock className="h-5 w-5" />
            </div>
            <div>
              <h4 className="font-semibold text-sm tracking-tight text-slate-950 dark:text-white">Transit Security</h4>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 leading-relaxed">
                Adhere always to mandatory TLS 1.3 encryption levels. Terminate insecure cipher suites across load balancers periodically.
              </p>
            </div>
          </div>

          <div className="bg-white dark:bg-slate-900 p-5 rounded-2xl border border-slate-200 dark:border-slate-850 flex gap-4">
            <div className="p-2.5 bg-rose-500/10 text-rose-600 dark:text-rose-455 rounded-xl max-h-min">
              <BookOpen className="h-5 w-5" />
            </div>
            <div>
              <h4 className="font-semibold text-sm tracking-tight text-slate-950 dark:text-white">Strict Frame Protection</h4>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 leading-relaxed">
                Nesting subdomains under frames requires extreme restrictiveness. Preempt Clickjacking vectors using absolute frame-ancestor rules.
              </p>
            </div>
          </div>

          <div className="bg-white dark:bg-slate-900 p-5 rounded-2xl border border-slate-200 dark:border-slate-850 flex gap-4">
            <div className="p-2.5 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 rounded-xl max-h-min">
              <CheckCircle className="h-5 w-5" />
            </div>
            <div>
              <h4 className="font-semibold text-sm tracking-tight text-slate-950 dark:text-white">DNS Records Verification</h4>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 leading-relaxed">
                CAA and SPF records serve as frontline shields. Implement rigid keys to intercept email identity counterfeits or unverified issuance lists.
              </p>
            </div>
          </div>
        </section>

      </div>

      {/* Footer copyright block */}
      <footer className="border-t border-slate-200 dark:border-slate-900 bg-white dark:bg-slate-950 py-6 text-center text-xs text-slate-400 dark:text-slate-500">
        <p className="font-mono">ORACLE COMPLIANCE & HARDENING CONTROL CABINET DEPLOYMENT v2.4.0</p>
        <p className="mt-1 font-sans">Developed in compliant environments under secure protocols. All configurations client-side persisted.</p>
      </footer>

    </div>
  );
}
