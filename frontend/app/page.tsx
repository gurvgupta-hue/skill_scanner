"use client";
import { useState } from "react";

// ── Types ─────────────────────────────────────────────────────────────────────

type DetectionDetail = {
  category: string;
  count: number;
  decoded: string | null;
  harm_categories: string[];
  positions: number[];
};

type ScanResponse = {
  status: string;
  threat_detected: boolean;
  density_score: number;
  detections: DetectionDetail[];
  sanitized_text: string | null;
  scan_time_ms: number;
  timed_out: boolean;
};

type ScanMode = "strict" | "sanitize" | "report";

type ThreatFinding = {
  category: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  description: string;
  evidence: string | null;
  position: number | null;
  source: "rule" | "llm";
};

type ThreatAnalysisResponse = {
  status: string;
  threat_detected: boolean;
  density_score: number;
  detections: DetectionDetail[];
  sanitized_text: string | null;
  scan_time_ms: number;
  timed_out: boolean;
  rule_findings: ThreatFinding[];
  llm_findings: ThreatFinding[];
  execution_summary: string;
  overall_risk: string;
  llm_available: boolean;
  analysis_time_ms: number;
};

// ── Constants ─────────────────────────────────────────────────────────────────

const CATEGORY_LABELS: Record<string, string> = {
  tag_block_smuggling: "Tag Block Smuggling",
  zero_width_chars: "Zero-Width Characters",
  sneaky_bits: "Invisible Math Operators",
  variation_selectors: "Variation Selectors",
  bidi_override: "Bidi Override Attack",
  emoji_smuggling: "Emoji Smuggling",
  scanner_timeout: "Scanner Timeout",
  unicode_confusable: "Unicode Confusable Characters",
  mixed_script: "Mixed Script Attack",
  invisible_separator: "Invisible Separator",
  unicode_normalization_evasion: "Normalization Evasion",
  directional_isolate: "Directional Isolate Abuse",
  combining_char_abuse: "Combining Character Flooding",
  encoded_command: "Encoded Command (Base64)",
  suspicious_shell_pattern: "Suspicious Shell Pattern",
  ascii_ctrl_smuggling: "ASCII Control Char Smuggling",
};

const HARM_COLORS: Record<string, string> = {
  credential_theft: "#dc2626",
  tool_execution: "#d97706",
  data_exfiltration: "#7c3aed",
  prompt_injection: "#2563eb",
  jailbreak: "#db2777",
  unknown_malicious: "#6b7280",
  scanner_error: "#374151",
};

const SEVERITY_COLORS: Record<string, { bg: string; text: string }> = {
  CRITICAL: { bg: "#7f1d1d", text: "#fff" },
  HIGH: { bg: "#dc2626", text: "#fff" },
  MEDIUM: { bg: "#d97706", text: "#fff" },
  LOW: { bg: "#16a34a", text: "#fff" },
};

const RISK_BANNER: Record<string, { bg: string; border: string; text: string }> = {
  CRITICAL: { bg: "#fef2f2", border: "#ef4444", text: "#7f1d1d" },
  HIGH: { bg: "#fff7ed", border: "#f97316", text: "#9a3412" },
  MEDIUM: { bg: "#fffbeb", border: "#f59e0b", text: "#92400e" },
  LOW: { bg: "#f0fdf4", border: "#22c55e", text: "#15803d" },
  NONE: { bg: "#f0fdf4", border: "#22c55e", text: "#15803d" },
};

const MODE_DESCRIPTIONS: Record<ScanMode, string> = {
  strict: "Block on any threat",
  sanitize: "Strip invisible chars and return clean text",
  report: "Scan and report only — never block",
};

// ── Component ─────────────────────────────────────────────────────────────────

export default function Home() {
  const [text, setText] = useState("");
  const [mode, setMode] = useState<ScanMode>("strict");
  const [result, setResult] = useState<ScanResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [analyzeResult, setAnalyzeResult] = useState<ThreatAnalysisResponse | null>(null);

  const handleDownload = (content: string) => {
    const blob = new Blob([content], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "clean_output.md";
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleScan = async () => {
    setLoading(true);
    setError(null);
    setResult(null);
    setAnalyzeResult(null);
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
      const res = await fetch(`${apiUrl}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text, mode }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: `HTTP ${res.status}` }));
        setError(err.detail ?? `Error ${res.status}`);
        return;
      }
      setResult(await res.json());
    } catch {
      setError("Could not connect to the scanner backend.");
    } finally {
      setLoading(false);
    }
  };

  const handleAnalyze = async () => {
    setAnalyzing(true);
    setError(null);
    setResult(null);
    setAnalyzeResult(null);
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
      const res = await fetch(`${apiUrl}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text, mode }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: `HTTP ${res.status}` }));
        setError(err.detail ?? `Error ${res.status}`);
        return;
      }
      const data: ThreatAnalysisResponse = await res.json();
      setResult(data);
      setAnalyzeResult(data);
    } catch {
      setError("Could not connect to the scanner backend.");
    } finally {
      setAnalyzing(false);
    }
  };

  const isClean = result && !result.threat_detected;

  return (
    <>
      <style>{`
        * { box-sizing: border-box; }
        body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
        .scan-btn:hover:not(:disabled) { background-color: #005ce6 !important; transform: translateY(-1px); box-shadow: 0 6px 16px rgba(0,112,243,0.35) !important; }
        .analyze-btn:hover:not(:disabled) { background-color: #6d28d9 !important; transform: translateY(-1px); box-shadow: 0 6px 16px rgba(124,58,237,0.35) !important; }
        .scan-btn, .analyze-btn, .dl-btn { transition: background-color 0.15s ease, transform 0.12s ease, box-shadow 0.15s ease; }
        .dl-btn:hover { background-color: #047857 !important; transform: translateY(-1px); }
        .result-card { transition: box-shadow 0.15s ease; }
        .result-card:hover { box-shadow: 0 4px 16px rgba(0,0,0,0.09) !important; }
        .mode-label:hover { border-color: #a5b4fc !important; }
        .scan-textarea { transition: border-color 0.15s ease, box-shadow 0.15s ease; }
        .scan-textarea:focus { border-color: #6366f1 !important; box-shadow: 0 0 0 3px rgba(99,102,241,0.15) !important; outline: none; }
      `}</style>

      <main style={{
        minHeight: "100vh",
        background: "linear-gradient(145deg, #eef2ff 0%, #f8fafc 55%, #ecfdf5 100%)",
        padding: "40px 16px",
        display: "flex", justifyContent: "center", alignItems: "flex-start",
      }}>
        <div style={{ width: "100%", maxWidth: "860px" }}>

          {/* ── Card ── */}
          <div style={{
            backgroundColor: "#fff",
            borderRadius: "20px",
            boxShadow: "0 1px 4px rgba(0,0,0,0.04), 0 16px 48px rgba(0,0,0,0.10)",
            overflow: "hidden",
          }}>

            {/* Header band */}
            <div style={{
              background: "linear-gradient(130deg, #1e1b4b 0%, #3730a3 60%, #4f46e5 100%)",
              padding: "26px 32px 24px",
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: "11px", marginBottom: "6px" }}>
                <span style={{ fontSize: "26px", lineHeight: 1 }}>🛡️</span>
                <h1 style={{ margin: 0, fontSize: "22px", fontWeight: 700, color: "#fff", letterSpacing: "-0.3px" }}>
                  Skill Scanner
                </h1>
                <span style={{
                  padding: "2px 10px", borderRadius: "999px",
                  backgroundColor: "rgba(255,255,255,0.15)", backdropFilter: "blur(4px)",
                  fontSize: "10px", fontWeight: 700, color: "rgba(255,255,255,0.9)", letterSpacing: "1px",
                }}>
                  AI SECURITY
                </span>
              </div>
              <p style={{ margin: 0, color: "rgba(199,210,254,0.85)", fontSize: "13px", lineHeight: "1.5" }}>
                Detect steganographic Unicode payloads and analyze malicious AI agent instructions
              </p>
            </div>

            {/* Body */}
            <div style={{ padding: "28px 32px" }}>

              {/* Textarea */}
              <div style={{ marginBottom: "18px" }}>
                <label style={{
                  display: "block", fontSize: "11px", fontWeight: 700, letterSpacing: "0.7px",
                  textTransform: "uppercase", color: "#64748b", marginBottom: "7px",
                }}>
                  Content to Analyze
                </label>
                <textarea
                  className="scan-textarea"
                  value={text}
                  onChange={(e) => setText(e.target.value)}
                  placeholder="Paste agent instructions, system prompts, or Markdown skill content…"
                  style={{
                    width: "100%", height: "200px", padding: "12px 14px",
                    border: "1.5px solid #e2e8f0", borderRadius: "10px",
                    fontSize: "14px", lineHeight: "1.6", color: "#1e293b",
                    backgroundColor: "#fcfcfd", resize: "vertical",
                  }}
                />
              </div>

              {/* Mode selector */}
              <div style={{ marginBottom: "20px" }}>
                <span style={{
                  display: "block", fontSize: "11px", fontWeight: 700, letterSpacing: "0.7px",
                  textTransform: "uppercase", color: "#64748b", marginBottom: "8px",
                }}>
                  Scan Mode
                </span>
                <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
                  {(["strict", "sanitize", "report"] as ScanMode[]).map((m) => (
                    <label key={m} className="mode-label" style={{
                      display: "flex", alignItems: "flex-start", gap: "9px", cursor: "pointer",
                      padding: "10px 14px", borderRadius: "10px",
                      border: `1.5px solid ${mode === m ? "#6366f1" : "#e2e8f0"}`,
                      backgroundColor: mode === m ? "#eef2ff" : "#f8fafc",
                      transition: "border-color 0.15s, background-color 0.15s",
                    }}>
                      <input
                        type="radio" name="mode" value={m} checked={mode === m}
                        onChange={() => setMode(m)}
                        style={{ accentColor: "#6366f1", marginTop: "2px" }}
                      />
                      <div>
                        <div style={{
                          fontWeight: 600, fontSize: "13px",
                          color: mode === m ? "#4338ca" : "#374151",
                          textTransform: "capitalize",
                        }}>{m}</div>
                        <div style={{ fontSize: "11px", color: "#94a3b8", marginTop: "1px" }}>
                          {MODE_DESCRIPTIONS[m]}
                        </div>
                      </div>
                    </label>
                  ))}
                </div>
              </div>

              {/* Buttons */}
              <div style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
                <button
                  className="scan-btn"
                  onClick={handleScan}
                  disabled={loading || analyzing || !text.trim()}
                  style={{
                    padding: "11px 26px", fontSize: "14px", fontWeight: 600,
                    border: "none", borderRadius: "10px", cursor: loading || analyzing || !text.trim() ? "not-allowed" : "pointer",
                    backgroundColor: loading || analyzing || !text.trim() ? "#bfdbfe" : "#0070f3",
                    color: "#fff",
                    boxShadow: loading || analyzing || !text.trim() ? "none" : "0 2px 8px rgba(0,112,243,0.28)",
                  }}
                >
                  {loading ? "Scanning…" : "Scan Payload"}
                </button>
                <button
                  className="analyze-btn"
                  onClick={handleAnalyze}
                  disabled={loading || analyzing || !text.trim()}
                  style={{
                    padding: "11px 26px", fontSize: "14px", fontWeight: 600,
                    border: "none", borderRadius: "10px", cursor: loading || analyzing || !text.trim() ? "not-allowed" : "pointer",
                    backgroundColor: loading || analyzing || !text.trim() ? "#ede9fe" : "#7c3aed",
                    color: loading || analyzing || !text.trim() ? "#a78bfa" : "#fff",
                    boxShadow: loading || analyzing || !text.trim() ? "none" : "0 2px 8px rgba(124,58,237,0.28)",
                  }}
                >
                  {analyzing ? "Analyzing…" : "Analyze Threats"}
                </button>
              </div>

              {/* Error */}
              {error && (
                <div style={{
                  marginTop: "16px", padding: "12px 16px", borderRadius: "10px",
                  backgroundColor: "#fef2f2", border: "1.5px solid #fecaca",
                  color: "#b91c1c", fontSize: "14px", display: "flex", alignItems: "center", gap: "8px",
                }}>
                  <span>⚠️</span> {error}
                </div>
              )}

              {/* ── Scan Results ── */}
              {result && (
                <div style={{ marginTop: "32px" }}>
                  <div style={{
                    display: "flex", alignItems: "center", gap: "8px",
                    borderTop: "1.5px solid #f1f5f9", paddingTop: "24px", marginBottom: "18px",
                  }}>
                    <span style={{ fontSize: "16px" }}>🔬</span>
                    <h2 style={{ margin: 0, fontSize: "15px", fontWeight: 700, color: "#0f172a", letterSpacing: "-0.1px" }}>
                      Scan Results
                    </h2>
                    <span style={{ fontSize: "12px", color: "#94a3b8", marginLeft: "2px" }}>
                      {result.scan_time_ms} ms
                    </span>
                  </div>

                  {/* Status banner */}
                  <div style={{
                    padding: "14px 18px", borderRadius: "12px", marginBottom: "18px",
                    backgroundColor: isClean ? "#f0fdf4" : "#fef2f2",
                    border: `1.5px solid ${isClean ? "#86efac" : "#fca5a5"}`,
                    display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "8px",
                  }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "9px" }}>
                      <span style={{ fontSize: "18px" }}>{isClean ? "✅" : "🚨"}</span>
                      <span style={{ fontWeight: 700, fontSize: "15px", color: isClean ? "#15803d" : "#b91c1c" }}>
                        {isClean ? "No Threats Detected" : "Threat Detected"}
                      </span>
                    </div>
                    <div style={{ fontSize: "12px", color: "#64748b", display: "flex", gap: "14px", flexWrap: "wrap" }}>
                      <span>Status: <strong style={{ color: "#334155" }}>{result.status.toUpperCase()}</strong></span>
                      <span>Density: <strong style={{ color: "#334155" }}>{(result.density_score * 100).toFixed(2)}%</strong></span>
                      {result.timed_out && <span style={{ color: "#dc2626", fontWeight: 600 }}>⚠️ Timed out</span>}
                    </div>
                  </div>

                  {/* Density-only notice */}
                  {result.threat_detected && result.detections.length === 0 && (
                    <div style={{
                      padding: "14px 16px", border: "1.5px solid #fde68a", borderRadius: "12px",
                      backgroundColor: "#fffbeb", marginBottom: "18px",
                    }}>
                      <div style={{ fontWeight: 600, color: "#92400e", marginBottom: "4px" }}>⚠️ High Invisible Character Density</div>
                      <p style={{ margin: 0, fontSize: "13px", color: "#78350f", lineHeight: "1.5" }}>
                        {(result.density_score * 100).toFixed(2)}% invisible Unicode characters detected above the threshold,
                        but no specific pattern matched. Sanitized output has these removed.
                      </p>
                    </div>
                  )}

                  {/* Detection cards */}
                  {result.detections.length > 0 && (
                    <section style={{ marginBottom: "20px" }}>
                      <h3 style={{
                        margin: "0 0 10px", fontSize: "11px", fontWeight: 700,
                        textTransform: "uppercase", letterSpacing: "0.7px", color: "#64748b",
                      }}>
                        Detections · {result.detections.length}
                      </h3>
                      {result.detections.map((d, i) => (
                        <div key={i} className="result-card" style={{
                          padding: "14px 16px", border: "1.5px solid #e2e8f0", borderRadius: "12px",
                          marginBottom: "10px", backgroundColor: "#fff",
                          boxShadow: "0 1px 4px rgba(0,0,0,0.04)",
                        }}>
                          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "10px", flexWrap: "wrap", gap: "6px", alignItems: "center" }}>
                            <strong style={{ color: "#0f172a", fontSize: "14px" }}>
                              {CATEGORY_LABELS[d.category] ?? d.category}
                            </strong>
                            <span style={{
                              fontSize: "11px", color: "#64748b",
                              backgroundColor: "#f1f5f9", padding: "2px 10px", borderRadius: "999px",
                            }}>
                              {d.count} char{d.count !== 1 ? "s" : ""} · pos: {d.positions.slice(0, 5).join(", ")}{d.positions.length > 5 ? "…" : ""}
                            </span>
                          </div>
                          <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
                            {d.harm_categories.map((hc) => (
                              <span key={hc} style={{
                                padding: "3px 10px", borderRadius: "999px", fontSize: "11px",
                                backgroundColor: HARM_COLORS[hc] ?? "#6b7280", color: "#fff", fontWeight: 600,
                              }}>
                                {hc.replace(/_/g, " ")}
                              </span>
                            ))}
                          </div>
                          {d.decoded && (
                            <div style={{ marginTop: "12px" }}>
                              <span style={{ fontSize: "10px", fontWeight: 700, letterSpacing: "0.7px", textTransform: "uppercase", color: "#64748b" }}>
                                Decoded payload
                              </span>
                              <pre style={{
                                backgroundColor: "#0f172a", color: "#e2e8f0",
                                padding: "10px 14px", borderRadius: "8px", marginTop: "6px",
                                fontSize: "12px", overflowX: "auto", whiteSpace: "pre-wrap", wordBreak: "break-all", lineHeight: "1.5",
                              }}>
                                {d.decoded}
                              </pre>
                            </div>
                          )}
                        </div>
                      ))}
                    </section>
                  )}

                  {/* Sanitized output */}
                  {result.sanitized_text !== null && (
                    <section style={{ border: "1.5px solid #e2e8f0", borderRadius: "12px", overflow: "hidden" }}>
                      <div style={{
                        display: "flex", justifyContent: "space-between", alignItems: "center",
                        padding: "11px 16px", backgroundColor: "#f8fafc", borderBottom: "1px solid #e2e8f0",
                      }}>
                        <span style={{ fontSize: "11px", fontWeight: 700, letterSpacing: "0.7px", textTransform: "uppercase", color: "#64748b" }}>
                          Sanitized Output
                        </span>
                        <button
                          className="dl-btn"
                          onClick={() => handleDownload(result.sanitized_text!)}
                          style={{
                            padding: "5px 14px", backgroundColor: "#059669", color: "#fff",
                            border: "none", borderRadius: "8px", cursor: "pointer", fontSize: "12px", fontWeight: 600,
                          }}
                        >
                          ⬇ Download .md
                        </button>
                      </div>
                      <pre style={{
                        backgroundColor: "#f8fafc", padding: "14px 16px", margin: 0,
                        fontSize: "13px", overflowX: "auto", whiteSpace: "pre-wrap",
                        wordBreak: "break-word", maxHeight: "280px", lineHeight: "1.6", color: "#334155",
                      }}>
                        {result.sanitized_text || "(empty after sanitization)"}
                      </pre>
                    </section>
                  )}
                </div>
              )}

              {/* ── Threat Analysis Results ── */}
              {analyzeResult && (
                <div style={{ marginTop: "32px" }}>
                  <div style={{
                    display: "flex", alignItems: "baseline", gap: "8px",
                    borderTop: "1.5px solid #f1f5f9", paddingTop: "24px", marginBottom: "18px",
                  }}>
                    <span style={{ fontSize: "16px" }}>🤖</span>
                    <h2 style={{ margin: 0, fontSize: "15px", fontWeight: 700, color: "#0f172a" }}>
                      Threat Analysis
                    </h2>
                    <span style={{ fontSize: "12px", color: "#94a3b8" }}>
                      {analyzeResult.analysis_time_ms} ms
                      {!analyzeResult.llm_available && " · Gemini not configured — rule-based only"}
                    </span>
                  </div>

                  {/* Risk Banner */}
                  {(() => {
                    const r = RISK_BANNER[analyzeResult.overall_risk] ?? RISK_BANNER["NONE"];
                    return (
                      <div style={{
                        padding: "14px 18px", borderRadius: "12px", marginBottom: "18px",
                        backgroundColor: r.bg, border: `1.5px solid ${r.border}`,
                        display: "flex", alignItems: "center", gap: "12px",
                      }}>
                        <span style={{
                          padding: "4px 16px", borderRadius: "999px",
                          backgroundColor: r.border, color: "#fff", fontWeight: 700, fontSize: "12px", letterSpacing: "0.5px",
                        }}>
                          {analyzeResult.overall_risk}
                        </span>
                        <span style={{ color: r.text, fontWeight: 600, fontSize: "14px" }}>Overall Risk Level</span>
                      </div>
                    );
                  })()}

                  {/* Execution Summary */}
                  <div style={{
                    padding: "16px 18px", border: "1.5px solid #e2e8f0", borderRadius: "12px",
                    backgroundColor: "#f8fafc", marginBottom: "18px",
                  }}>
                    <div style={{ fontSize: "11px", fontWeight: 700, letterSpacing: "0.7px", textTransform: "uppercase", color: "#64748b", marginBottom: "8px" }}>
                      📋 Execution Summary
                    </div>
                    <p style={{ margin: 0, color: "#475569", lineHeight: "1.7", fontSize: "14px" }}>
                      {analyzeResult.execution_summary}
                    </p>
                  </div>

                  {/* Threat Findings */}
                  {(analyzeResult.rule_findings.length > 0 || analyzeResult.llm_findings.length > 0) ? (
                    <section>
                      <h3 style={{
                        margin: "0 0 10px", fontSize: "11px", fontWeight: 700,
                        textTransform: "uppercase", letterSpacing: "0.7px", color: "#64748b",
                      }}>
                        ⚡ Threat Findings · {analyzeResult.rule_findings.length + analyzeResult.llm_findings.length}
                      </h3>
                      {[...analyzeResult.rule_findings, ...analyzeResult.llm_findings].map((f, i) => {
                        const sc = SEVERITY_COLORS[f.severity] ?? { bg: "#6b7280", text: "#fff" };
                        return (
                          <div key={i} className="result-card" style={{
                            padding: "14px 16px", border: "1.5px solid #e2e8f0", borderRadius: "12px",
                            marginBottom: "10px", backgroundColor: "#fff",
                            boxShadow: "0 1px 4px rgba(0,0,0,0.04)",
                          }}>
                            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "8px", flexWrap: "wrap" }}>
                              <span style={{
                                padding: "3px 12px", borderRadius: "999px",
                                backgroundColor: sc.bg, color: sc.text, fontWeight: 700, fontSize: "11px", letterSpacing: "0.4px",
                              }}>
                                {f.severity}
                              </span>
                              <span style={{
                                padding: "3px 10px", borderRadius: "999px", fontSize: "11px", fontWeight: 600,
                                backgroundColor: f.source === "llm" ? "#ede9fe" : "#dbeafe",
                                color: f.source === "llm" ? "#5b21b6" : "#1d4ed8",
                                border: `1px solid ${f.source === "llm" ? "#c4b5fd" : "#bfdbfe"}`,
                              }}>
                                {f.source === "llm" ? "AI" : "Rule"}
                              </span>
                              <span style={{
                                fontSize: "11px", color: "#64748b",
                                backgroundColor: "#f1f5f9", padding: "2px 8px", borderRadius: "6px",
                              }}>
                                {f.category.replace(/_/g, " ")}
                              </span>
                            </div>
                            <p style={{ margin: "0 0 8px", color: "#0f172a", fontWeight: 500, fontSize: "14px", lineHeight: "1.5" }}>
                              {f.description}
                            </p>
                            {f.evidence && (
                              <pre style={{
                                backgroundColor: "#0f172a", color: "#e2e8f0",
                                padding: "8px 12px", borderRadius: "8px", fontSize: "12px",
                                margin: 0, overflowX: "auto", whiteSpace: "pre-wrap", wordBreak: "break-all", lineHeight: "1.5",
                              }}>
                                {f.evidence}
                              </pre>
                            )}
                          </div>
                        );
                      })}
                    </section>
                  ) : (
                    <div style={{
                      padding: "14px 18px", border: "1.5px solid #bbf7d0", borderRadius: "12px",
                      backgroundColor: "#f0fdf4", color: "#15803d", fontSize: "14px",
                      display: "flex", alignItems: "center", gap: "8px",
                    }}>
                      ✅ No specific threat patterns detected.
                    </div>
                  )}
                </div>
              )}

            </div>{/* /body */}
          </div>{/* /card */}

          {/* Footer */}
          <p style={{ textAlign: "center", marginTop: "16px", fontSize: "12px", color: "#94a3b8" }}>
            Skill Scanner · Unicode steganography + Threat analysis
          </p>
        </div>
      </main>
    </>
  );
}