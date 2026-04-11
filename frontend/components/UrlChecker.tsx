import { useState } from "react";
import { analyzeURL, deepAnalyzeURL } from "../services/api";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "./ui/card";
import { Input } from "./ui/input";
import { Button } from "./ui/button";
import { Badge } from "./ui/badge";
import {
  AlertCircle, ShieldAlert, ShieldCheck, ShieldBan,
  Loader2, Link as LinkIcon, AlertTriangle, Sparkles, ChevronDown
} from "lucide-react";


export default function UrlChecker() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [deepLoading, setDeepLoading] = useState(false);
  const [deepResult, setDeepResult] = useState<any>(null);
  const [deepError, setDeepError] = useState<string | null>(null);


  const handleCheck = async () => {
    if (!url) return;
    setLoading(true);
    setError(null);
    setResult(null);
    setDeepResult(null);
    setDeepError(null);

    try {
      const data = await analyzeURL(url);
      setResult(data);
    } catch (e: any) {
      setError(e.message || "An unexpected error occurred.");
    } finally {
      setLoading(false);
    }
  };

  const handleDeepCheck = async () => {
    if (!url) return;
    setDeepLoading(true);
    setDeepError(null);
    setDeepResult(null);
    try {
      const data = await deepAnalyzeURL(url);
      setDeepResult(data);
    } catch (e: any) {
      setDeepError(e.message || "Deep analysis failed.");
    } finally {
      setDeepLoading(false);
    }
  };


  const getRiskColor = (level: string) => {
    switch (level?.toLowerCase()) {
      case "safe": return "bg-green-500/10 text-green-500 hover:bg-green-500/20";
      case "suspicious": return "bg-yellow-500/10 text-yellow-500 hover:bg-yellow-500/20";
      case "dangerous":
      case "high": return "bg-red-500/10 text-red-500 hover:bg-red-500/20";
      default: return "bg-gray-500/10 text-gray-500 hover:bg-gray-500/20";
    }
  };

  const getRiskIcon = (level: string) => {
    switch (level?.toLowerCase()) {
      case "safe": return <ShieldCheck className="h-6 w-6 text-green-500" />;
      case "suspicious": return <AlertTriangle className="h-6 w-6 text-yellow-500" />;
      case "dangerous":
      case "high": return <ShieldBan className="h-6 w-6 text-red-500" />;
      default: return <AlertCircle className="h-6 w-6 text-gray-500" />;
    }
  };

  return (
    <Card className="w-full max-w-2xl mx-auto shadow-lg border-primary/10 bg-card/50 backdrop-blur-sm">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-2xl">
          <LinkIcon className="h-6 w-6 text-primary" />
          URL Scam Scanner
        </CardTitle>
        <CardDescription>
          Enter a website URL to scan it for phishing attempts, malicious redirects, and scam signals.
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-6">
        <div className="flex space-x-2">
          <Input
            type="url"
            placeholder="https://example.com"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleCheck()}
            className="flex-1 bg-background/50"
            disabled={loading}
          />
          <Button onClick={handleCheck} disabled={loading || !url}>
            {loading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Scanning...
              </>
            ) : (
              "Analyze URL"
            )}
          </Button>
        </div>

        {error && (
          <div className="p-4 rounded-md bg-destructive/10 text-destructive text-sm flex items-start gap-3">
            <AlertCircle className="h-5 w-5 shrink-0" />
            <p>{error}</p>
          </div>
        )}

        {result && (
          <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
            {/* Risk summary header */}
            <div className="flex items-start justify-between p-4 rounded-lg bg-background/50 border">
              <div className="flex items-center gap-4">
                {getRiskIcon(result.risk_level)}
                <div>
                  <h3 className="font-semibold text-lg capitalize">{result.risk_level} Risk</h3>
                  <p className="text-sm text-muted-foreground">{result.risk_summary || "Analysis complete."}</p>
                </div>
              </div>
              <div className="text-right">
                <div className="text-2xl font-bold">{result.risk_score ?? result.risk_score_percent ?? 0}%</div>
                <div className="text-xs text-muted-foreground">Confidence: {Math.round((result.confidence || 0) * 100)}%</div>
              </div>
            </div>

            {/* LLM explanation block */}
            {result.llm_explanation && typeof result.llm_explanation === "object" ? (
              <div className="space-y-4">
                {result.llm_explanation.website_summary && (
                  <div className="p-4 rounded-lg bg-secondary/10 border border-secondary/20">
                    <h4 className="font-medium mb-1 text-sm text-foreground/80">🌐 Website Summary</h4>
                    <p className="text-sm text-muted-foreground">{result.llm_explanation.website_summary}</p>
                  </div>
                )}

                {result.llm_explanation.analysis_summary && (
                  <div className="p-4 rounded-lg bg-primary/5 border border-primary/20">
                    <h4 className="font-medium mb-1 flex items-center gap-2 text-sm">
                      <ShieldAlert className="h-4 w-4 text-primary" /> AI Risk Analysis
                    </h4>
                    <p className="text-sm text-muted-foreground">{result.llm_explanation.analysis_summary}</p>
                  </div>
                )}

                {result.llm_explanation.recommended_action && (
                  <div className="p-4 rounded-lg bg-green-500/5 border border-green-500/20">
                    <h4 className="font-medium mb-1 text-sm text-green-500">👉 Recommended Action</h4>
                    <p className="text-sm text-muted-foreground">{result.llm_explanation.recommended_action}</p>
                  </div>
                )}
              </div>
            ) : result.advice ? (
              <div className="p-4 rounded-lg bg-primary/5 border border-primary/20">
                <h4 className="font-medium mb-2 flex items-center gap-2">
                  <ShieldAlert className="h-4 w-4 text-primary" /> AI Advice
                </h4>
                <p className="text-sm text-muted-foreground whitespace-pre-wrap">{result.advice}</p>
              </div>
            ) : null}

            {/* Risk factors badges */}
            {result.reasons && result.reasons.length > 0 && (
              <div className="space-y-2">
                <h4 className="text-sm font-medium text-muted-foreground">Detected Risk Factors</h4>
                <div className="flex flex-wrap gap-2">
                  {result.reasons.map((reason: string, idx: number) => (
                    <Badge key={idx} variant="outline" className="bg-background">
                      {reason}
                    </Badge>
                  ))}
                </div>
              </div>
            )}

            {/* Screenshot */}
            {result.screenshot && (
              <div className="space-y-2">
                <h4 className="text-sm font-medium text-muted-foreground">Site Screenshot</h4>
                <div className="rounded-md overflow-hidden border shadow-sm max-h-[400px] overflow-y-auto">
                  <img
                    src={result.screenshot.startsWith('data:') ? result.screenshot : `data:image/png;base64,${result.screenshot}`}
                    alt="Website screenshot"
                    className="w-full object-cover"
                  />
                </div>
              </div>
            )}

            {/* Deep Analysis Button */}
            <div className="pt-2 border-t border-border/40">
              <Button
                variant="outline"
                onClick={handleDeepCheck}
                disabled={deepLoading}
                className="w-full flex items-center gap-2 border-primary/30 hover:border-primary/60 hover:bg-primary/5"
              >
                {deepLoading ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Running Deep AI Analysis...
                  </>
                ) : (
                  <>
                    <Sparkles className="h-4 w-4 text-primary" />
                    Deep AI Analysis
                    <ChevronDown className="h-4 w-4 ml-auto opacity-60" />
                  </>
                )}
              </Button>
              <p className="text-xs text-muted-foreground text-center mt-1">
                Crawls website content and runs AI-powered deep inspection
              </p>
            </div>

            {deepError && (
              <div className="p-4 rounded-md bg-destructive/10 text-destructive text-sm flex items-start gap-3">
                <AlertCircle className="h-5 w-5 shrink-0" />
                <p>{deepError}</p>
              </div>
            )}
          </div>
        )}

        {/* Deep Result Panel */}
        {deepResult && (
          <div className="space-y-4 animate-in fade-in slide-in-from-bottom-4 duration-500 p-4 rounded-xl border border-primary/20 bg-primary/5">
            <div className="flex items-center gap-2 mb-2">
              <Sparkles className="h-5 w-5 text-primary" />
              <h3 className="font-semibold text-lg">Deep AI Analysis Result</h3>
            </div>

            {deepResult.website_title && (
              <p className="text-sm text-muted-foreground">
                🌐 <span className="font-medium text-foreground">Website:</span> {deepResult.website_title}
              </p>
            )}

            <div className="flex items-center gap-4 p-3 rounded-lg bg-background/60 border">
              {getRiskIcon(deepResult.risk_level)}
              <div>
                <span className="font-semibold capitalize">{deepResult.risk_level || "Unknown"} Risk</span>
                <div className="text-xs text-muted-foreground">
                  Score: {deepResult.risk_score_percent ?? Math.round((deepResult.risk_score ?? 0) * 100)}%
                </div>
              </div>
            </div>

            {/* Deep LLM explanation */}
            {deepResult.llm_explanation && typeof deepResult.llm_explanation === "object" && (
              <div className="space-y-3">
                {deepResult.llm_explanation.website_summary && (
                  <div className="p-3 rounded-lg bg-secondary/10 border border-secondary/20">
                    <h4 className="font-medium mb-1 text-sm text-foreground/80">🌐 Website Summary</h4>
                    <p className="text-sm text-muted-foreground">{deepResult.llm_explanation.website_summary}</p>
                  </div>
                )}
                {deepResult.llm_explanation.analysis_summary && (
                  <div className="p-3 rounded-lg bg-primary/5 border border-primary/20">
                    <h4 className="font-medium mb-1 flex items-center gap-2 text-sm">
                      <ShieldAlert className="h-4 w-4 text-primary" /> AI Risk Analysis
                    </h4>
                    <p className="text-sm text-muted-foreground">{deepResult.llm_explanation.analysis_summary}</p>
                  </div>
                )}
                {deepResult.llm_explanation.recommended_action && (
                  <div className="p-3 rounded-lg bg-green-500/5 border border-green-500/20">
                    <h4 className="font-medium mb-1 text-sm text-green-500">👉 Recommended Action</h4>
                    <p className="text-sm text-muted-foreground">{deepResult.llm_explanation.recommended_action}</p>
                  </div>
                )}
              </div>
            )}

            {/* Signals */}
            {deepResult.signals && deepResult.signals.length > 0 && (
              <div className="space-y-2">
                <h4 className="text-sm font-medium text-muted-foreground">Detected Signals</h4>
                <div className="flex flex-wrap gap-2">
                  {deepResult.signals.map((signal: string, idx: number) => (
                    <Badge key={idx} variant="outline" className="bg-background">
                      {signal}
                    </Badge>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}