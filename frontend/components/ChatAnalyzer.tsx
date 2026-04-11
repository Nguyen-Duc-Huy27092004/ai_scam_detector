import { useState } from "react";
import { analyzeText } from "../services/api";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "./ui/card";
import { Textarea } from "./ui/textarea";
import { Button } from "./ui/button";
import { MessageSquare, Loader2, AlertCircle, ShieldAlert } from "lucide-react";

export default function ChatAnalyzer() {
  const [text, setText] = useState("");
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleAnalyze = async () => {
    if (!text.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await analyzeText(text);
      setResult(data);
    } catch (e: any) {
      setError(e.message || "Failed to analyze text.");
    } finally {
      setLoading(false);
    }
  };

  const isScam = result?.analysis?.risk_level === "dangerous" || result?.analysis?.risk_level === "high" || result?.analysis?.is_scam;

  return (
    <Card className="w-full max-w-2xl mx-auto shadow-lg border-primary/10 bg-card/50 backdrop-blur-sm">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-2xl">
          <MessageSquare className="h-6 w-6 text-primary" />
          Chat & Email Analyzer
        </CardTitle>
        <CardDescription>
          Paste a suspicious message, email, or SMS to detect urgent scams, phishing, or social engineering tactics.
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-6">
        <div className="space-y-4">
          <Textarea
            placeholder="Paste the suspicious message here..."
            className="min-h-[150px] resize-y bg-background/50"
            value={text}
            onChange={(e) => setText(e.target.value)}
            disabled={loading}
          />
          <Button onClick={handleAnalyze} disabled={loading || !text.trim()} className="w-full">
            {loading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Analyzing Message...
              </>
            ) : (
              "Analyze Content"
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
            <div className={`flex items-start justify-between p-4 rounded-lg border ${isScam ? 'bg-red-500/10 border-red-500/20' : 'bg-green-500/10 border-green-500/20'}`}>
              <div className="flex items-center gap-4">
                {isScam ? <ShieldAlert className="h-6 w-6 text-red-500" /> : <MessageSquare className="h-6 w-6 text-green-500" />}
                <div>
                  <h3 className={`font-semibold text-lg capitalize ${isScam ? 'text-red-600 dark:text-red-400' : 'text-green-600 dark:text-green-400'}`}>
                    {result.analysis?.risk_level || (isScam ? "High Risk" : "Safe")}
                  </h3>
                  <p className="text-sm text-foreground/80">{result.analysis?.label || "Analysis is finished."}</p>
                </div>
              </div>
              <div className="text-right">
                <div className="text-2xl font-bold">{result.analysis?.overall_score ?? 0}%</div>
                <div className="text-xs text-muted-foreground">Score</div>
              </div>
            </div>

            {result.advice && (
              <div className="p-4 rounded-lg bg-primary/5 border border-primary/20">
                <h4 className="font-medium mb-2">Detailed Advice</h4>
                <p className="text-sm text-muted-foreground whitespace-pre-wrap">{result.advice}</p>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}