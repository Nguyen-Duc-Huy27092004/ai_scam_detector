import { useState, useRef } from "react";
import { analyzeImage } from "../services/api";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "./ui/card";
import { Button } from "./ui/button";
import { Image as ImageIcon, UploadCloud, Loader2, AlertCircle, ShieldAlert, CheckCircle2 } from "lucide-react";

export default function ImageAnalyzer() {
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    if (selectedFile) {
      setFile(selectedFile);
      // Create a preview URL
      const objectUrl = URL.createObjectURL(selectedFile);
      setPreview(objectUrl);
      setResult(null);
      setError(null);
    }
  };

  const handleUpload = async () => {
    if (!file) return;
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await analyzeImage(file);
      setResult(data);
    } catch (e: any) {
      setError(e.message || "Failed to analyze image.");
    } finally {
      setLoading(false);
    }
  };

  const isScam = result?.risk_level === "dangerous" || result?.risk_level === "high" || result?.is_scam;

  return (
    <Card className="w-full max-w-2xl mx-auto shadow-lg border-primary/10 bg-card/50 backdrop-blur-sm">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-2xl">
          <ImageIcon className="h-6 w-6 text-primary" />
          Image Scam Detector
        </CardTitle>
        <CardDescription>
          Upload a screenshot of a suspicious website, message, or QR code warning for AI analysis using OCR.
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-6">
        <div 
          onClick={() => !loading && fileInputRef.current?.click()}
          className={`border-2 border-dashed rounded-xl p-8 text-center transition-colors ${loading ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer hover:border-primary/50 hover:bg-primary/5'} ${preview ? 'border-primary/30' : 'border-border'}`}
        >
          <input
            type="file"
            ref={fileInputRef}
            className="hidden"
            accept="image/*"
            onChange={handleFileChange}
            disabled={loading}
          />
          
          {preview ? (
            <div className="space-y-4">
              <div className="relative mx-auto max-w-[300px] rounded-lg overflow-hidden border shadow-sm">
                <img src={preview} alt="Upload preview" className="w-full h-auto object-cover" />
              </div>
              <p className="text-sm font-medium text-muted-foreground">Click to change image</p>
            </div>
          ) : (
            <div className="space-y-3 flex flex-col items-center justify-center">
              <div className="w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center">
                <UploadCloud className="h-6 w-6 text-primary" />
              </div>
              <div>
                <p className="font-medium">Click to upload image</p>
                <p className="text-sm text-muted-foreground mt-1">PNG, JPG or WEBP up to 5MB</p>
              </div>
            </div>
          )}
        </div>

        {file && (
          <Button onClick={handleUpload} disabled={loading} className="w-full">
            {loading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Analyzing Image...
              </>
            ) : (
              "Scan Image Details"
            )}
          </Button>
        )}

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
                {isScam ? <ShieldAlert className="h-6 w-6 text-red-500" /> : <CheckCircle2 className="h-6 w-6 text-green-500" />}
                <div>
                  <h3 className={`font-semibold text-lg capitalize ${isScam ? 'text-red-600 dark:text-red-400' : 'text-green-600 dark:text-green-400'}`}>
                    {result.risk_level || (isScam ? "High Risk" : "Safe")}
                  </h3>
                  <p className="text-sm text-foreground/80">{result.summary || "Image analysis complete."}</p>
                </div>
              </div>
              <div className="text-right">
                <div className="text-2xl font-bold">{result.risk_score || 0}%</div>
                <div className="text-xs text-muted-foreground">Score</div>
              </div>
            </div>

            {result.ocr_text && (
               <div className="space-y-2">
                 <h4 className="text-sm font-medium text-muted-foreground">Extracted Text (OCR)</h4>
                 <div className="p-3 bg-muted rounded-md text-sm whitespace-pre-wrap font-mono text-muted-foreground max-h-40 overflow-y-auto">
                   {result.ocr_text}
                 </div>
               </div>
            )}

            {result.advice && (
              <div className="p-4 rounded-lg bg-primary/5 border border-primary/20">
                <h4 className="font-medium mb-2">Detailed Advice</h4>
                <p className="text-sm text-muted-foreground whitespace-pre-wrap">{result.advice}</p>
              </div>
            )}
            
            {result.risk_factors && result.risk_factors.length > 0 && (
               <div className="space-y-2">
                 <h4 className="text-sm font-medium text-muted-foreground">Key Signals</h4>
                 <ul className="list-disc pl-5 space-y-1 text-sm text-muted-foreground">
                   {result.risk_factors.map((factor: string, i: number) => (
                     <li key={i}>{factor}</li>
                   ))}
                 </ul>
               </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}