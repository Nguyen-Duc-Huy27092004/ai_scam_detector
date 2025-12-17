"use client"

import type React from "react"
import { useState } from "react"

type StatusType = "idle" | "loading" | "safe" | "suspicious" | "dangerous"

export default function UrlChecker() {
  const [url, setUrl] = useState("")
  const [status, setStatus] = useState<StatusType>("idle")
  const [loading, setLoading] = useState(false)

  const handleCheck = async () => {
    if (!url.trim()) return

    setLoading(true)
    setStatus("loading")

    try {
      const res = await fetch("http://localhost:5000/api/predict", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url }),
      })

      const data = await res.json()
      if (data.label === "phishing") {
        setStatus("dangerous")
      } else {
        setStatus("safe")
      }
    } catch (error) {
      console.error("Error calling AI backend:", error)
      setStatus("suspicious")
    } finally {
      setLoading(false)
    }
  }

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !loading) {
      handleCheck()
    }
  }

  const getStatusDisplay = () => {
    switch (status) {
      case "safe":
        return {
          icon: "✓",
          text: "Safe",
          className: "safe-badge",
          color: "text-green-400",
        }
      case "suspicious":
        return {
          icon: "⚠",
          text: "Suspicious",
          className: "warning-badge",
          color: "text-yellow-400",
        }
      case "dangerous":
        return {
          icon: "✕",
          text: "Dangerous",
          className: "danger-badge",
          color: "text-red-400",
        }
      default:
        return null
    }
  }

  const statusDisplay = getStatusDisplay()

  return (
    <div className="min-h-screen flex items-center justify-center px-4 pt-20">
      <div className="w-full max-w-2xl">
        <div className="text-center mb-12 animate-fadeIn">
          <h1 className="text-4xl md:text-5xl font-bold mb-4 bg-gradient-to-r from-primary via-secondary to-accent bg-clip-text text-transparent leading-tight">
            Check website safety with AI
          </h1>
          <p className="text-foreground/70 text-lg">
            Paste a URL below to analyze and detect possible scam or phishing threats.
          </p>
        </div>

        {/* URL Input Section */}
        <div className="mb-8 animate-fadeIn delay-75">
          <div className="glow-border p-1">
            <div className="flex gap-2 bg-card rounded-xl p-1">
              <input
                type="text"
                placeholder="https://example.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onKeyPress={handleKeyPress}
                className="flex-1 cyber-input border-none bg-transparent focus:outline-none"
              />
              <button
                onClick={handleCheck}
                disabled={loading || !url.trim()}
                className="cyber-button text-white disabled:opacity-50 disabled:cursor-not-allowed transition-transform hover:scale-105"
              >
                {loading ? (
                  <>
                    <span className="animate-spin">⟳</span>
                    Checking
                  </>
                ) : (
                  "Check"
                )}
              </button>
            </div>
          </div>
        </div>

        {/* Results Display */}
        {status !== "idle" && (
          <div className="text-center animate-fadeIn">
            {loading ? (
              <div className="flex flex-col items-center gap-4">
                <div className="w-16 h-16 border-4 border-primary/30 border-t-primary rounded-full animate-spin"></div>
                <p className="text-foreground/60">Analyzing website with AI model...</p>
              </div>
            ) : statusDisplay ? (
              <div
                className={`${statusDisplay.className} inline-flex items-center gap-2 px-6 py-3 text-lg font-semibold mb-6 transition-transform hover:scale-105`}
              >
                <span className={statusDisplay.color}>{statusDisplay.icon}</span>
                {statusDisplay.text}
              </div>
            ) : null}

            {!loading && statusDisplay && (
              <div className="mt-6 p-6 bg-card/50 border border-border/30 rounded-xl text-left transition-all hover:border-border/50 hover:bg-card/70">
                <h3 className="font-semibold mb-3 text-foreground">Analysis Details:</h3>
                <ul className="space-y-2 text-sm text-foreground/70">
                  <li className="flex gap-2">
                    <span className="text-accent">•</span>
                    URL analyzed using machine learning phishing detection model
                  </li>
                  <li className="flex gap-2">
                    <span className="text-accent">•</span>
                    Features extracted from URL structure and lexical patterns
                  </li>
                  <li className="flex gap-2">
                    <span className="text-accent">•</span>
                    Prediction generated by trained classification model
                  </li>
                </ul>
              </div>
            )}
          </div>
        )}

        {/* Sample URLs */}
        {status === "idle" && (
          <div className="mt-12 p-6 bg-card/30 border border-border/20 rounded-xl animate-fadeIn delay-150">
            <p className="text-sm text-foreground/60 mb-4">
              Try these sample URLs to see the AI detection in action:
            </p>
            <div className="flex flex-wrap gap-2">
              {[
                "https://google.com",
                "http://paypal-secure-login.xyz",
                "https://account-verify-update.info",
              ].map((sampleUrl) => (
                <button
                  key={sampleUrl}
                  onClick={() => {
                    setUrl(sampleUrl)
                    setStatus("idle")
                  }}
                  className="text-xs px-3 py-1.5 bg-primary/20 border border-primary/50 rounded-lg hover:bg-primary/30 transition-all hover:scale-105 active:scale-95 text-primary/90"
                >
                  {sampleUrl}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
