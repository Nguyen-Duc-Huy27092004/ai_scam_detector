"use client"

import Navbar from "@/components/navbar"
import Footer from "@/components/footer"
import UrlChecker from "@/components/UrlChecker"

export default function Home() {
  return (
    <div className="min-h-screen flex flex-col bg-gradient-to-b from-background via-background to-card/30">
      
      <Navbar />

      {/* Animated background elements */}
      <div className="fixed inset-0 -z-10 overflow-hidden">
        <div className="absolute top-20 left-10 w-72 h-72 bg-primary/10 rounded-full blur-3xl animate-pulse"></div>

        <div className="absolute bottom-40 right-10 w-96 h-96 bg-secondary/10 rounded-full blur-3xl animate-pulse delay-75"></div>

        <div className="absolute top-1/2 left-1/2 w-80 h-80 bg-accent/5 rounded-full blur-3xl animate-pulse delay-150"></div>
      </div>

      <main className="flex-1 w-full max-w-6xl mx-auto px-6 py-12 space-y-16">

        {/* HERO */}
        <section className="text-center space-y-4">
          <h1 className="text-4xl font-bold tracking-tight">
            AI Scam Detector
          </h1>

          <p className="text-muted-foreground max-w-2xl mx-auto">
            Detect phishing websites, analyze suspicious chats, and identify
            scam messages using AI-powered analysis.
          </p>
        </section>

        {/* URL SCAM DETECTOR */}
        <section>
          <UrlChecker />
        </section>

      </main>

      <Footer />
    </div>
  )
}