"use client"
import Navbar from "@/components/navbar"
import Footer from "@/components/footer"
import UrlChecker from "@/components/url-checker"

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

      <main className="flex-1 w-full">
        <UrlChecker />
      </main>

      <Footer />
    </div>
  )
}
