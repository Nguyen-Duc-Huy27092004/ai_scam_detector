"use client"

import Link from "next/link"
import { useState } from "react"

export default function Navbar() {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false)

  return (
    <nav className="fixed top-0 w-full z-50 backdrop-blur-md bg-background/80 border-b border-border/50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          {/* Logo */}
          <Link href="/" className="flex items-center gap-2 group">
            <div className="w-8 h-8 bg-gradient-to-br from-primary to-secondary rounded-lg flex items-center justify-center group-hover:scale-110 transition-transform">
              <span className="text-white font-bold text-sm">AI</span>
            </div>
            <span className="font-bold text-lg hidden sm:inline bg-gradient-to-r from-primary to-secondary bg-clip-text text-transparent">
              Scam Detector
            </span>
          </Link>

          {/* Desktop Menu */}
          <div className="hidden md:flex items-center gap-8">
            <Link href="/" className="nav-link group">
              Check URL
            </Link>
            <Link href="/consultation" className="nav-link group">
              AI Consultation
            </Link>
            <Link href="/login" className="cyber-button text-white">
              Login / Register
            </Link>
          </div>

          {/* Mobile Menu Button */}
          <button className="md:hidden p-2" onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}>
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d={isMobileMenuOpen ? "M6 18L18 6M6 6l12 12" : "M4 6h16M4 12h16M4 18h16"}
              />
            </svg>
          </button>
        </div>

        {/* Mobile Menu */}
        {isMobileMenuOpen && (
          <div className="md:hidden pb-4 pt-2 border-t border-border/30">
            <Link href="/" className="block px-3 py-2 text-sm hover:bg-card/50 rounded-lg transition-colors">
              Check URL
            </Link>
            <Link
              href="/consultation"
              className="block px-3 py-2 text-sm hover:bg-card/50 rounded-lg transition-colors"
            >
              AI Consultation
            </Link>
            <Link href="/login" className="block px-3 py-2 mt-2 text-sm hover:bg-card/50 rounded-lg transition-colors">
              Login / Register
            </Link>
          </div>
        )}
      </div>
    </nav>
  )
}
