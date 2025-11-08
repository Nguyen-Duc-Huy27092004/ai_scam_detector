"use client"

import type React from "react"

import { useState } from "react"
import Navbar from "@/components/navbar"
import Footer from "@/components/footer"

export default function LoginPage() {
  const [isLogin, setIsLogin] = useState(true)
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [confirmPassword, setConfirmPassword] = useState("")
  const [errors, setErrors] = useState<{ [key: string]: string }>({})
  const [isLoading, setIsLoading] = useState(false)

  const validateForm = () => {
    const newErrors: { [key: string]: string } = {}

    if (!email) newErrors.email = "Email is required"
    else if (!email.includes("@")) newErrors.email = "Invalid email format"

    if (!password) newErrors.password = "Password is required"
    else if (password.length < 6) newErrors.password = "Password must be at least 6 characters"

    if (!isLogin && password !== confirmPassword) {
      newErrors.confirmPassword = "Passwords do not match"
    }

    setErrors(newErrors)
    return Object.keys(newErrors).length === 0
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    if (!validateForm()) return

    setIsLoading(true)
    setTimeout(() => {
      console.log({ email, password, confirmPassword, isLogin })
      setIsLoading(false)
    }, 1500)
  }

  return (
    <div className="min-h-screen flex flex-col bg-gradient-to-b from-background via-background to-card/30">
      <Navbar />

      <div className="fixed inset-0 -z-10 overflow-hidden">
        <div className="absolute top-1/3 left-10 w-80 h-80 bg-primary/10 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-1/3 right-10 w-80 h-80 bg-secondary/10 rounded-full blur-3xl animate-pulse delay-75"></div>
      </div>

      <main className="flex-1 flex items-center justify-center px-4 pt-20">
        <div className="w-full max-w-md">
          <div className="glow-border p-8 bg-card/50 backdrop-blur-sm animate-fadeIn">
            <div className="text-center mb-8">
              <h1 className="text-3xl font-bold mb-2 bg-gradient-to-r from-primary to-secondary bg-clip-text text-transparent">
                {isLogin ? "Welcome Back" : "Join Us"}
              </h1>
              <p className="text-foreground/60 text-sm">
                {isLogin ? "Access your security dashboard" : "Start protecting yourself today"}
              </p>
            </div>

            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-2 text-foreground/80">Email Address</label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => {
                    setEmail(e.target.value)
                    if (errors.email) setErrors({ ...errors, email: "" })
                  }}
                  placeholder="you@example.com"
                  className={`w-full cyber-input ${errors.email ? "border-red-500/50" : ""}`}
                  required
                />
                {errors.email && <p className="text-xs text-red-400 mt-1">{errors.email}</p>}
              </div>

              <div>
                <label className="block text-sm font-medium mb-2 text-foreground/80">Password</label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value)
                    if (errors.password) setErrors({ ...errors, password: "" })
                  }}
                  placeholder="••••••••"
                  className={`w-full cyber-input ${errors.password ? "border-red-500/50" : ""}`}
                  required
                />
                {errors.password && <p className="text-xs text-red-400 mt-1">{errors.password}</p>}
              </div>

              {!isLogin && (
                <div>
                  <label className="block text-sm font-medium mb-2 text-foreground/80">Confirm Password</label>
                  <input
                    type="password"
                    value={confirmPassword}
                    onChange={(e) => {
                      setConfirmPassword(e.target.value)
                      if (errors.confirmPassword) setErrors({ ...errors, confirmPassword: "" })
                    }}
                    placeholder="••••••••"
                    className={`w-full cyber-input ${errors.confirmPassword ? "border-red-500/50" : ""}`}
                    required
                  />
                  {errors.confirmPassword && <p className="text-xs text-red-400 mt-1">{errors.confirmPassword}</p>}
                </div>
              )}

              <button
                type="submit"
                disabled={isLoading}
                className="w-full cyber-button text-white font-semibold justify-center mt-6 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isLoading ? (
                  <>
                    <span className="animate-spin">⟳</span>
                    {isLogin ? "Signing In..." : "Creating Account..."}
                  </>
                ) : isLogin ? (
                  "Sign In"
                ) : (
                  "Create Account"
                )}
              </button>
            </form>

            <div className="mt-6 pt-6 border-t border-border/30 text-center">
              <p className="text-sm text-foreground/60 mb-2">
                {isLogin ? "Don't have an account?" : "Already have an account?"}
              </p>
              <button
                onClick={() => {
                  setIsLogin(!isLogin)
                  setEmail("")
                  setPassword("")
                  setConfirmPassword("")
                  setErrors({})
                }}
                className="text-primary hover:text-secondary transition-colors font-medium"
              >
                {isLogin ? "Sign Up" : "Sign In"}
              </button>
            </div>
          </div>

          <p className="text-center text-xs text-foreground/50 mt-6">
            By continuing, you agree to our Terms of Service and Privacy Policy
          </p>
        </div>
      </main>

      <Footer />
    </div>
  )
}
