"use client"

import type React from "react"

import { useState, useRef, useEffect } from "react"
import Navbar from "@/components/navbar"
import Footer from "@/components/footer"

interface Message {
  id: string
  type: "user" | "ai"
  content: string
  timestamp: Date
}

const suggestedPrompts = [
  "What are the common signs of a phishing email?",
  "How do I spot a fake website?",
  "What should I do if I clicked a suspicious link?",
  "How can I protect my password from scammers?",
]

export default function ConsultationPage() {
  const [messages, setMessages] = useState<Message[]>([
    {
      id: "1",
      type: "ai",
      content:
        "Hello! I'm your AI Scam Detection Consultant. I can help you analyze suspicious websites, explain phishing techniques, and answer questions about online security. How can I assist you today?",
      timestamp: new Date(),
    },
  ])
  const [inputValue, setInputValue] = useState("")
  const [isLoading, setIsLoading] = useState(false)
  const messagesEndRef = useRef<HTMLDivElement>(null)

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" })
  }

  useEffect(() => {
    scrollToBottom()
  }, [messages])

  const handleSendMessage = () => {
    if (!inputValue.trim()) return

    const userMessage: Message = {
      id: Date.now().toString(),
      type: "user",
      content: inputValue,
      timestamp: new Date(),
    }

    setMessages((prev) => [...prev, userMessage])
    setInputValue("")
    setIsLoading(true)

    // Simulate AI response
    setTimeout(() => {
      const aiResponse: Message = {
        id: (Date.now() + 1).toString(),
        type: "ai",
        content:
          "I've analyzed your query. Based on current phishing trends and security patterns, here's what I found...\n\nThis is a simulated AI response. In a production environment, this would be powered by advanced AI models to provide detailed security analysis and recommendations.",
        timestamp: new Date(),
      }
      setMessages((prev) => [...prev, aiResponse])
      setIsLoading(false)
    }, 1500)
  }

  const handleClearChat = () => {
    setMessages([
      {
        id: "1",
        type: "ai",
        content:
          "Hello! I'm your AI Scam Detection Consultant. I can help you analyze suspicious websites, explain phishing techniques, and answer questions about online security. How can I assist you today?",
        timestamp: new Date(),
      },
    ])
  }

  const handleSuggestedPrompt = (prompt: string) => {
    setInputValue(prompt)
  }

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !isLoading && inputValue.trim()) {
      handleSendMessage()
    }
  }

  return (
    <div className="min-h-screen flex flex-col bg-gradient-to-br from-background via-background to-card/20">
      <Navbar />

      {/* Animated background elements */}
      <div className="fixed inset-0 -z-10 overflow-hidden">
        <div className="absolute top-20 right-20 w-80 h-80 bg-secondary/10 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-20 left-20 w-80 h-80 bg-primary/10 rounded-full blur-3xl animate-pulse delay-75"></div>
      </div>

      <main className="flex-1 w-full pt-24 pb-6">
        <div className="max-w-4xl mx-auto h-full flex flex-col px-4">
          {/* Header with clear button */}
          <div className="text-center mb-6 flex items-center justify-between">
            <div className="flex-1"></div>
            <div className="text-center flex-1">
              <h1 className="text-3xl font-bold mb-2 bg-gradient-to-r from-primary to-secondary bg-clip-text text-transparent">
                AI Consultation
              </h1>
              <p className="text-foreground/60">Chat with our AI security expert about scams and phishing</p>
            </div>
            <button
              onClick={handleClearChat}
              className="text-sm px-3 py-1.5 rounded-lg hover:bg-card/50 transition-colors text-foreground/60 hover:text-foreground"
              title="Clear chat history"
            >
              Clear
            </button>
          </div>

          {/* Chat Container */}
          <div className="flex-1 glow-border p-6 mb-6 overflow-y-auto flex flex-col bg-card/30 backdrop-blur-sm">
            {messages.map((message) => (
              <div
                key={message.id}
                className={`flex mb-4 ${message.type === "user" ? "justify-end" : "justify-start"} animate-fadeIn`}
              >
                <div
                  className={`max-w-xs lg:max-w-md xl:max-w-lg rounded-2xl px-4 py-3 ${
                    message.type === "user"
                      ? "bg-gradient-to-r from-primary to-secondary text-white rounded-br-none"
                      : "bg-card border border-border/50 text-foreground rounded-bl-none"
                  }`}
                >
                  <p className="text-sm leading-relaxed whitespace-pre-wrap">{message.content}</p>
                  <span className="text-xs opacity-70 mt-2 block">
                    {message.timestamp.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                  </span>
                </div>
              </div>
            ))}
            {isLoading && (
              <div className="flex justify-start mb-4">
                <div className="bg-card border border-border/50 rounded-2xl rounded-bl-none px-4 py-3">
                  <div className="flex gap-2">
                    <div className="w-2 h-2 bg-foreground/50 rounded-full animate-bounce"></div>
                    <div className="w-2 h-2 bg-foreground/50 rounded-full animate-bounce delay-100"></div>
                    <div className="w-2 h-2 bg-foreground/50 rounded-full animate-bounce delay-200"></div>
                  </div>
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {messages.length === 1 && !isLoading && (
            <div className="mb-6">
              <p className="text-sm text-foreground/60 mb-3">Try asking:</p>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {suggestedPrompts.map((prompt, index) => (
                  <button
                    key={index}
                    onClick={() => handleSuggestedPrompt(prompt)}
                    className="text-left p-3 rounded-lg border border-border/30 bg-card/20 hover:bg-card/40 transition-colors text-sm text-foreground/70 hover:text-foreground"
                  >
                    {prompt}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Input Area */}
          <div className="glow-border p-4 bg-card/30 backdrop-blur-sm">
            <div className="flex gap-2">
              <input
                type="text"
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
                onKeyPress={handleKeyPress}
                placeholder="Ask me anything about scams and security..."
                className="flex-1 cyber-input border-none bg-transparent text-sm focus:outline-none"
              />
              <button
                onClick={handleSendMessage}
                disabled={isLoading || !inputValue.trim()}
                className="cyber-button text-white text-sm disabled:opacity-50"
              >
                {isLoading ? "⟳" : "📨"}
              </button>
              <button className="p-3 hover:bg-card/50 rounded-lg transition-colors text-foreground/60 hover:text-foreground">
                📎
              </button>
            </div>
          </div>
        </div>
      </main>

      <Footer />
    </div>
  )
}
