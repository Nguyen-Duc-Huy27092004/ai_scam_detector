const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api";

// All fetch calls use a timeout so requests never hang indefinitely.
// AbortController-based: throws AbortError after timeoutMs milliseconds.
const fetchWithTimeout = async (
  url: string,
  options: RequestInit,
  timeoutMs = 30000
): Promise<Response> => {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(id);
  }
};


export const analyzeURL = async (url: string) => {
  const res = await fetchWithTimeout(`${API_URL}/url/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  const data = await res.json();
  if (!data.success) throw new Error(data.error || "Failed to analyze URL");
  return data.data;
};

export const analyzeText = async (text: string) => {
  const res = await fetchWithTimeout(`${API_URL}/text/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text }),
  });
  const data = await res.json();
  if (!data.success) throw new Error(data.error || "Failed to analyze text");
  return data.data;
};

export const analyzeImage = async (file: File) => {
  const formData = new FormData();
  formData.append("image", file);
  // Image analysis can take longer (OCR + ML inference)
  const res = await fetchWithTimeout(`${API_URL}/image/analyze`, {
    method: "POST",
    body: formData,
  }, 60_000);
  const data = await res.json();
  if (!data.success) throw new Error(data.error || "Failed to analyze image");
  return data.data;
};

export const deepAnalyzeURL = async (url: string) => {
  // Deep analysis includes website crawl + LLM — allow 60 s
  const res = await fetchWithTimeout(`${API_URL}/url/deep-analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  }, 60_000);
  const data = await res.json();
  if (!data.success) throw new Error(data.error || "Failed to run deep AI analysis");
  return data.data;
};

export interface ChatMessage {
  role: "user" | "assistant" | "system";
  content: string;
}

export const chatCompletions = async (messages: ChatMessage[], stream = false) => {
  // LLM chat can take up to 90 s — use fetchWithTimeout to prevent infinite hang
  const res = await fetchWithTimeout(
    `${API_URL}/chat/completions`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ messages, stream }),
    },
    90_000,
  );
  const data = await res.json();
  if (!data.success) throw new Error(data.error || "Chat request failed");

  // Extract plain text content from the LLM message
  const msg = data.message;
  if (typeof msg?.content === "string") return msg.content;
  return "Xin lỗi, tôi không thể xử lý yêu cầu này.";
};
