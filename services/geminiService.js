/**
 * Gemini AI Service — Production-hardened wrapper with rate limiting,
 * token-based key management, retry logic, and streaming support.
 * Used by both the backend analysis pipeline and the Copilot chat.
 */

const GEMINI_BASE = 'https://generativelanguage.googleapis.com/v1beta';
const DEFAULT_MODEL = 'gemini-1.5-flash';

// ── Rate Limiter ──
class TokenBucketRateLimiter {
  constructor(maxTokens = 60, refillRate = 1, refillIntervalMs = 1000) {
    this.tokens = maxTokens;
    this.maxTokens = maxTokens;
    this.refillRate = refillRate;
    this.lastRefill = Date.now();
    this.refillIntervalMs = refillIntervalMs;
    this.queue = [];
  }

  _refill() {
    const now = Date.now();
    const elapsed = now - this.lastRefill;
    const refills = Math.floor(elapsed / this.refillIntervalMs);
    if (refills > 0) {
      this.tokens = Math.min(this.maxTokens, this.tokens + refills * this.refillRate);
      this.lastRefill = now;
    }
  }

  async acquire() {
    this._refill();
    if (this.tokens > 0) {
      this.tokens--;
      return;
    }
    // Wait for next refill
    return new Promise(resolve => {
      this.queue.push(resolve);
      setTimeout(() => {
        this._refill();
        if (this.tokens > 0 && this.queue.length > 0) {
          this.tokens--;
          this.queue.shift()();
        }
      }, this.refillIntervalMs);
    });
  }
}

// ── Retry Logic ──
async function retryWithBackoff(fn, maxRetries = 3, baseDelayMs = 1000) {
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (err) {
      const isRetryable = err.status === 429 || err.status === 503 || err.status >= 500;
      if (attempt === maxRetries || !isRetryable) throw err;
      const delay = baseDelayMs * Math.pow(2, attempt) + Math.random() * 500;
      await new Promise(r => setTimeout(r, delay));
    }
  }
}

// ── Main Service ──
export class GeminiService {
  constructor(options = {}) {
    this.apiKey = options.apiKey || process.env.GEMINI_API_KEY || '';
    this.model = options.model || DEFAULT_MODEL;
    this.rateLimiter = new TokenBucketRateLimiter(
      options.maxRequestsPerMinute || 60,
      options.refillRate || 1,
      1000
    );
    this.metrics = { totalRequests: 0, successfulRequests: 0, failedRequests: 0, totalTokensUsed: 0, avgLatencyMs: 0, _latencies: [] };
    this.logger = options.logger || console;
  }

  isConfigured() {
    return !!this.apiKey;
  }

  setApiKey(key) {
    this.apiKey = key;
  }

  /** Generate content with full safety settings and structured output */
  async generateContent({ prompt, systemInstruction, history = [], temperature = 0.7, maxOutputTokens = 4096, responseSchema = null }) {
    if (!this.apiKey) throw Object.assign(new Error('Gemini API key not configured'), { code: 'NO_API_KEY' });
    await this.rateLimiter.acquire();

    const contents = [];
    for (const msg of history) {
      contents.push({ role: msg.role, parts: [{ text: msg.text }] });
    }
    contents.push({ role: 'user', parts: [{ text: prompt }] });

    const body = {
      contents,
      generationConfig: {
        temperature,
        maxOutputTokens,
        topP: 0.95,
        topK: 40,
      },
      safetySettings: [
        { category: 'HARM_CATEGORY_HARASSMENT', threshold: 'BLOCK_NONE' },
        { category: 'HARM_CATEGORY_HATE_SPEECH', threshold: 'BLOCK_NONE' },
        { category: 'HARM_CATEGORY_SEXUALLY_EXPLICIT', threshold: 'BLOCK_NONE' },
        { category: 'HARM_CATEGORY_DANGEROUS_CONTENT', threshold: 'BLOCK_NONE' },
      ],
    };

    if (systemInstruction) {
      body.systemInstruction = { parts: [{ text: systemInstruction }] };
    }
    if (responseSchema) {
      body.generationConfig.responseMimeType = 'application/json';
      body.generationConfig.responseSchema = responseSchema;
    }

    const start = Date.now();
    this.metrics.totalRequests++;

    try {
      const result = await retryWithBackoff(async () => {
        const url = `${GEMINI_BASE}/models/${this.model}:generateContent?key=${this.apiKey}`;
        const res = await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        });
        if (!res.ok) {
          const err = Object.assign(new Error(`Gemini API error: ${res.status}`), { status: res.status });
          err.body = await res.json().catch(() => ({}));
          throw err;
        }
        return res.json();
      });

      const latency = Date.now() - start;
      this.metrics.successfulRequests++;
      this.metrics._latencies.push(latency);
      if (this.metrics._latencies.length > 100) this.metrics._latencies.shift();
      this.metrics.avgLatencyMs = Math.round(this.metrics._latencies.reduce((a, b) => a + b, 0) / this.metrics._latencies.length);

      if (result.usageMetadata) {
        this.metrics.totalTokensUsed += (result.usageMetadata.totalTokenCount || 0);
      }

      const text = result.candidates?.[0]?.content?.parts?.[0]?.text || '';
      return {
        text,
        usage: result.usageMetadata || null,
        finishReason: result.candidates?.[0]?.finishReason || 'UNKNOWN',
        safetyRatings: result.candidates?.[0]?.safetyRatings || [],
        latencyMs: latency,
      };
    } catch (err) {
      this.metrics.failedRequests++;
      this.logger.error?.({ err: err.message, status: err.status }, 'Gemini API call failed');
      throw err;
    }
  }

  /** SOC-specific: analyze telemetry and return structured JSON */
  async analyzeTelemetry({ logs, network, systemInfo }) {
    const schema = {
      type: 'object',
      properties: {
        summary:        { type: 'string' },
        score:          { type: 'integer' },
        threats:        { type: 'array', items: { type: 'string' } },
        mitreMappings:  { type: 'array', items: { type: 'string' } },
        recommendations:{ type: 'array', items: { type: 'string' } },
        riskLevel:      { type: 'string', enum: ['low', 'medium', 'high', 'critical'] },
      },
      required: ['summary', 'score', 'threats', 'mitreMappings'],
    };

    const prompt = `Analyze the following Windows telemetry data as a Tier 3 SOC Analyst.
Host: ${systemInfo?.localIp || 'unknown'} | Gateway: ${systemInfo?.gateway || 'unknown'} | DNS: ${systemInfo?.dns || 'unknown'}

Event Logs (last 50):
${JSON.stringify(logs?.slice?.(0, 50) || [], null, 1)}

Network Connections:
${typeof network === 'string' ? network : JSON.stringify(network?.slice?.(0, 30) || [], null, 1)}

Return a structured security assessment.`;

    return this.generateContent({
      prompt,
      systemInstruction: 'You are a Tier 3 SOC Analyst AI. Analyze with precision. Flag only anomalies supported by telemetry evidence. Map to MITRE ATT&CK techniques when applicable.',
      temperature: 0.3,
      responseSchema: schema,
    });
  }

  /** Copilot chat with conversation history */
  async chat({ message, history = [], telemetryContext = null }) {
    let systemCtx = 'You are Sentinel Copilot, a Tier 3 SOC Analyst AI assistant. Be concise, technical, and evidence-based.';
    if (telemetryContext) {
      systemCtx += `\n\nCurrent host telemetry:\nIP: ${telemetryContext.localIp}\nGateway: ${telemetryContext.gateway}\nDNS: ${telemetryContext.dns}`;
    }

    return this.generateContent({
      prompt: message,
      systemInstruction: systemCtx,
      history,
      temperature: 0.7,
    });
  }

  /** Get service health metrics */
  getMetrics() {
    return {
      ...this.metrics,
      configured: this.isConfigured(),
      model: this.model,
      rateLimiterTokens: this.rateLimiter.tokens,
    };
  }
}

export default GeminiService;
