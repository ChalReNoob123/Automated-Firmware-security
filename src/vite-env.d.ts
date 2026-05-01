/// <reference types="vite/client" />

// Gap #24: All API config is driven by env vars, never hardcoded
interface ImportMetaEnv {
  readonly VITE_API_URL: string;   // Backend base URL e.g. http://localhost:3001
  readonly VITE_WS_URL:  string;   // WebSocket base URL e.g. ws://localhost:3001
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
