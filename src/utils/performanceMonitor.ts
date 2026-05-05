/**
 * Performance Monitor & Optimization Utilities
 * Production-grade performance tracking and optimization
 */

export type PerformanceMetrics = {
  timestamp: number;
  memoryUsage: number;
  cpuUsage: number;
  renderTime: number;
  fps: number;
  networkLatency: number;
  activeConnections: number;
  eventProcessingRate: number;
};

export type SystemHealth = {
  status: "healthy" | "degraded" | "critical";
  uptime: number;
  lastRestart: number;
  errors: number;
  warnings: number;
  avgResponseTime: number;
  throughput: number;
};

class PerformanceMonitor {
  private metrics: PerformanceMetrics[] = [];
  private maxMetrics = 100;
  private frameCount = 0;
  private lastFrameTime = performance.now();
  private fps = 60;
  private isRunning = false;
  private rAFId: number | null = null;
  private memoryTimerId: ReturnType<typeof setTimeout> | null = null;
  
  // Singleton pattern
  private static instance: PerformanceMonitor;
  public static getInstance(): PerformanceMonitor {
    if (!PerformanceMonitor.instance) {
      PerformanceMonitor.instance = new PerformanceMonitor();
    }
    return PerformanceMonitor.instance;
  }

  public startMonitoring(): void {
    if (this.isRunning) return; // Guard against double-start
    this.isRunning = true;
    this.measureFPS();
    this.measureMemory();
  }

  public stopMonitoring(): void {
    this.isRunning = false;
    if (this.rAFId !== null) {
      cancelAnimationFrame(this.rAFId);
      this.rAFId = null;
    }
    if (this.memoryTimerId !== null) {
      clearTimeout(this.memoryTimerId);
      this.memoryTimerId = null;
    }
  }

  private measureFPS(): void {
    if (!this.isRunning) return;
    const now = performance.now();
    this.frameCount++;
    
    if (now >= this.lastFrameTime + 1000) {
      this.fps = this.frameCount;
      this.frameCount = 0;
      this.lastFrameTime = now;
    }
    
    this.rAFId = requestAnimationFrame(() => this.measureFPS());
  }

  private measureMemory(): void {
    if (!this.isRunning) return;
    if ("memory" in performance) {
      const mem = (performance as any).memory;
      if (mem) {
        const used = mem.usedJSHeapSize / 1048576; // MB
        this.recordMetric({
          timestamp: Date.now(),
          memoryUsage: used,
          cpuUsage: 0,
          renderTime: 0,
          fps: this.fps,
          networkLatency: 0,
          activeConnections: 0,
          eventProcessingRate: 0,
        });
      }
    }
    
    this.memoryTimerId = setTimeout(() => this.measureMemory(), 5000);
  }

  public recordMetric(metric: PerformanceMetrics): void {
    this.metrics.push(metric);
    if (this.metrics.length > this.maxMetrics) {
      this.metrics.shift();
    }
  }

  public getMetrics(): PerformanceMetrics[] {
    return [...this.metrics];
  }

  public getAverageFPS(): number {
    if (this.metrics.length === 0) return 60;
    const sum = this.metrics.reduce((acc, m) => acc + m.fps, 0);
    return Math.round(sum / this.metrics.length);
  }

  public getAverageMemory(): number {
    if (this.metrics.length === 0) return 0;
    const sum = this.metrics.reduce((acc, m) => acc + m.memoryUsage, 0);
    return Math.round((sum / this.metrics.length) * 100) / 100;
  }

  public getSystemHealth(): SystemHealth {
    const recent = this.metrics.slice(-10);
    const avgFps = recent.reduce((a, m) => a + m.fps, 0) / recent.length;
    const avgMem = recent.reduce((a, m) => a + m.memoryUsage, 0) / recent.length;
    
    let status: SystemHealth["status"] = "healthy";
    if (avgFps < 30 || avgMem > 512) status = "critical";
    else if (avgFps < 45 || avgMem > 256) status = "degraded";
    
    return {
      status,
      uptime: Date.now() - (performance.timeOrigin || 0),
      lastRestart: 0,
      errors: 0,
      warnings: status === "degraded" ? 1 : 0,
      avgResponseTime: 1000 / avgFps,
      throughput: avgFps,
    };
  }

  // Debounce function for performance
  public debounce<T extends (...args: any[]) => any>(
    func: T,
    wait: number
  ): (...args: Parameters<T>) => void {
    let timeout: NodeJS.Timeout;
    return (...args: Parameters<T>) => {
      clearTimeout(timeout);
      timeout = setTimeout(() => func(...args), wait);
    };
  }

  // Throttle function for performance
  public throttle<T extends (...args: any[]) => any>(
    func: T,
    limit: number
  ): (...args: Parameters<T>) => void {
    let inThrottle: boolean;
    return (...args: Parameters<T>) => {
      if (!inThrottle) {
        func(...args);
        inThrottle = true;
        setTimeout(() => (inThrottle = false), limit);
      }
    };
  }

  // Batch processing for large datasets
  public async processBatch<T, R>(
    items: T[],
    processor: (item: T) => R,
    batchSize = 100
  ): Promise<R[]> {
    const results: R[] = [];
    
    for (let i = 0; i < items.length; i += batchSize) {
      const batch = items.slice(i, i + batchSize);
      const batchResults = batch.map(processor);
      results.push(...batchResults);
      
      // Yield to main thread
      if (i + batchSize < items.length) {
        await new Promise(resolve => setTimeout(resolve, 0));
      }
    }
    
    return results;
  }
}

export const perfMonitor = PerformanceMonitor.getInstance();

// Memoization helper with TTL
export function memoizeWithTTL<T extends (...args: any[]) => any>(
  fn: T,
  ttl: number = 60000
): T {
  const cache = new Map<string, { value: ReturnType<T>; timestamp: number }>();
  
  return ((...args: Parameters<T>): ReturnType<T> => {
    const key = JSON.stringify(args);
    const cached = cache.get(key);
    const now = Date.now();
    
    if (cached && now - cached.timestamp < ttl) {
      return cached.value;
    }
    
    const result = fn(...args);
    cache.set(key, { value: result, timestamp: now });
    
    // Cleanup old entries
    if (cache.size > 100) {
      const oldest = cache.entries().next().value;
      if (oldest) cache.delete(oldest[0]);
    }
    
    return result;
  }) as T;
}

// Virtual scrolling calculator
export function getVirtualScrollItems(
  itemHeight: number,
  containerHeight: number,
  scrollTop: number,
  totalItems: number
): { startIndex: number; endIndex: number; offsetY: number } {
  const overscan = 5;
  const startIndex = Math.max(0, Math.floor(scrollTop / itemHeight) - overscan);
  const visibleCount = Math.ceil(containerHeight / itemHeight);
  const endIndex = Math.min(totalItems, startIndex + visibleCount + overscan * 2);
  const offsetY = startIndex * itemHeight;
  
  return { startIndex, endIndex, offsetY };
}

// Data export utilities
export function exportToCSV<T extends Record<string, any>>(
  data: T[],
  filename: string
): void {
  if (data.length === 0) return;
  
  const headers = Object.keys(data[0]);
  const csv = [
    headers.join(","),
    ...data.map(row =>
        headers.map(h => {
        const val = row[h];
        if (typeof val === "string" && val.includes(",")) {
          return `"${val.replace(/"/g, '""')}"`;
        }
        return val;
      }).join(",")
    ),
  ].join("\n");
  
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  link.click();
  URL.revokeObjectURL(link.href);
}

export function exportToJSON<T>(data: T, filename: string): void {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  link.click();
  URL.revokeObjectURL(link.href);
}

export function exportToPDF(
  content: string,
  filename: string
): void {
  // In production, use a library like jsPDF
  // For now, export as formatted text
  const blob = new Blob([content], { type: "text/plain;charset=utf-8;" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = filename.replace(".pdf", ".txt");
  link.click();
  URL.revokeObjectURL(link.href);
}
