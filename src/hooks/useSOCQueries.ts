/**
 * useSOCQueries — React Query hooks for all SOC API data
 * 
 * Replaces raw useEffect + apiGet polling with @tanstack/react-query:
 * - Automatic caching & deduplication
 * - Stale-while-revalidate for instant UI
 * - Retry with exponential backoff
 * - Background refetching
 * - Query invalidation on mutations
 */

import { useQuery } from '@tanstack/react-query';
import { apiGet } from '../utils/api';
import { useSOCStore } from '../stores/socStore';

/* ── System Stats ── */
export function useSystemStats() {
  const isAuthenticated = useSOCStore((s) => s.isAuthenticated);
  const setSystemStats = useSOCStore((s) => s.setSystemStats);
  const pushStatsHistory = useSOCStore((s) => s.pushStatsHistory);

  return useQuery({
    queryKey: ['system-stats'],
    queryFn: async () => {
      const stats: any = await apiGet('/api/system/stats', { cacheMs: 0, force: true });
      setSystemStats(stats);
      pushStatsHistory({
        ts: stats.timestamp,
        cpu: parseFloat(stats.cpu),
        mem: parseFloat(stats.memory),
      });
      useSOCStore.getState().recordTelemetryEvent('system_stats', { systemStats: 1 });
      return stats;
    },
    enabled: isAuthenticated,
    refetchInterval: 10_000,
    staleTime: 8_000,
    retry: 2,
    retryDelay: (attempt) => Math.min(1000 * 2 ** attempt, 10000),
  });
}

/* ── Permissions ── */
export function usePermissions() {
  const isAuthenticated = useSOCStore((s) => s.isAuthenticated);
  const setPermissions = useSOCStore((s) => s.setPermissions);

  return useQuery({
    queryKey: ['permissions'],
    queryFn: async () => {
      const perms: any = await apiGet('/api/system/permissions', { cacheMs: 0, force: true });
      setPermissions(perms);
      useSOCStore.getState().recordTelemetryEvent('permissions_query', { permissions: 1 });
      return perms;
    },
    enabled: isAuthenticated,
    refetchInterval: 30_000,
    staleTime: 25_000,
    retry: 1,
  });
}

/* ── Plugin Data (less frequent) ── */
export function usePluginData() {
  const isAuthenticated = useSOCStore((s) => s.isAuthenticated);

  return useQuery({
    queryKey: ['plugins'],
    queryFn: async () => {
      const data: any = await apiGet('/api/plugins', { cacheMs: 0, force: true });
      if (data?.plugins) {
        const store = useSOCStore.getState();
        store.setSystemStats({ ...store.systemStats, plugins: data.plugins.length });
        store.recordTelemetryEvent('plugins_query', { plugins: data.plugins.length });
      }
      return data;
    },
    enabled: isAuthenticated,
    refetchInterval: 30_000,
    staleTime: 25_000,
    retry: 1,
  });
}
