import { readdirSync } from 'node:fs';
import path from 'node:path';

// SF://REEL — one clean request that reports which photographic plates exist in
// public/devices (reel-1/2/3.{jpg,png,webp}). This replaces the device reel's
// old client-side HEAD probes, which logged a burst of expected-but-noisy 404s
// on every page load (round-16a: zero console noise for the drop-in flow).
// GET handlers are dynamic by default in this Next version, so a plate dropped
// into public/devices after a build is picked up on the next page visit —
// the drop-in convention is unchanged.
export async function GET() {
  const dir = path.join(process.cwd(), 'public', 'devices');
  const exts = ['.jpg', '.png', '.webp'];
  try {
    const files = new Set(readdirSync(dir));
    const photos: string[] = [];
    for (let i = 1; i <= 3; i++) {
      for (const ext of exts) {
        if (files.has(`reel-${i}${ext}`)) {
          photos.push(`/devices/reel-${i}${ext}`);
          break;
        }
      }
    }
    return Response.json({ photos });
  } catch {
    // devices dir missing — the reel simply runs all-procedural
    return Response.json({ photos: [] });
  }
}
