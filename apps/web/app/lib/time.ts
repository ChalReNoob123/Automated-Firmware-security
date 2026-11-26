// Timestamp formatting shared by server and client.
//
// `Intl` reads the runtime's locale and time zone, so Node on the server and a
// browser can format the SAME ISO string differently (en-US vs en-GB date order,
// the server's zone vs the viewer's). React reports that as a hydration mismatch
// and will not patch it up, so both inputs are pinned: en-GB for day-first,
// unambiguous dates, UTC for the zone, and h23 so midnight is 00:00, never 24:00.
const DATE_TIME = new Intl.DateTimeFormat('en-GB', {
  timeZone: 'UTC',
  year: 'numeric',
  month: 'short',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hourCycle: 'h23',
});

/** "21 Nov 2026, 17:13:32 UTC" — identical on every runtime. */
export function fmtUtcDateTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `${DATE_TIME.format(d)} UTC`;
}
