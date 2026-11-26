// Timestamp formatting shared by server and client.
//
// `Intl` reads the runtime's locale and time zone, so Node and a browser can
// format the SAME instant differently (en-US vs en-GB order, the server's zone
// vs the viewer's). React reports that as a hydration mismatch and refuses to
// patch it up, so both are pinned: en-GB, UTC, and h23 so midnight is 00:00, not
// 24:00. Stored timestamps go through here, never toLocaleString()/slice().
const DATE = new Intl.DateTimeFormat('en-GB', {
  timeZone: 'UTC',
  year: 'numeric',
  month: 'short',
  day: '2-digit',
});
const TIME = new Intl.DateTimeFormat('en-GB', {
  timeZone: 'UTC',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hourCycle: 'h23',
});

/** ISO string, epoch milliseconds, or Date — whatever a row or the API hands over. */
type Stamp = string | number | Date;

const parse = (value: Stamp): Date | null => {
  const d = value instanceof Date ? value : new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
};

/** "21 Nov 2026" — for dates where the time adds nothing. */
export function fmtUtcDate(value: Stamp): string {
  const d = parse(value);
  return d ? DATE.format(d) : String(value);
}

/** "17:13:32 UTC" — for a timestamp on a row that already carries the date. */
export function fmtUtcTime(value: Stamp): string {
  const d = parse(value);
  return d ? `${TIME.format(d)} UTC` : String(value);
}

/** "21 Nov 2026, 17:13:32 UTC" — identical on every runtime. */
export function fmtUtcDateTime(value: Stamp): string {
  const d = parse(value);
  return d ? `${DATE.format(d)}, ${TIME.format(d)} UTC` : String(value);
}
