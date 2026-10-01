import dayjs from 'dayjs';
import utc from 'dayjs/plugin/utc';
import timezone from 'dayjs/plugin/timezone';

dayjs.extend(utc);
dayjs.extend(timezone);

// Runtime timezone: fetched from /api/config at app start; falls back
// to build-time VITE_DISPLAY_TZ, then Europe/Moscow.
let DISPLAY_TZ = import.meta.env.VITE_DISPLAY_TZ || 'Europe/Moscow';

const TZ_SHORT = { 'Europe/Moscow': 'MSK' };

// Live binding: VpnPage / AdPage / MultiPage import TZ_LABEL for
// column titles - the value updates when the backend timezone loads,
// without touching those pages.
export let TZ_LABEL = TZ_SHORT[DISPLAY_TZ] || DISPLAY_TZ;

export function setDisplayTz(tz) {
  if (tz && tz !== DISPLAY_TZ) {
    DISPLAY_TZ = tz;
    TZ_LABEL = TZ_SHORT[DISPLAY_TZ] || DISPLAY_TZ;
  }
}

export async function loadDisplayTz() {
  try {
    const r = await fetch('/api/config');
    if (r.ok) {
      const c = await r.json();
      setDisplayTz(c.display_tz);
    }
  } catch { /* keep fallback */ }
}

export const fmtTime = (utcStr) => {
  if (!utcStr) return '—';
  const d = dayjs.utc(utcStr, 'YYYY-MM-DD HH:mm:ss');
  if (!d.isValid()) return utcStr;
  return d.tz(DISPLAY_TZ).format('YYYY-MM-DD HH:mm');
};