/**
 * utils.js — Shared UI helpers for the Gavel dashboard.
 *
 * Consolidates HTML escaping, time formatting, and status display
 * functions used across dashboard.js and inspector.js.
 *
 * ES module — no build step, no external dependencies.
 */

/**
 * Escape HTML entities to prevent XSS.
 * @param {*} s - value to escape
 * @returns {string}
 */
export function esc(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Format an ISO timestamp as a relative "time ago" string.
 * @param {string} iso - ISO 8601 timestamp
 * @returns {string}
 */
export function timeAgo(iso) {
  if (!iso) return '';
  const now = Date.now();
  const then = new Date(iso).getTime();
  if (isNaN(then)) return '';
  const diff = Math.max(0, now - then);
  const secs = Math.floor(diff / 1000);
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

/**
 * Format an ISO timestamp as absolute date string (YYYY-MM-DD HH:MM:SS).
 * @param {string} iso - ISO 8601 timestamp
 * @returns {string}
 */
export function fmtDate(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '';
  return d.toISOString().replace('T', ' ').slice(0, 19);
}

/**
 * Render an inline status dot span for a given agent status.
 * @param {string} status - ACTIVE, IDLE, SUSPENDED, DEAD
 * @returns {string} HTML string
 */
export function statusDot(status) {
  const colors = {
    ACTIVE: 'var(--green)', IDLE: 'var(--text3)',
    SUSPENDED: 'var(--amber)', DEAD: 'var(--red)',
  };
  return `<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${colors[status] || 'var(--text3)'};margin-right:6px;"></span>`;
}

/**
 * Render an inline chip span for a status value.
 * @param {string} status
 * @returns {string} HTML string
 */
export function statusChip(status) {
  const cls = (status || '').toLowerCase();
  return `<span class="chip chip-${cls}" style="font-size:10px;">${esc(status)}</span>`;
}

/**
 * Map a status string to a CSS color variable name.
 * @param {string} status
 * @returns {string} CSS color value
 */
export function statusColor(status) {
  const s = (status || '').toUpperCase();
  if (s === 'ACTIVE') return 'var(--green)';
  if (s === 'IDLE') return 'var(--amber)';
  if (s === 'SUSPENDED') return 'var(--red)';
  if (s === 'DEAD') return 'var(--text3)';
  if (s === 'APPROVED' || s === 'COMPLETED') return 'var(--green)';
  if (s === 'ESCALATED' || s === 'PENDING') return 'var(--amber)';
  if (s === 'DENIED') return 'var(--red)';
  if (s === 'TIMED_OUT') return 'var(--text3)';
  return 'var(--text2)';
}

/**
 * Return a CSS class for a chip based on status.
 * @param {string} status
 * @returns {string} CSS class name
 */
export function statusChipClass(status) {
  const s = (status || '').toUpperCase();
  if (s === 'APPROVED' || s === 'COMPLETED') return 'chip-green';
  if (s === 'ESCALATED' || s === 'PENDING') return 'chip-amber';
  if (s === 'DENIED') return 'chip-red';
  if (s === 'TIMED_OUT') return 'chip-accent';
  return 'chip-accent';
}

/**
 * Render an autonomy tier chip.
 * @param {number} tier - 0-3
 * @returns {string} HTML string
 */
export function tierChip(tier) {
  const names = ['SUPERVISED', 'SEMI-AUTO', 'AUTONOMOUS', 'CRITICAL'];
  return `<span class="chip">${names[tier] || 'T' + tier}</span>`;
}

/**
 * Render an inline trust score bar with numeric label.
 * @param {number} score - 0-1000
 * @returns {string} HTML string
 */
export function trustBar(score) {
  const pct = Math.round((score / 1000) * 100);
  return `<span style="display:inline-block;width:80px;height:8px;background:var(--border);border-radius:4px;overflow:hidden;vertical-align:middle;">
    <span style="display:block;width:${pct}%;height:100%;background:var(--accent);border-radius:4px;"></span>
  </span> <span style="font-size:12px;color:var(--text2);font-family:'JetBrains Mono',monospace;margin-left:4px;">${score}</span>`;
}

/**
 * Truncate a hash to first 12 characters for display.
 * @param {string} h
 * @returns {string}
 */
export function hashPreview(h) {
  if (!h) return '';
  return String(h).slice(0, 12);
}
