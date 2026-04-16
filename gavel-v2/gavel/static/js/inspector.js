/**
 * inspector.js — Right-side detail panel for the Gavel dashboard.
 *
 * Renders agent, chain, and engine detail views when a node is selected
 * in the topology canvas or elsewhere. Subscribes to GavelState.selection.
 *
 * ES module — no build step, no external dependencies.
 */

import { GavelState } from './state.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Escape HTML entities to prevent XSS. */
function esc(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Format an ISO timestamp as a relative "time ago" string. */
function timeAgo(iso) {
  if (!iso) return 'unknown';
  const now = Date.now();
  const then = new Date(iso).getTime();
  if (isNaN(then)) return 'unknown';
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

/** Format an ISO timestamp as absolute date string. */
function fmtDate(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '';
  return d.toISOString().replace('T', ' ').slice(0, 19);
}

/** Truncate a hash to first 12 chars. */
function hashPreview(h) {
  if (!h) return '';
  return String(h).slice(0, 12);
}

/** Map agent/chain status to a CSS color variable name. */
function statusColor(status) {
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

/** Return chip CSS class for chain status. */
function statusChipClass(status) {
  const s = (status || '').toUpperCase();
  if (s === 'APPROVED' || s === 'COMPLETED') return 'chip-green';
  if (s === 'ESCALATED' || s === 'PENDING') return 'chip-amber';
  if (s === 'DENIED') return 'chip-red';
  if (s === 'TIMED_OUT') return 'chip-accent';
  return 'chip-accent';
}

/** Autonomy tier label. */
function tierLabel(tier) {
  const labels = {
    0: 'SUPERVISED',
    1: 'GUIDED',
    2: 'AUTONOMOUS',
    3: 'SYSTEM',
  };
  return labels[tier] ?? `TIER ${tier}`;
}

// ---------------------------------------------------------------------------
// Section header helper
// ---------------------------------------------------------------------------

function sectionHeader(title) {
  return `<div style="font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:1px;color:var(--text3);margin:16px 0 8px;padding-bottom:4px;border-bottom:1px solid var(--border)">${esc(title)}</div>`;
}

function kvRow(label, value) {
  return `<div style="display:flex;justify-content:space-between;align-items:center;padding:3px 0;font-size:12px">
    <span style="color:var(--text3)">${esc(label)}</span>
    <span style="color:var(--text);font-family:'JetBrains Mono',monospace;font-size:11px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(value)}">${esc(value)}</span>
  </div>`;
}

// ---------------------------------------------------------------------------
// Agent detail renderer
// ---------------------------------------------------------------------------

function renderAgent(agentId) {
  const agent = GavelState.agents[agentId];
  if (!agent) {
    return `<div class="empty-state">Agent not found: ${esc(agentId)}</div>`;
  }

  const name = agent.display_name || agentId;
  const status = (agent.status || 'IDLE').toUpperCase();
  const trust = agent.trust_score ?? 500;
  const tier = agent.autonomy_tier ?? 0;
  const pct = Math.min(100, Math.max(0, (trust / 1000) * 100));

  // Capabilities
  const caps = agent.capabilities || agent.tools || [];
  const capsList = Array.isArray(caps) ? caps : [];

  // Find related chains
  const relatedChains = [];
  for (const [chainId, chain] of Object.entries(GavelState.chains)) {
    const roster = chain.roster || {};
    if (agentId in roster) {
      relatedChains.push({ chainId, status: chain.status || 'PENDING' });
    }
  }

  return `
    <div style="margin-bottom:12px">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
        <span style="width:10px;height:10px;border-radius:50%;background:${statusColor(status)};flex-shrink:0;${status === 'ACTIVE' ? 'box-shadow:0 0 6px ' + statusColor(status) : ''}"></span>
        <span style="font-size:14px;font-weight:600">${esc(name)}</span>
      </div>
      <div style="font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--text3)">${esc(agentId)}</div>
    </div>

    ${sectionHeader('Identity')}
    ${kvRow('DID', agent.did || 'not assigned')}
    ${kvRow('Type', agent.agent_type || 'unknown')}
    ${kvRow('Owner', agent.owner || 'unassigned')}
    ${kvRow('Status', status)}

    ${sectionHeader('Trust & Autonomy')}
    <div style="margin:6px 0">
      <div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:4px">
        <span style="color:var(--text3)">Trust</span>
        <span style="font-family:'JetBrains Mono',monospace;color:var(--text)">${trust}/1000</span>
      </div>
      <div style="height:6px;background:var(--surface2);border-radius:3px;overflow:hidden">
        <div style="height:100%;width:${pct}%;background:var(--accent);border-radius:3px;transition:width 0.3s"></div>
      </div>
    </div>
    ${kvRow('Tier', tierLabel(tier) + ' (' + tier + ')')}

    ${capsList.length > 0 ? `
      ${sectionHeader('Capabilities')}
      <div style="display:flex;flex-wrap:wrap;gap:4px">
        ${capsList.map(c => `<span class="chip chip-accent">${esc(c)}</span>`).join('')}
      </div>
    ` : ''}

    ${sectionHeader('Activity')}
    ${kvRow('Current', agent.current_activity || 'Idle')}
    ${kvRow('Last heartbeat', agent.last_heartbeat ? timeAgo(agent.last_heartbeat) : 'never')}

    ${relatedChains.length > 0 ? `
      ${sectionHeader('Related Chains')}
      ${relatedChains.map(rc => `
        <div class="inspector-jump" data-type="chain" data-id="${esc(rc.chainId)}" style="display:flex;align-items:center;justify-content:space-between;padding:5px 8px;margin-bottom:3px;background:var(--surface2);border-radius:4px;cursor:pointer;transition:background 0.15s;font-size:11px" onmouseover="this.style.background='var(--border)'" onmouseout="this.style.background='var(--surface2)'">
          <span style="font-family:'JetBrains Mono',monospace;color:var(--accent)">${esc(rc.chainId.slice(0, 12))}</span>
          <span style="display:flex;align-items:center;gap:6px">
            <span class="chip ${statusChipClass(rc.status)}">${esc(rc.status)}</span>
            <span style="color:var(--text3)">&#9656;</span>
          </span>
        </div>
      `).join('')}
    ` : ''}
  `;
}

// ---------------------------------------------------------------------------
// Chain detail renderer
// ---------------------------------------------------------------------------

function renderChain(chainId) {
  const chain = GavelState.chains[chainId];
  if (!chain) {
    return `<div class="empty-state">Chain not found: ${esc(chainId)}</div>`;
  }

  const status = (chain.status || 'PENDING').toUpperCase();
  const integrity = chain.integrity !== false;
  const roster = chain.roster || {};
  const evidence = chain.evidence || [];

  // Integrity badge
  const integrityBadge = integrity
    ? `<span style="color:var(--green);font-size:11px;font-weight:600">&#10003; verified</span>`
    : `<span style="color:var(--red);font-size:11px;font-weight:600">&#10007; TAMPERED</span>`;

  // Roster section
  const rosterHtml = Object.entries(roster).map(([agentId, role]) => `
    <div class="inspector-jump" data-type="agent" data-id="${esc(agentId)}" style="display:flex;align-items:center;justify-content:space-between;padding:5px 8px;margin-bottom:3px;background:var(--surface2);border-radius:4px;cursor:pointer;transition:background 0.15s;font-size:11px" onmouseover="this.style.background='var(--border)'" onmouseout="this.style.background='var(--surface2)'">
      <span style="font-family:'JetBrains Mono',monospace;color:var(--text)">${esc(agentId.slice(0, 18))}</span>
      <span style="display:flex;align-items:center;gap:6px">
        <span style="color:var(--text3)">${esc(role)}</span>
        <span style="color:var(--text3)">&#9656;</span>
      </span>
    </div>
  `).join('');

  // Timeline
  const timelineHtml = evidence.map((ev, i) => {
    const evType = ev.event_type || ev.type || 'UNKNOWN';
    const actor = ev.actor || ev.agent_id || '';
    const role = ev.role || '';
    const hash = ev.hash || ev.event_hash || '';
    const ts = ev.timestamp || '';
    const dotColor = statusColor(evType === 'APPROVAL_GRANTED' ? 'APPROVED' : evType === 'ESCALATED' ? 'ESCALATED' : evType === 'DENIED' ? 'DENIED' : 'ACTIVE');
    const isLast = i === evidence.length - 1;

    // Extract relevant payload details
    let detail = '';
    const payload = ev.payload || ev.data || {};
    if (evType === 'POLICY_EVAL' || evType === 'policy_eval') {
      const risk = payload.risk_score ?? payload.risk ?? '';
      const evalTier = payload.tier ?? '';
      if (risk !== '' || evalTier !== '') {
        detail = `<div style="font-size:10px;color:var(--text2);margin-top:2px">Risk: ${esc(String(risk))}${evalTier ? ' Tier: ' + esc(String(evalTier)) : ''}</div>`;
      }
    } else if (evType === 'APPROVAL_GRANTED' || evType === 'ESCALATED' || evType === 'DENIED') {
      const rationale = payload.rationale || payload.reason || '';
      if (rationale) {
        detail = `<div style="font-size:10px;color:var(--text2);margin-top:2px;font-style:italic">"${esc(rationale)}"</div>`;
      }
    } else if (evType === 'EXECUTION_TOKEN') {
      const tokenId = payload.token_id || '';
      const expires = payload.expires || '';
      if (tokenId) detail += `<div style="font-size:10px;font-family:'JetBrains Mono',monospace;color:var(--text2);margin-top:2px">${esc(tokenId)}</div>`;
      if (expires) detail += `<div style="font-size:10px;color:var(--text3);margin-top:1px">Expires: ${esc(fmtDate(expires) || expires)}</div>`;
    }

    return `
      <div style="display:flex;gap:10px;position:relative;padding-bottom:${isLast ? '4' : '16'}px">
        <div style="display:flex;flex-direction:column;align-items:center;flex-shrink:0;width:12px">
          <div style="width:10px;height:10px;border-radius:50%;background:${dotColor};flex-shrink:0;z-index:1"></div>
          ${!isLast ? '<div style="width:2px;flex:1;background:var(--border);margin-top:2px"></div>' : ''}
        </div>
        <div style="flex:1;min-width:0">
          <div style="font-size:11px;font-weight:600;color:var(--text)">${esc(evType)}</div>
          ${actor ? `<div style="font-size:10px;color:var(--text2)">${esc(actor)}${role ? ' (' + esc(role) + ')' : ''}</div>` : ''}
          ${detail}
          ${hash ? `<div style="font-size:9px;font-family:'JetBrains Mono',monospace;color:var(--text3);margin-top:2px">${esc(hashPreview(hash))}</div>` : ''}
          ${ts ? `<div style="font-size:9px;color:var(--text3)">${fmtDate(ts)}</div>` : ''}
        </div>
      </div>
    `;
  }).join('');

  return `
    <div style="margin-bottom:12px">
      <div style="font-size:14px;font-weight:600;margin-bottom:4px">Chain ${esc(chainId.slice(0, 12))}</div>
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
        <span class="chip ${statusChipClass(status)}">${esc(status)}</span>
        ${integrityBadge}
      </div>
    </div>

    ${Object.keys(roster).length > 0 ? `
      ${sectionHeader('Roster')}
      ${rosterHtml}
    ` : ''}

    ${evidence.length > 0 ? `
      ${sectionHeader('Timeline')}
      <div style="padding:8px 0">${timelineHtml}</div>
    ` : `
      ${sectionHeader('Timeline')}
      <div class="empty-state">No events recorded yet</div>
    `}
  `;
}

// ---------------------------------------------------------------------------
// Engine detail renderer
// ---------------------------------------------------------------------------

async function renderEngine() {
  const status = await GavelState.fetchStatus();
  const agentCount = Object.keys(GavelState.agents).length;
  const activeCount = Object.values(GavelState.agents).filter(a => (a.status || '').toUpperCase() === 'ACTIVE').length;
  const chainCount = Object.keys(GavelState.chains).length;

  // Fetch constitution for invariant count
  let invariantCount = '?';
  let cedarCount = '?';
  try {
    const res = await fetch('/v1/constitution');
    if (res.ok) {
      const data = await res.json();
      const invariants = data.invariants || data.articles || [];
      invariantCount = Array.isArray(invariants) ? invariants.length : '?';
      cedarCount = data.cedar_rules?.length ?? data.cedar_count ?? '?';
    }
  } catch (_) { /* ignore */ }

  const blockedPatterns = [
    'rm -rf', 'drop table', 'delete from',
    'format c:', 'truncate', 'shutdown',
  ];

  return `
    <div style="margin-bottom:12px">
      <div style="display:flex;align-items:center;gap:8px">
        <span style="font-size:18px;color:var(--accent)">&#11043;</span>
        <span style="font-size:14px;font-weight:600">Policy Engine</span>
      </div>
    </div>

    ${sectionHeader('Constitution')}
    ${kvRow('Invariants', String(invariantCount))}
    ${kvRow('Cedar Rules', cedarCount + ' loaded')}

    ${sectionHeader('Current State')}
    ${kvRow('Active chains', String(chainCount))}
    ${kvRow('Total agents', String(agentCount))}
    ${kvRow('Active agents', String(activeCount))}

    ${sectionHeader('Blocked Patterns')}
    <div style="display:flex;flex-direction:column;gap:3px">
      ${blockedPatterns.map(p => `
        <div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--red);padding:3px 8px;background:var(--red-dim);border-radius:3px">${esc(p)}</div>
      `).join('')}
    </div>
  `;
}

// ---------------------------------------------------------------------------
// InspectorPanel class
// ---------------------------------------------------------------------------

export class InspectorPanel {
  /**
   * @param {string} panelSelector - CSS selector for the panel root, e.g. '#inspector-panel'
   */
  constructor(panelSelector) {
    this._panel = document.querySelector(panelSelector);
    this._body = this._panel.querySelector('#inspector-body');
    this._closeBtn = this._panel.querySelector('#inspector-close');
    this._currentKey = null; // tracks "type:id" to avoid redundant re-renders

    // Close button
    this._closeBtn.addEventListener('click', () => this.close());

    // Click-outside-to-close
    document.addEventListener('click', (e) => {
      if (!this._panel.classList.contains('open')) return;
      if (this._panel.contains(e.target)) return;
      // Don't close if click was on a topology node or agent card (those trigger selection)
      if (e.target.closest('[data-agent-id], [data-chain-id], .agent-card, .chain-card, .topo-node')) return;
      this.close();
    });

    // Delegate jump-link clicks inside the inspector body
    this._body.addEventListener('click', (e) => {
      const jump = e.target.closest('.inspector-jump');
      if (!jump) return;
      const type = jump.dataset.type;
      const id = jump.dataset.id;
      if (type && id) {
        GavelState.setSelection(type, id);
      }
    });
  }

  /**
   * Update the panel based on current state. Called by state subscriber.
   * @param {object} state - GavelState
   */
  update(state) {
    if (!state.selection) {
      this._close();
      return;
    }

    const key = state.selection.type + ':' + state.selection.id;
    if (key === this._currentKey && this._panel.classList.contains('open')) {
      // Same selection, still open — re-render to pick up data changes
      // but only for non-async renders
      if (state.selection.type !== 'engine') {
        this._renderSync(state.selection);
      }
      return;
    }

    this._currentKey = key;
    this._render(state.selection);
    this._open();
  }

  /** Open the panel (add CSS class). */
  open() { this._open(); }

  /** Close the panel and clear selection. */
  close() {
    this._close();
    GavelState.clearSelection();
  }

  // -- Internal methods --

  _open() {
    this._panel.classList.add('open');
  }

  _close() {
    this._panel.classList.remove('open');
    this._currentKey = null;
  }

  _renderSync(selection) {
    if (selection.type === 'agent') {
      this._body.innerHTML = renderAgent(selection.id);
    } else if (selection.type === 'chain') {
      this._body.innerHTML = renderChain(selection.id);
    }
    // engine is async, skip in sync path
  }

  async _render(selection) {
    if (selection.type === 'agent') {
      this._body.innerHTML = renderAgent(selection.id);
    } else if (selection.type === 'chain') {
      this._body.innerHTML = renderChain(selection.id);
    } else if (selection.type === 'engine') {
      this._body.innerHTML = '<div class="empty-state">Loading...</div>';
      this._body.innerHTML = await renderEngine();
    } else {
      this._body.innerHTML = `<div class="empty-state">Unknown selection type: ${esc(selection.type)}</div>`;
    }
  }
}
