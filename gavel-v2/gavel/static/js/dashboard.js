/**
 * Dashboard panel logic for Gavel's non-topology tabs.
 *
 * Handles the Operations 6-panel grid, Agents & Enrollment table,
 * Governance Timeline, Incidents, Compliance, and Constitution tabs.
 * Extracted from the original monolithic dashboard.html.
 *
 * This is a minimal initial version — the topology canvas and inspector
 * are the primary focus. These panels will be progressively enhanced.
 */

import { GavelState } from './state.js';

function statusDot(status) {
  const colors = {
    ACTIVE: 'var(--green)', IDLE: 'var(--text3)',
    SUSPENDED: 'var(--amber)', DEAD: 'var(--red)',
  };
  return `<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${colors[status] || 'var(--text3)'};margin-right:6px;"></span>`;
}

function tierChip(tier) {
  const names = ['SUPERVISED', 'SEMI-AUTO', 'AUTONOMOUS', 'CRITICAL'];
  return `<span class="chip">${names[tier] || 'T' + tier}</span>`;
}

function trustBar(score) {
  const pct = Math.round((score / 1000) * 100);
  return `<span class="trust-bar" style="display:inline-block;width:60px;height:6px;background:var(--border);border-radius:3px;overflow:hidden;vertical-align:middle;">
    <span style="display:block;width:${pct}%;height:100%;background:var(--accent);border-radius:3px;"></span>
  </span> <span style="font-size:11px;color:var(--text2);font-family:'JetBrains Mono',monospace;">${score}</span>`;
}

function renderAgentRoster(agents) {
  const el = document.getElementById('agent-roster-list');
  if (!el) return;
  const list = Object.values(agents);
  document.getElementById('agent-roster-count')?.setAttribute('data-count', list.length);

  if (list.length === 0) {
    el.innerHTML = '<div class="empty">No agents registered</div>';
    return;
  }

  el.innerHTML = list.map(a => `
    <div class="agent-card">
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <strong>${statusDot(a.status)}${a.display_name || a.agent_id}</strong>
        <span class="chip chip-${(a.status || '').toLowerCase()}">${a.status}</span>
      </div>
      <div style="font-size:11px;color:var(--text3);margin-top:2px;">${a.agent_id}</div>
      <div style="margin-top:4px;">${tierChip(a.autonomy_tier)} ${trustBar(a.trust_score)} <span class="chip">${a.agent_type || 'agent'}</span></div>
      <div style="font-size:11px;color:var(--text3);margin-top:4px;font-style:italic;">${a.current_activity || 'Idle'}</div>
    </div>
  `).join('');
}

function renderTopBarStats(agents) {
  const list = Object.values(agents);
  const active = list.filter(a => a.status === 'ACTIVE').length;
  const el = (id, val) => { const e = document.getElementById(id); if (e) e.textContent = val; };
  el('stat-agents', list.length);
  el('stat-chains', Object.keys(GavelState.chains).length);
}

function renderAgentsTable(agents) {
  const el = document.getElementById('agents-table-body');
  if (!el) return;
  const list = Object.values(agents);
  if (list.length === 0) {
    el.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text3);padding:24px;">No agents enrolled</td></tr>';
    return;
  }
  el.innerHTML = list.map(a => `
    <tr>
      <td>${statusDot(a.status)}${a.agent_id}</td>
      <td>${a.display_name || ''}</td>
      <td><span class="chip">${a.agent_type || 'agent'}</span></td>
      <td>${tierChip(a.autonomy_tier)}</td>
      <td>${trustBar(a.trust_score)}</td>
      <td style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text3);">${(a.did || '').substring(0, 20)}...</td>
      <td><span class="chip chip-${a.enrolled ? 'active' : 'idle'}">${a.enrolled ? 'ENROLLED' : 'PENDING'}</span></td>
      <td style="font-size:11px;color:var(--text3);">${a.owner || ''}</td>
    </tr>
  `).join('');
}

function renderKillSwitch(agents) {
  const el = document.getElementById('kill-switch-list');
  if (!el) return;
  const list = Object.values(agents);
  if (list.length === 0) {
    el.innerHTML = '<div class="empty">No agents to manage</div>';
    return;
  }
  el.innerHTML = list.map(a => `
    <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--border);">
      <span>${statusDot(a.status)}<strong>${a.display_name || a.agent_id}</strong>
        <span class="chip chip-${(a.status || '').toLowerCase()}" style="margin-left:8px;">${a.status}</span></span>
      <button class="kill-btn" data-agent="${a.agent_id}" style="background:var(--red);color:white;border:none;padding:4px 12px;border-radius:4px;cursor:pointer;font-size:11px;font-weight:600;">KILL</button>
    </div>
  `).join('');
}

export function initDashboard() {
  return {
    update(state) {
      renderAgentRoster(state.agents);
      renderTopBarStats(state.agents);
      renderAgentsTable(state.agents);
      renderKillSwitch(state.agents);
    },
  };
}
