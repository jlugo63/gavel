/**
 * Dashboard panel logic for Gavel's non-topology tabs.
 *
 * Handles the Operations 6-panel grid, Agents & Enrollment table,
 * Governance Timeline, Incidents, Compliance, and Constitution tabs.
 */

import { GavelState } from './state.js?v=5';
import { esc, statusDot, statusChip, tierChip, trustBar, timeAgo } from './utils.js';

function renderAgentRoster(agents) {
  const el = document.getElementById('agents-panel');
  if (!el) return;
  const list = Object.values(agents);

  const badge = document.getElementById('agent-count');
  if (badge) badge.textContent = list.length;

  if (list.length === 0) {
    el.innerHTML = '<div style="padding:16px;color:var(--text3);font-style:italic;">No agents registered</div>';
    return;
  }

  el.innerHTML = list.map(a => `
    <div class="agent-card" data-agent-id="${esc(a.agent_id)}" style="padding:12px;margin:8px;background:var(--surface);border:1px solid var(--border);border-radius:8px;cursor:pointer;">
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <strong style="font-size:14px;">${statusDot(a.status)}${esc(a.display_name || a.agent_id)}</strong>
        <span class="chip chip-${(a.status || '').toLowerCase()}" style="font-size:11px;">${a.status}</span>
      </div>
      <div style="font-size:11px;color:var(--text3);margin-top:3px;font-family:'JetBrains Mono',monospace;">${esc(a.agent_id)}</div>
      <div style="margin-top:8px;display:flex;gap:6px;align-items:center;flex-wrap:wrap;">
        ${tierChip(a.autonomy_tier)}
        ${trustBar(a.trust_score)}
        <span class="chip" style="text-transform:uppercase;">${esc(a.agent_type || 'agent')}</span>
      </div>
      <div style="font-size:11px;color:var(--text3);margin-top:6px;font-style:italic;">${esc(a.current_activity || 'Idle')}</div>
    </div>
  `).join('');
}

function renderTopBarStats(agents) {
  const list = Object.values(agents);
  const set = (id, val) => { const e = document.getElementById(id); if (e) e.textContent = val; };
  set('stat-agents', list.length);
  set('stat-chains', Object.keys(GavelState.chains).length);
}

function renderAgentsTable(agents) {
  const el = document.getElementById('agents-tab-tbody');
  if (!el) return;
  const list = Object.values(agents);
  if (list.length === 0) {
    el.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text3);padding:32px;font-size:14px;">No agents enrolled</td></tr>';
    return;
  }
  el.innerHTML = list.map(a => `
    <tr style="border-bottom:1px solid var(--border);">
      <td style="padding:10px 8px;">${statusDot(a.status)}${esc(a.agent_id)}</td>
      <td style="padding:10px 8px;">${esc(a.display_name || '')}</td>
      <td style="padding:10px 8px;"><span class="chip" style="text-transform:uppercase;">${esc(a.agent_type || 'agent')}</span></td>
      <td style="padding:10px 8px;">${tierChip(a.autonomy_tier)}</td>
      <td style="padding:10px 8px;">${trustBar(a.trust_score)}</td>
      <td style="padding:10px 8px;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text3);">${esc((a.did || '').substring(0, 22))}...</td>
      <td style="padding:10px 8px;"><span class="chip ${a.enrollment_status === 'ENROLLED' ? 'chip-active' : 'chip-rejected'}">${esc((a.enrollment_status || 'PENDING'))}</span></td>
      <td style="padding:10px 8px;font-size:12px;color:var(--text2);">${esc(a.owner || '')}</td>
    </tr>
  `).join('');
}

function renderKillSwitch(agents) {
  const el = document.getElementById('kill-panel');
  if (!el) return;
  const list = Object.values(agents);
  if (list.length === 0) {
    el.innerHTML = '<div style="padding:16px;color:var(--text3);font-style:italic;">No agents to manage</div>';
    return;
  }
  el.innerHTML = list.map(a => {
    const dead = a.status === 'SUSPENDED' || a.status === 'DEAD';
    const btnStyle = dead
      ? 'background:var(--bg3);color:var(--text3);border:none;padding:6px 14px;border-radius:4px;cursor:default;font-size:11px;font-weight:600;opacity:0.5;'
      : 'background:var(--red);color:white;border:none;padding:6px 14px;border-radius:4px;cursor:pointer;font-size:11px;font-weight:600;';
    const btnLabel = dead ? a.status : 'KILL';
    return `
    <div style="display:flex;justify-content:space-between;align-items:center;padding:10px 12px;border-bottom:1px solid var(--border);">
      <span style="font-size:13px;">${statusDot(a.status)}<strong>${esc(a.display_name || a.agent_id)}</strong>
        <span class="chip chip-${(a.status || '').toLowerCase()}" style="margin-left:8px;font-size:10px;">${a.status}</span></span>
      <button class="kill-btn" data-agent="${esc(a.agent_id)}" ${dead ? 'disabled' : ''} style="${btnStyle}">${btnLabel}</button>
    </div>`;
  }).join('') + `
    <div style="padding:12px;text-align:center;">
      <button id="kill-all-btn" style="background:var(--red);color:white;border:none;padding:8px 24px;border-radius:6px;cursor:pointer;font-size:12px;font-weight:700;letter-spacing:0.5px;">KILL ALL AGENTS</button>
    </div>`;
}


function renderChains(chains) {
  const el = document.getElementById('chains-panel');
  if (!el) return;
  const list = Object.values(chains);
  const badge = document.getElementById('chain-count');
  if (badge) badge.textContent = list.length;

  if (list.length === 0) {
    el.innerHTML = '<div style="padding:16px;color:var(--text3);font-style:italic;">No governance chains</div>';
    return;
  }

  el.innerHTML = list.map(c => {
    const actors = c.roster ? Object.keys(c.roster).join(', ') : '';
    const lastEvent = (c.timeline && c.timeline.length > 0) ? c.timeline[c.timeline.length - 1] : null;
    return `
    <div class="chain-card" data-chain-id="${esc(c.chain_id)}" style="padding:10px 12px;border-bottom:1px solid var(--border);cursor:pointer;">
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <span style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent);">${esc(c.chain_id)}</span>
        ${statusChip(c.status)}
      </div>
      <div style="font-size:11px;color:var(--text3);margin-top:4px;">${esc(actors)}${lastEvent ? ' — ' + esc(lastEvent.event) : ''}</div>
    </div>`;
  }).join('');
}

function renderGateActivity(gateChecks) {
  const el = document.getElementById('gate-panel');
  if (!el) return;
  const badge = document.getElementById('gate-count');
  if (badge) badge.textContent = gateChecks.length;

  if (gateChecks.length === 0) {
    el.innerHTML = '<div style="padding:16px;color:var(--text3);font-style:italic;">No gate checks yet</div>';
    return;
  }

  el.innerHTML = gateChecks.slice(0, 50).map(g => {
    const p = g.payload || {};
    return `
    <div style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:12px;">
      <div style="display:flex;justify-content:space-between;">
        <span>${esc(g.agent_id || 'system')}</span>
        <span style="color:var(--text3);">${timeAgo(g.timestamp)}</span>
      </div>
      <div style="color:var(--text3);margin-top:2px;">${esc(p.action_type || p.result || g.chain_id || '')}</div>
    </div>`;
  }).join('');
}

function renderEventStream(events) {
  const el = document.getElementById('events-panel');
  if (!el) return;
  const badge = document.getElementById('event-count');
  if (badge) badge.textContent = events.length;

  if (events.length === 0) {
    el.innerHTML = '<div style="padding:16px;color:var(--text3);font-style:italic;">Waiting for events…</div>';
    return;
  }

  const typeColors = {
    agent_registered: 'var(--green)', agent_enrolled: 'var(--green)',
    agent_killed: 'var(--red)', agent_dead: 'var(--red)',
    enrollment_failed: 'var(--red)',
    chain_event: 'var(--accent)', gate_check: 'var(--amber)',
    escalation: 'var(--amber)', incident_created: 'var(--red)',
  };

  el.innerHTML = events.slice(0, 50).map(e => {
    const color = typeColors[e.event_type] || 'var(--text2)';
    return `
    <div style="padding:6px 12px;border-bottom:1px solid var(--border);font-size:11px;display:flex;justify-content:space-between;align-items:center;">
      <span>
        <span style="color:${color};font-weight:600;font-family:'JetBrains Mono',monospace;">${esc(e.event_type)}</span>
        ${e.agent_id ? `<span style="color:var(--text3);margin-left:6px;">${esc(e.agent_id)}</span>` : ''}
        ${e.chain_id ? `<span style="color:var(--text3);margin-left:6px;">${esc(e.chain_id)}</span>` : ''}
      </span>
      <span style="color:var(--text3);white-space:nowrap;">${timeAgo(e.timestamp)}</span>
    </div>`;
  }).join('');
}

function renderSLA() {
  const el = document.getElementById('sla-panel');
  const badge = document.getElementById('sla-count');
  if (!el) return;
  fetch('/v1/liveness').then(r => r.json()).then(data => {
    const chains = data.chains || {};
    const entries = Object.entries(chains);
    if (badge) badge.textContent = entries.length;
    if (entries.length === 0) {
      el.innerHTML = '<div class="empty-state">No active SLA timers</div>';
      return;
    }
    el.innerHTML = entries.map(([cid, info]) => {
      const pct = Math.min(100, Math.round((info.elapsed_fraction || 0) * 100));
      const remaining = Math.max(0, Math.round(info.remaining_seconds || 0));
      const level = (info.level || 'NORMAL').toLowerCase();
      const mins = Math.floor(remaining / 60);
      const secs = remaining % 60;
      return `<div class="sla-row">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
          <span style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--accent);">${esc(cid.substring(0, 12))}</span>
          <span style="font-size:10px;color:var(--text3);">${mins}m ${secs}s left</span>
        </div>
        <div class="sla-bar-bg"><div class="sla-bar-fill sla-${level}" style="width:${pct}%"></div></div>
      </div>`;
    }).join('');
  }).catch(() => {});
}

function renderTimeline(chains) {
  const el = document.getElementById('timeline-container');
  if (!el) return;
  const list = Object.values(chains);

  if (list.length === 0) {
    el.innerHTML = '<p style="color:var(--text3);font-style:italic">No governance chains yet.</p>';
    return;
  }

  el.innerHTML = list.map(c => {
    const events = c.timeline || [];
    return `
    <div style="margin-bottom:20px;background:var(--surface);border:1px solid var(--border);border-radius:8px;overflow:hidden;">
      <div style="padding:12px 16px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;">
        <span style="font-family:'JetBrains Mono',monospace;font-size:13px;color:var(--accent);">${esc(c.chain_id)}</span>
        ${statusChip(c.status)}
      </div>
      <div style="padding:8px 16px;">
        ${events.map(ev => `
          <div style="display:flex;gap:12px;padding:6px 0;border-bottom:1px solid var(--bg2);font-size:12px;">
            <span style="color:var(--text3);min-width:80px;font-family:'JetBrains Mono',monospace;">${timeAgo(ev.time)}</span>
            <span style="font-weight:600;min-width:120px;">${esc(ev.event)}</span>
            <span style="color:var(--text3);">${esc(ev.actor)}${ev.role ? ` (${esc(ev.role)})` : ''}</span>
          </div>
        `).join('')}
      </div>
    </div>`;
  }).join('');
}

function renderTopBarChainStats(state) {
  const set = (id, val) => { const e = document.getElementById(id); if (e) e.textContent = val; };
  set('stat-chains', Object.keys(state.chains).length);
  set('stat-gates', state.gateChecks.length);
  const denials = state.events.filter(e =>
    e.event_type === 'chain_event' && e.payload && e.payload.status === 'DENIED'
  ).length;
  set('stat-denials', denials);
}

// ---------------------------------------------------------------------------
// Incidents tab
// ---------------------------------------------------------------------------
let _incidentsCache = null;
let _incidentsFetched = false;

async function fetchAndRenderIncidents() {
  try {
    const res = await fetch('/v1/incidents');
    if (!res.ok) throw new Error(`GET /v1/incidents → ${res.status}`);
    _incidentsCache = await res.json();
  } catch (err) {
    console.error('[Dashboard] fetchIncidents failed:', err);
    _incidentsCache = [];
  }
  _incidentsFetched = true;
  renderIncidents();
}

function renderIncidents() {
  const el = document.getElementById('incidents-container');
  if (!el || !_incidentsFetched) return;
  const list = _incidentsCache || [];

  if (list.length === 0) {
    el.innerHTML = '<p style="color:var(--text3);font-style:italic">No incidents reported.</p>';
    return;
  }

  const sevColors = { CRITICAL: 'var(--red)', SERIOUS: 'var(--amber)', STANDARD: 'var(--accent)', MINOR: 'var(--text3)' };

  el.innerHTML = list.map(inc => `
    <div style="padding:12px;margin-bottom:8px;background:var(--surface);border:1px solid var(--border);border-radius:8px;">
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <strong style="font-size:14px;">${esc(inc.title || inc.incident_id)}</strong>
        <span style="color:${sevColors[inc.severity] || 'var(--text2)'};font-size:11px;font-weight:700;">${esc(inc.severity || 'UNKNOWN')}</span>
      </div>
      <div style="font-size:12px;color:var(--text3);margin-top:4px;">
        ${esc(inc.agent_id || '')}${inc.created_at ? ' — ' + timeAgo(inc.created_at) : ''}
      </div>
      ${inc.description ? `<div style="font-size:12px;color:var(--text2);margin-top:6px;">${esc(inc.description)}</div>` : ''}
      <div style="margin-top:6px;">${statusChip(inc.status || 'OPEN')}</div>
    </div>
  `).join('');
}

// ---------------------------------------------------------------------------
// Compliance tab
// ---------------------------------------------------------------------------
let _complianceCache = null;
let _complianceFetched = false;

async function fetchAndRenderCompliance() {
  try {
    const res = await fetch('/v1/compliance/status');
    if (!res.ok) throw new Error(`GET /v1/compliance/status → ${res.status}`);
    _complianceCache = await res.json();
  } catch (err) {
    console.error('[Dashboard] fetchCompliance failed:', err);
    _complianceCache = {};
  }
  _complianceFetched = true;
  renderCompliance();
}

function renderCompliance() {
  const el = document.getElementById('compliance-container');
  if (!el || !_complianceFetched) return;
  const d = _complianceCache || {};

  const stat = (label, val, color) =>
    `<div style="text-align:center;padding:16px 24px;background:var(--surface);border:1px solid var(--border);border-radius:8px;">
      <div style="font-size:28px;font-weight:700;color:${color};font-family:'JetBrains Mono',monospace;">${val}</div>
      <div style="font-size:11px;color:var(--text3);margin-top:4px;text-transform:uppercase;letter-spacing:0.5px;">${label}</div>
    </div>`;

  el.innerHTML = `
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:12px;margin-bottom:16px;">
      ${stat('Agents', d.total_agents ?? 0, 'var(--accent)')}
      ${stat('Enrolled', d.enrolled_agents ?? 0, 'var(--green)')}
      ${stat('Chains', d.total_chains ?? 0, 'var(--accent)')}
      ${stat('Completed', d.completed_chains ?? 0, 'var(--green)')}
      ${stat('Denied', d.denied_chains ?? 0, 'var(--red)')}
      ${stat('Incidents', d.total_incidents ?? 0, d.total_incidents > 0 ? 'var(--amber)' : 'var(--text2)')}
      ${stat('Overdue', d.overdue_incidents ?? 0, d.overdue_incidents > 0 ? 'var(--red)' : 'var(--text2)')}
    </div>
    ${Object.keys(d.incidents_by_severity || {}).length > 0 ? `
      <h3 style="font-size:14px;margin:16px 0 8px;">Incidents by Severity</h3>
      <div style="display:flex;gap:8px;flex-wrap:wrap;">
        ${Object.entries(d.incidents_by_severity).map(([sev, count]) =>
          `<span class="chip" style="font-size:12px;">${esc(sev)}: ${count}</span>`
        ).join('')}
      </div>` : ''}`;
}

// ---------------------------------------------------------------------------
// Constitution tab
// ---------------------------------------------------------------------------
let _constitutionCache = null;
let _constitutionFetched = false;

async function fetchAndRenderConstitution() {
  try {
    const res = await fetch('/v1/constitution');
    if (!res.ok) throw new Error(`GET /v1/constitution → ${res.status}`);
    _constitutionCache = await res.json();
  } catch (err) {
    console.error('[Dashboard] fetchConstitution failed:', err);
    _constitutionCache = { invariants: [] };
  }
  _constitutionFetched = true;
  renderConstitution();
}

function renderConstitution() {
  const el = document.getElementById('constitution-container');
  if (!el || !_constitutionFetched) return;
  const invariants = (_constitutionCache && _constitutionCache.invariants) || [];

  if (invariants.length === 0) {
    el.innerHTML = '<p style="color:var(--text3);font-style:italic">No constitutional invariants defined.</p>';
    return;
  }

  el.innerHTML = invariants.map(inv => `
    <div style="padding:14px;margin-bottom:10px;background:var(--surface);border:1px solid var(--border);border-radius:8px;">
      <div style="display:flex;gap:10px;align-items:baseline;">
        <span style="font-family:'JetBrains Mono',monospace;font-size:13px;font-weight:700;color:var(--accent);min-width:48px;">${esc(inv.id)}</span>
        <span style="font-size:13px;color:var(--text1);">${esc(inv.text)}</span>
      </div>
      ${inv.enforcement ? `<div style="font-size:11px;color:var(--text3);margin-top:8px;padding-left:58px;">${esc(inv.enforcement)}</div>` : ''}
    </div>
  `).join('');
}

export function initDashboard() {
  GavelState.fetchRecentEvents();
  fetchAndRenderIncidents();
  fetchAndRenderCompliance();
  fetchAndRenderConstitution();

  // Wire agent card and chain card clicks to Inspector
  document.addEventListener('click', (e) => {
    const agentCard = e.target.closest('.agent-card[data-agent-id]');
    if (agentCard) {
      GavelState.setSelection('agent', agentCard.dataset.agentId);
      return;
    }
    const chainCard = e.target.closest('.chain-card[data-chain-id]');
    if (chainCard) {
      GavelState.setSelection('chain', chainCard.dataset.chainId);
      return;
    }
  });

  // Wire kill switch buttons (event delegation for dynamically rendered buttons)
  document.addEventListener('click', async (e) => {
    const killBtn = e.target.closest('.kill-btn[data-agent]');
    if (killBtn) {
      const agentId = killBtn.dataset.agent;
      if (!confirm(`Kill agent ${agentId}?`)) return;
      try {
        const res = await fetch(`/v1/agents/${encodeURIComponent(agentId)}/kill`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ reason: 'Manual kill switch' }),
        });
        if (!res.ok) throw new Error(`Kill failed: ${res.status}`);
        await GavelState.fetchAgents();
      } catch (err) {
        console.error('[Dashboard] Kill failed:', err);
        alert(`Kill failed: ${err.message}`);
      }
      return;
    }

    if (e.target.closest('#kill-all-btn')) {
      if (!confirm('Kill ALL agents?')) return;
      const agents = Object.keys(GavelState.agents);
      for (const agentId of agents) {
        try {
          await fetch(`/v1/agents/${encodeURIComponent(agentId)}/kill`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ reason: 'Manual kill-all switch' }),
          });
        } catch (err) {
          console.error(`[Dashboard] Kill ${agentId} failed:`, err);
        }
      }
      await GavelState.fetchAgents();
      return;
    }
  });

  // Wire Create Incident button
  const createIncBtn = document.getElementById('incident-create-btn');
  if (createIncBtn) {
    createIncBtn.addEventListener('click', () => {
      const container = document.getElementById('incidents-container');
      if (!container) return;
      // Toggle form
      const existing = document.getElementById('incident-form');
      if (existing) { existing.remove(); return; }

      const agents = Object.keys(GavelState.agents);
      const agentOpts = agents.map(a => `<option value="${esc(a)}">${esc(a)}</option>`).join('');

      const form = document.createElement('div');
      form.id = 'incident-form';
      form.style.cssText = 'padding:16px;margin-bottom:12px;background:var(--surface);border:1px solid var(--border);border-radius:8px;';
      form.innerHTML = `
        <div style="display:grid;gap:10px;">
          <select id="inc-agent" style="padding:8px;background:var(--bg2);color:var(--text);border:1px solid var(--border);border-radius:4px;">
            ${agentOpts}
          </select>
          <input id="inc-title" placeholder="Incident title" style="padding:8px;background:var(--bg2);color:var(--text);border:1px solid var(--border);border-radius:4px;">
          <textarea id="inc-desc" placeholder="Description" rows="3" style="padding:8px;background:var(--bg2);color:var(--text);border:1px solid var(--border);border-radius:4px;resize:vertical;"></textarea>
          <select id="inc-severity" style="padding:8px;background:var(--bg2);color:var(--text);border:1px solid var(--border);border-radius:4px;">
            <option value="MINOR">MINOR</option>
            <option value="STANDARD" selected>STANDARD</option>
            <option value="SERIOUS">SERIOUS</option>
            <option value="CRITICAL">CRITICAL</option>
          </select>
          <div style="display:flex;gap:8px;">
            <button id="inc-submit" style="padding:8px 16px;background:var(--accent);color:white;border:none;border-radius:4px;cursor:pointer;font-weight:600;">Submit</button>
            <button id="inc-cancel" style="padding:8px 16px;background:var(--surface2);color:var(--text);border:1px solid var(--border);border-radius:4px;cursor:pointer;">Cancel</button>
          </div>
        </div>`;
      container.insertBefore(form, container.firstChild);

      document.getElementById('inc-cancel').addEventListener('click', () => form.remove());
      document.getElementById('inc-submit').addEventListener('click', async () => {
        const payload = {
          agent_id: document.getElementById('inc-agent').value,
          title: document.getElementById('inc-title').value,
          description: document.getElementById('inc-desc').value,
          severity: document.getElementById('inc-severity').value.toLowerCase(),
          event_type: 'manual',
        };
        if (!payload.title.trim()) { alert('Title is required'); return; }
        try {
          const res = await fetch('/v1/incidents', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
          });
          if (!res.ok) throw new Error(`POST /v1/incidents → ${res.status}`);
          form.remove();
          fetchAndRenderIncidents();
        } catch (err) {
          console.error('[Dashboard] Create incident failed:', err);
          alert(`Failed: ${err.message}`);
        }
      });
    });
  }

  return {
    update(state) {
      renderAgentRoster(state.agents);
      renderTopBarStats(state.agents);
      renderTopBarChainStats(state);
      renderAgentsTable(state.agents);
      renderKillSwitch(state.agents);
      renderChains(state.chains);
      renderGateActivity(state.gateChecks);
      renderEventStream(state.events);
      renderTimeline(state.chains);
      renderSLA();

      // Re-fetch incidents on incident SSE events
      const hasIncidentEvent = state.events.length > 0 &&
        state.events[0].event_type && state.events[0].event_type.startsWith('incident');
      if (hasIncidentEvent) fetchAndRenderIncidents();
    },
  };
}
