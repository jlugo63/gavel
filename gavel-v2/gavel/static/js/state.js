/**
 * state.js — Central state store for the Gavel dashboard.
 *
 * Singleton pub/sub store that holds all agent, chain, and enrollment data.
 * Subscribers are notified on every mutation so UI layers (topology.js,
 * inspector.js) can re-render reactively.
 *
 * ES module — no build step, no external dependencies.
 */

import { buildGraphModel } from './graph-model.js';

// ---------------------------------------------------------------------------
// Subscriber registry
// ---------------------------------------------------------------------------
const _subscribers = new Set();

// ---------------------------------------------------------------------------
// Central state singleton
// ---------------------------------------------------------------------------
export const GavelState = {
  agents: {},         // agent_id -> full agent record from API
  chains: {},         // chain_id -> chain data from API
  enrollments: {},    // agent_id -> enrollment record
  events: [],         // recent SSE events for the event stream panel (newest first)
  gateChecks: [],     // gate_check events for the gate activity panel (newest first)
  graph: {            // derived graph model (rebuilt by graph-model.js)
    nodes: [],
    edges: [],
  },
  selection: null,    // { type: 'agent'|'chain'|'engine', id: string } | null
  focusMode: false,   // when true, only selection subgraph is visible
  filters: {
    showConstraints: true,
    showInactiveAgents: true,
    showChainFlows: true,
  },

  // -----------------------------------------------------------------------
  // Pub/Sub
  // -----------------------------------------------------------------------

  /**
   * Register a callback that fires on every state change.
   * @param {Function} callback
   * @returns {Function} unsubscribe function
   */
  subscribe(callback) {
    _subscribers.add(callback);
    return () => _subscribers.delete(callback);
  },

  /**
   * Notify all subscribers that state has changed.
   */
  notify() {
    for (const cb of _subscribers) {
      try {
        cb(GavelState);
      } catch (err) {
        console.error('[GavelState] subscriber error:', err);
      }
    }
  },

  // -----------------------------------------------------------------------
  // Selection
  // -----------------------------------------------------------------------

  /**
   * Set the current selection (agent, chain, or engine node).
   * @param {'agent'|'chain'|'engine'} type
   * @param {string} id
   */
  setSelection(type, id) {
    GavelState.selection = { type, id };
    GavelState.notify();
  },

  /**
   * Clear the current selection.
   */
  clearSelection() {
    GavelState.selection = null;
    GavelState.focusMode = false;
    GavelState.notify();
  },

  toggleFocus() {
    GavelState.focusMode = !GavelState.focusMode;
    GavelState.notify();
  },

  // -----------------------------------------------------------------------
  // Filters
  // -----------------------------------------------------------------------

  /**
   * Toggle a boolean filter value.
   * @param {string} filterName - key in GavelState.filters
   */
  toggleFilter(filterName) {
    if (filterName in GavelState.filters) {
      GavelState.filters[filterName] = !GavelState.filters[filterName];
      GavelState.notify();
    }
  },

  // -----------------------------------------------------------------------
  // Data mutations
  // -----------------------------------------------------------------------

  /**
   * Upsert an agent record into the agents map.
   * @param {object} agentData - must contain agent_id
   */
  updateAgent(agentData) {
    if (!agentData || !agentData.agent_id) return;
    const existing = GavelState.agents[agentData.agent_id] || {};
    GavelState.agents[agentData.agent_id] = Object.assign(existing, agentData);
  },

  /**
   * Upsert chain data into the chains map.
   * @param {object} chainData - must contain chain_id
   */
  updateChain(chainData) {
    if (!chainData || !chainData.chain_id) return;
    const existing = GavelState.chains[chainData.chain_id] || {};
    GavelState.chains[chainData.chain_id] = Object.assign(existing, chainData);
  },

  /**
   * Remove an agent from the agents map.
   * @param {string} agentId
   */
  removeAgent(agentId) {
    delete GavelState.agents[agentId];
  },

  // -----------------------------------------------------------------------
  // Graph rebuild
  // -----------------------------------------------------------------------

  /**
   * Rebuild the derived graph model from current agents/chains data.
   * Stores result in GavelState.graph and notifies subscribers.
   */
  rebuildGraph() {
    GavelState.graph = buildGraphModel(GavelState);
    GavelState.notify();
  },

  // -----------------------------------------------------------------------
  // API fetch methods
  // -----------------------------------------------------------------------

  /**
   * Fetch all agents from the API, populate the agents map,
   * rebuild the graph, and notify.
   */
  async fetchAgents() {
    try {
      const res = await fetch('/v1/agents');
      if (!res.ok) throw new Error(`GET /v1/agents → ${res.status}`);
      const agents = await res.json();
      GavelState.agents = {};
      for (const agent of agents) {
        GavelState.agents[agent.agent_id] = agent;
      }
      // Merge enrollment data (owner, purpose, risk_tier)
      try {
        const eres = await fetch('/v1/agents/enrollments');
        if (eres.ok) {
          const enrollments = await eres.json();
          for (const e of enrollments) {
            if (GavelState.agents[e.agent_id]) {
              Object.assign(GavelState.agents[e.agent_id], {
                owner: e.owner,
                enrollment_status: e.status,
                purpose: e.purpose,
                risk_tier: e.risk_tier,
              });
            }
          }
        }
      } catch (_) { /* enrollment data is optional */ }
      GavelState.rebuildGraph();
    } catch (err) {
      console.error('[GavelState] fetchAgents failed:', err);
    }
  },

  /**
   * Fetch a single chain from the API, populate the chains map,
   * rebuild the graph, and notify.
   * @param {string} chainId
   */
  async fetchChain(chainId) {
    try {
      const res = await fetch(`/v1/chain/${chainId}`);
      if (!res.ok) throw new Error(`GET /v1/chain/${chainId} → ${res.status}`);
      const chain = await res.json();
      GavelState.chains[chain.chain_id] = chain;
      GavelState.rebuildGraph();
    } catch (err) {
      console.error(`[GavelState] fetchChain(${chainId}) failed:`, err);
    }
  },

  /**
   * Fetch all chains from the API, populate the chains map,
   * rebuild the graph, and notify.
   */
  async fetchChains() {
    try {
      const res = await fetch('/v1/chains');
      if (!res.ok) throw new Error(`GET /v1/chains → ${res.status}`);
      const chains = await res.json();
      GavelState.chains = {};
      for (const chain of chains) {
        GavelState.chains[chain.chain_id] = chain;
      }
      GavelState.rebuildGraph();
    } catch (err) {
      console.error('[GavelState] fetchChains failed:', err);
    }
  },

  /**
   * Fetch system status from the API.
   * @returns {object|null} status data or null on failure
   */
  async fetchStatus() {
    try {
      const res = await fetch('/v1/status');
      if (!res.ok) throw new Error(`GET /v1/status → ${res.status}`);
      return await res.json();
    } catch (err) {
      console.error('[GavelState] fetchStatus failed:', err);
      return null;
    }
  },

  // -----------------------------------------------------------------------
  // SSE connection
  // -----------------------------------------------------------------------

  /** @type {EventSource|null} */
  _eventSource: null,

  /** @type {number|null} */
  _reconnectTimer: null,

  /**
   * Connect to the SSE event stream. Handles all Gavel event types
   * and auto-reconnects on connection loss with a 3-second delay.
   */
  connectSSE() {
    // Clean up any existing connection
    if (GavelState._eventSource) {
      GavelState._eventSource.close();
      GavelState._eventSource = null;
    }
    if (GavelState._reconnectTimer) {
      clearTimeout(GavelState._reconnectTimer);
      GavelState._reconnectTimer = null;
    }

    const es = new EventSource('/v1/events/stream');
    GavelState._eventSource = es;

    es.onopen = () => {
      console.log('[GavelState] SSE connected');
      const ind = document.getElementById('conn-indicator');
      const txt = document.getElementById('conn-text');
      if (ind) { ind.classList.remove('conn-dead'); ind.classList.add('conn-live'); }
      if (txt) txt.textContent = 'Live';
    };

    es.onerror = () => {
      console.warn('[GavelState] SSE connection lost, reconnecting in 3s...');
      const ind = document.getElementById('conn-indicator');
      const txt = document.getElementById('conn-text');
      if (ind) { ind.classList.remove('conn-live'); ind.classList.add('conn-dead'); }
      if (txt) txt.textContent = 'Reconnecting...';
      es.close();
      GavelState._eventSource = null;
      GavelState._reconnectTimer = setTimeout(() => GavelState.connectSSE(), 3000);
    };

    // All event types the Gavel backend emits
    const eventTypes = [
      'agent_registered',
      'agent_heartbeat',
      'agent_killed',
      'agent_dead',
      'agent_promoted',
      'agent_demoted',
      'agent_status_change',
      'agent_enrolled',
      'enrollment_failed',
      'chain_event',
      'escalation',
      'action',
      'gate_check',
      'action_reported',
      'incident_created',
      'incident_reported',
      'incident_resolved',
    ];

    for (const type of eventTypes) {
      es.addEventListener(type, (e) => {
        try {
          const data = JSON.parse(e.data);
          GavelState._handleSSEEvent(data);
        } catch (err) {
          console.error(`[GavelState] failed to parse SSE event (${type}):`, err);
        }
      });
    }
  },

  /**
   * Internal handler for a single SSE event. Mirrors the logic from
   * dashboard.html handleEvent().
   * @param {object} data - parsed event payload with event_type, agent_id, etc.
   */
  _handleSSEEvent(data) {
    const eventType = data.event_type;
    const payload = data.payload || {};

    // Push to the event log (cap at 200 entries)
    GavelState.events.unshift(data);
    if (GavelState.events.length > 200) GavelState.events.length = 200;

    // Track gate checks separately
    if (eventType === 'gate_check') {
      GavelState.gateChecks.unshift(data);
      if (GavelState.gateChecks.length > 100) GavelState.gateChecks.length = 100;
    }

    // --- Agent-level events ---
    if (eventType === 'agent_registered') {
      GavelState.updateAgent({
        agent_id: data.agent_id,
        ...payload,
        status: 'ACTIVE',
        autonomy_tier: payload.autonomy_tier ?? 0,
      });
      GavelState.rebuildGraph();
      return;
    }

    if (eventType === 'agent_heartbeat') {
      GavelState.updateAgent({
        agent_id: data.agent_id,
        last_heartbeat: data.timestamp,
        status: 'ACTIVE',
        ...(payload.activity ? { current_activity: payload.activity } : {}),
      });
      GavelState.notify();
      return;
    }

    if (eventType === 'agent_killed') {
      GavelState.updateAgent({ agent_id: data.agent_id, status: 'SUSPENDED' });
      GavelState.rebuildGraph();
      return;
    }

    if (eventType === 'agent_dead') {
      GavelState.updateAgent({ agent_id: data.agent_id, status: 'DEAD' });
      GavelState.rebuildGraph();
      return;
    }

    if (eventType === 'agent_promoted') {
      GavelState.updateAgent({ agent_id: data.agent_id, autonomy_tier: payload.new_tier });
      GavelState.notify();
      return;
    }

    if (eventType === 'agent_demoted') {
      GavelState.updateAgent({ agent_id: data.agent_id, autonomy_tier: payload.new_tier });
      GavelState.notify();
      return;
    }

    if (eventType === 'agent_status_change') {
      GavelState.updateAgent({ agent_id: data.agent_id, status: payload.new_status });
      GavelState.rebuildGraph();
      return;
    }

    // --- Enrollment events ---
    if (eventType === 'agent_enrolled') {
      // Refresh the full agent list to pick up enrollment data
      GavelState.fetchAgents();
      return;
    }

    // --- Chain events ---
    if (eventType === 'chain_event' && data.chain_id) {
      // Fetch full chain data from API to get roster, evidence, etc.
      GavelState.fetchChain(data.chain_id);
      return;
    }

    // --- All other events: just notify so UI can update event logs ---
    GavelState.notify();
  },
};
