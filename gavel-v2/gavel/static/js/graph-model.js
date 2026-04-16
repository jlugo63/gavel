/**
 * graph-model.js — Pure transformation layer for Gavel topology canvas.
 *
 * Takes raw API state (agents, chains, enrollments) and produces a graph
 * schema of nodes and edges that topology.js can render.
 *
 * No side effects, no DOM access, no fetch calls.
 */

// ---------------------------------------------------------------------------
// Column mapping — determines which side of the canvas an agent lands on
// ---------------------------------------------------------------------------
const COLUMN_MAP = {
  engineer: 'left',
  executor: 'left',
  assistant: 'left',
  analyst: 'left',
  reviewer: 'right',
  approver: 'right',
  compliance: 'right',
};

// ---------------------------------------------------------------------------
// Node type constants
// ---------------------------------------------------------------------------
const RIGHT_ROLES = new Set(['reviewer', 'approver', 'compliance']);

/**
 * Determine the canonical node type string for an agent.
 * @param {string} agentType - the agent_type field from the API record
 * @returns {string}
 */
function resolveNodeType(agentType) {
  const t = (agentType || '').toLowerCase();
  if (t === 'reviewer') return 'AGENT_REVIEWER';
  if (t === 'approver') return 'AGENT_APPROVER';
  if (t === 'executor') return 'AGENT_EXECUTOR';
  if (RIGHT_ROLES.has(t)) return 'AGENT_REVIEWER';
  return 'AGENT_GENERIC';
}

/**
 * Determine column placement for an agent.
 * @param {string} agentType
 * @returns {'left'|'right'}
 */
function resolveColumn(agentType) {
  return COLUMN_MAP[(agentType || '').toLowerCase()] || 'left';
}

// ---------------------------------------------------------------------------
// Main builder
// ---------------------------------------------------------------------------

/**
 * Build a graph model from the current GavelState.
 *
 * @param {object} state - The GavelState singleton (agents, chains, enrollments)
 * @returns {{ nodes: Array, edges: Array }}
 */
export function buildGraphModel(state) {
  const nodes = [];
  const edges = [];
  const agentMap = state.agents || {};
  const chainMap = state.chains || {};

  // --- Policy Engine node (always present, center column) ---
  nodes.push({
    id: 'policy-engine',
    type: 'POLICY_ENGINE',
    column: 'center',
    label: 'Policy Engine',
    data: { description: 'Gavel governance engine' },
    status: 'ACTIVE',
    trustScore: 1000,
    tier: 3,
  });

  // --- Agent nodes ---
  for (const [agentId, agent] of Object.entries(agentMap)) {
    nodes.push({
      id: agentId,
      type: resolveNodeType(agent.agent_type),
      column: resolveColumn(agent.agent_type),
      label: agent.display_name || agentId,
      data: agent,
      status: agent.status || 'IDLE',
      trustScore: agent.trust_score ?? 500,
      tier: agent.autonomy_tier ?? 0,
    });

    // Enrollment edge: every agent connects to the policy engine
    edges.push({
      id: `enrollment-${agentId}`,
      source: agentId,
      target: 'policy-engine',
      type: 'ENROLLMENT',
      chainId: null,
      animated: false,
      data: {},
    });
  }

  // --- Chain-derived edges ---
  for (const [chainId, chain] of Object.entries(chainMap)) {
    const roster = chain.roster || {};
    const status = (chain.status || '').toUpperCase();

    // Identify proposer and approver/reviewer from the roster
    let proposerId = null;
    let approverId = null;
    let executorId = null;

    for (const [agentId, role] of Object.entries(roster)) {
      const r = (role || '').toLowerCase();
      if (r === 'proposer') proposerId = agentId;
      if (r === 'approver' || r === 'reviewer') approverId = agentId;
      if (r === 'executor') executorId = agentId;
    }

    // Proposal edge: proposer -> policy engine
    if (proposerId && agentMap[proposerId]) {
      const isActive = ['PENDING', 'ESCALATED', 'EVALUATING'].includes(status);
      edges.push({
        id: `proposal-${chainId}`,
        source: proposerId,
        target: 'policy-engine',
        type: 'PROPOSAL',
        chainId,
        animated: isActive,
        data: chain,
      });
    }

    // Approval / Denial edge: policy engine -> approver
    if (approverId && agentMap[approverId]) {
      const edgeType = status === 'DENIED' ? 'DENIAL' : 'APPROVAL';
      const isActive = ['PENDING', 'ESCALATED', 'EVALUATING'].includes(status);
      edges.push({
        id: `decision-${chainId}`,
        source: 'policy-engine',
        target: approverId,
        type: edgeType,
        chainId,
        animated: isActive,
        data: chain,
      });
    }

    // Execution edge: policy engine -> executor (when execution token issued)
    if (executorId && agentMap[executorId]) {
      const isExecuting = ['EXECUTING', 'APPROVED'].includes(status);
      edges.push({
        id: `execution-${chainId}`,
        source: 'policy-engine',
        target: executorId,
        type: 'EXECUTION',
        chainId,
        animated: isExecuting,
        data: chain,
      });
    }
  }

  // --- Constraint edges (separation of powers) ---
  // If two agents appeared in the same chain with one as proposer,
  // they get a CONSTRAINT edge indicating they cannot approve each other.
  const constraintPairs = new Set();
  for (const [chainId, chain] of Object.entries(chainMap)) {
    const roster = chain.roster || {};
    const participants = Object.keys(roster).filter((id) => agentMap[id]);
    let proposer = null;
    for (const [agentId, role] of Object.entries(roster)) {
      if ((role || '').toLowerCase() === 'proposer') proposer = agentId;
    }
    if (proposer && participants.length > 1) {
      for (const pid of participants) {
        if (pid === proposer) continue;
        const pairKey = [proposer, pid].sort().join('::');
        if (!constraintPairs.has(pairKey)) {
          constraintPairs.add(pairKey);
          edges.push({
            id: `constraint-${pairKey}`,
            source: proposer,
            target: pid,
            type: 'CONSTRAINT',
            chainId: null,
            animated: false,
            data: { reason: 'separation-of-powers' },
          });
        }
      }
    }
  }

  return { nodes, edges };
}

// ---------------------------------------------------------------------------
// Layout computation
// ---------------------------------------------------------------------------

/**
 * Compute x/y positions for each node based on column assignment.
 *
 * @param {Array} nodes - Array of node objects with `column` field
 * @param {number} width - Canvas width in pixels
 * @param {number} height - Canvas height in pixels
 * @returns {Map<string, {x: number, y: number}>}
 */
export function computeLayout(nodes, width, height) {
  const positions = new Map();

  // Bucket nodes by column
  const left = [];
  const center = [];
  const right = [];

  for (const node of nodes) {
    if (node.column === 'center') center.push(node);
    else if (node.column === 'right') right.push(node);
    else left.push(node);
  }

  // Helper: evenly space a list of nodes vertically at a given x
  function distribute(list, x) {
    const count = list.length;
    if (count === 0) return;
    const spacing = height / (count + 1);
    for (let i = 0; i < count; i++) {
      positions.set(list[i].id, { x, y: spacing * (i + 1) });
    }
  }

  distribute(left, width * 0.15);
  distribute(center, width * 0.5);
  distribute(right, width * 0.85);

  return positions;
}
