/**
 * topology.js — D3.js directed layout renderer for Gavel dashboard.
 *
 * Renders a three-column directed graph (Execution | Governance | Oversight)
 * using stable computed positions from graph-model.js.
 *
 * ES module — D3 v7 loaded globally via CDN.
 */

import { GavelState } from './state.js';
import { computeLayout } from './graph-model.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const TIER_NAMES = ['SUPERVISED', 'SEMI_AUTONOMOUS', 'AUTONOMOUS', 'SOVEREIGN'];
const STATUS_COLORS = {
  ACTIVE: '#00b894',
  IDLE: '#5e5e72',
  SUSPENDED: '#fdcb6e',
  DEAD: '#ff6b6b',
};
const EDGE_STYLES = {
  ENROLLMENT: { stroke: '#252536', width: 1, dash: null, anim: false },
  PROPOSAL: { stroke: '#fdcb6e', width: 1.5, dash: '5,5', anim: true },
  APPROVAL: { stroke: '#00b894', width: 1.5, dash: null, anim: false },
  DENIAL: { stroke: '#ff6b6b', width: 1.5, dash: null, anim: false },
  EXECUTION: { stroke: '#81ecec', width: 1.5, dash: '6,3', anim: true },
  CONSTRAINT: { stroke: 'rgba(255,107,107,0.3)', width: 1, dash: '2,4', anim: false },
};
const AGENT_RADIUS = 36;
const ENGINE_RADIUS = 55;
const TRANSITION_MS = 500;

// ---------------------------------------------------------------------------
// Hexagon path helper
// ---------------------------------------------------------------------------
function hexagonPath(cx, cy, r) {
  const pts = [];
  for (let i = 0; i < 6; i++) {
    const angle = (Math.PI / 3) * i - Math.PI / 2;
    pts.push(`${cx + r * Math.cos(angle)},${cy + r * Math.sin(angle)}`);
  }
  return `M${pts.join('L')}Z`;
}

// ---------------------------------------------------------------------------
// Trust arc generator
// ---------------------------------------------------------------------------
function trustArc(score, radius) {
  const fraction = Math.max(0, Math.min(1, score / 1000));
  const startAngle = -Math.PI / 2;
  const endAngle = startAngle + fraction * 2 * Math.PI;
  const arc = d3.arc()
    .innerRadius(radius + 2)
    .outerRadius(radius + 5)
    .startAngle(0)
    .endAngle(fraction * 2 * Math.PI);
  return arc();
}

// ---------------------------------------------------------------------------
// TopologyRenderer
// ---------------------------------------------------------------------------
export class TopologyRenderer {
  constructor(svgSelector) {
    this._svgSelector = svgSelector;
    this._svg = d3.select(svgSelector);
    this._width = 0;
    this._height = 0;
    this._positions = new Map();

    // Root group for zoom/pan
    this._rootG = this._svg.append('g').attr('class', 'topology-root');

    // Layer groups (edges below nodes)
    this._edgeG = this._rootG.append('g').attr('class', 'topology-edges');
    this._nodeG = this._rootG.append('g').attr('class', 'topology-nodes');

    // Tooltip
    this._tooltip = d3.select('body').append('div')
      .attr('class', 'topo-tooltip')
      .style('position', 'absolute')
      .style('pointer-events', 'none')
      .style('background', '#1c1c2c')
      .style('border', '1px solid #252536')
      .style('border-radius', '4px')
      .style('padding', '6px 10px')
      .style('font-size', '10px')
      .style('font-family', "'JetBrains Mono', monospace")
      .style('color', '#e8e8ef')
      .style('white-space', 'pre')
      .style('z-index', '100')
      .style('display', 'none');

    // Defs: arrowheads and gradient
    this._initDefs();

    // Zoom
    this._zoom = d3.zoom()
      .scaleExtent([0.3, 3])
      .on('zoom', (event) => {
        this._rootG.attr('transform', event.transform);
      });
    this._svg.call(this._zoom);

    // Bind floating controls
    this._bindControls();

    // Resize observer
    this._resizeObs = new ResizeObserver(() => this._updateSize());
    const svgEl = this._svg.node();
    if (svgEl && svgEl.parentElement) {
      this._resizeObs.observe(svgEl.parentElement);
    }

    // CSS for animated dashes
    this._injectCSS();
  }

  // -----------------------------------------------------------------------
  // Initialization helpers
  // -----------------------------------------------------------------------

  _initDefs() {
    const defs = this._svg.append('defs');

    // Arrowhead markers per edge type
    for (const [type, style] of Object.entries(EDGE_STYLES)) {
      defs.append('marker')
        .attr('id', `arrow-${type}`)
        .attr('viewBox', '0 0 10 10')
        .attr('refX', 10)
        .attr('refY', 5)
        .attr('markerWidth', 8)
        .attr('markerHeight', 8)
        .attr('orient', 'auto-start-reverse')
        .append('path')
        .attr('d', 'M0,0 L10,5 L0,10 Z')
        .attr('fill', style.stroke);
    }

    // Accent gradient for engine node
    const grad = defs.append('linearGradient')
      .attr('id', 'engine-gradient')
      .attr('x1', '0%').attr('y1', '0%')
      .attr('x2', '100%').attr('y2', '100%');
    grad.append('stop').attr('offset', '0%').attr('stop-color', '#7c6cf7');
    grad.append('stop').attr('offset', '100%').attr('stop-color', '#5c4cd7');

    // Golden glow filter for selection
    const glow = defs.append('filter')
      .attr('id', 'glow-selected')
      .attr('x', '-50%').attr('y', '-50%')
      .attr('width', '200%').attr('height', '200%');
    glow.append('feGaussianBlur').attr('in', 'SourceAlpha').attr('stdDeviation', '4').attr('result', 'blur');
    glow.append('feFlood').attr('flood-color', '#fdcb6e').attr('flood-opacity', '0.7').attr('result', 'color');
    glow.append('feComposite').attr('in', 'color').attr('in2', 'blur').attr('operator', 'in').attr('result', 'glow');
    const merge = glow.append('feMerge');
    merge.append('feMergeNode').attr('in', 'glow');
    merge.append('feMergeNode').attr('in', 'SourceGraphic');
  }

  _injectCSS() {
    if (document.getElementById('topo-anim-css')) return;
    const style = document.createElement('style');
    style.id = 'topo-anim-css';
    style.textContent = `
      @keyframes dash-flow {
        to { stroke-dashoffset: -20; }
      }
      .edge-animated {
        animation: dash-flow 0.8s linear infinite;
      }
      @keyframes engine-pulse {
        0%, 100% { stroke-opacity: 0.4; }
        50% { stroke-opacity: 1; }
      }
      .engine-pulsing {
        animation: engine-pulse 1.5s ease-in-out infinite;
      }
      @keyframes path-pulse {
        0% { filter: none; }
        50% { filter: drop-shadow(0 0 4px var(--glow-color, #fdcb6e)); }
        100% { filter: none; }
      }
      .edge-pulse-amber {
        --glow-color: #fdcb6e;
        animation: dash-flow 0.8s linear infinite, path-pulse 2s ease-in-out infinite;
      }
      .edge-pulse-green {
        --glow-color: #00b894;
        animation: path-pulse 0.6s ease-out 1;
      }
      .edge-pulse-cyan {
        --glow-color: #81ecec;
        animation: dash-flow 0.6s linear infinite, path-pulse 1.5s ease-in-out infinite;
      }
      @keyframes red-flash {
        0% { stroke: #ff6b6b; stroke-width: 3; filter: drop-shadow(0 0 6px #ff6b6b); }
        100% { stroke: #ff6b6b; stroke-width: 1.5; filter: none; }
      }
      .edge-denied {
        animation: red-flash 0.5s ease-out 1;
      }
      .topo-node.focus-dimmed { opacity: 0.08 !important; pointer-events: none; }
      .topo-edge.focus-dimmed { opacity: 0.05 !important; }
      .topo-node.focus-visible { opacity: 1 !important; }
      .topo-edge.focus-visible { opacity: 1 !important; }
    `;
    document.head.appendChild(style);
  }

  _bindControls() {
    const btns = document.querySelectorAll('.topology-controls .topo-btn');
    for (const btn of btns) {
      const ctrl = btn.dataset.control;
      if (ctrl === 'constraints') {
        btn.addEventListener('click', () => {
          GavelState.toggleFilter('showConstraints');
          btn.classList.toggle('active');
        });
      } else if (ctrl === 'inactive') {
        btn.addEventListener('click', () => {
          GavelState.toggleFilter('showInactiveAgents');
          btn.classList.toggle('active');
        });
      } else if (ctrl === 'chains') {
        btn.addEventListener('click', () => {
          GavelState.toggleFilter('showChainFlows');
          btn.classList.toggle('active');
        });
      } else if (ctrl === 'focus') {
        btn.addEventListener('click', () => {
          GavelState.toggleFocus();
          btn.classList.toggle('active', GavelState.focusMode);
        });
      } else if (ctrl === 'zoom-reset') {
        btn.addEventListener('click', () => this.resetZoom());
      } else if (ctrl === 'export-svg') {
        btn.addEventListener('click', () => this.exportSVG());
      }
    }
  }

  // -----------------------------------------------------------------------
  // Size management
  // -----------------------------------------------------------------------

  _updateSize() {
    const el = this._svg.node();
    if (!el) return;
    const rect = el.getBoundingClientRect();
    this._width = rect.width || 800;
    this._height = rect.height || 600;
  }

  // -----------------------------------------------------------------------
  // Main render
  // -----------------------------------------------------------------------

  render(state) {
    this._updateSize();
    const { nodes, edges } = state.graph;
    const { selection, filters } = state;
    const w = this._width;
    const h = this._height;

    // Compute layout positions
    this._positions = computeLayout(nodes, w, h);

    // Determine which edges are visible
    const visibleEdges = edges.filter((e) => {
      if (e.type === 'CONSTRAINT' && !filters.showConstraints) return false;
      if (['PROPOSAL', 'APPROVAL', 'DENIAL', 'EXECUTION'].includes(e.type) && !filters.showChainFlows) return false;
      return true;
    });

    // Determine which nodes are visible
    const visibleNodes = nodes.filter((n) => {
      if (n.type === 'POLICY_ENGINE') return true;
      if (!filters.showInactiveAgents && (n.status === 'IDLE' || n.status === 'DEAD')) return false;
      return true;
    });

    const visibleNodeIds = new Set(visibleNodes.map((n) => n.id));

    // Check if there are active chains (for engine pulse)
    const hasActiveChains = Object.values(state.chains || {}).some((c) => {
      const s = (c.status || '').toUpperCase();
      return ['PENDING', 'ESCALATED', 'EVALUATING', 'EXECUTING'].includes(s);
    });

    // Selection context
    const selectedId = selection ? selection.id : null;
    const selectedType = selection ? selection.type : null;
    const selectedEdgeIds = new Set();
    if (selection) {
      for (const e of edges) {
        if (selectedType === 'agent' || selectedType === 'engine') {
          if (e.source === selectedId || e.target === selectedId) selectedEdgeIds.add(e.id);
        } else if (selectedType === 'chain' && e.chainId === selectedId) {
          selectedEdgeIds.add(e.id);
        }
      }
    }

    // Focus mode: compute the subgraph of the selected entity
    const focusNodeIds = new Set();
    if (state.focusMode && selection) {
      focusNodeIds.add('policy-engine');
      if (selection.type === 'agent' || selection.type === 'engine') {
        focusNodeIds.add(selection.id);
        for (const e of edges) {
          if (e.source === selection.id || e.target === selection.id) {
            focusNodeIds.add(e.source);
            focusNodeIds.add(e.target);
          }
        }
      } else if (selection.type === 'chain') {
        for (const e of edges) {
          if (e.chainId === selection.id) {
            focusNodeIds.add(e.source);
            focusNodeIds.add(e.target);
          }
        }
      }
    }

    this._renderEdges(visibleEdges, visibleNodeIds, selection, selectedEdgeIds, state.focusMode, focusNodeIds);
    this._renderNodes(visibleNodes, selection, hasActiveChains, state.focusMode, focusNodeIds);
  }

  // -----------------------------------------------------------------------
  // Edge rendering
  // -----------------------------------------------------------------------

  _renderEdges(edges, visibleNodeIds, selection, selectedEdgeIds, focusMode = false, focusNodeIds = null) {
    const pos = this._positions;

    // Filter edges whose endpoints are visible
    const drawn = edges.filter((e) => visibleNodeIds.has(e.source) && visibleNodeIds.has(e.target));

    const edgeSel = this._edgeG.selectAll('.topo-edge').data(drawn, (d) => d.id);

    // EXIT
    edgeSel.exit()
      .transition().duration(300).attr('opacity', 0).remove();

    // ENTER
    const enter = edgeSel.enter()
      .append('path')
      .attr('class', 'topo-edge')
      .attr('fill', 'none')
      .attr('opacity', 0);

    // ENTER + UPDATE
    const merged = enter.merge(edgeSel);

    merged.each(function (d) {
      const el = d3.select(this);
      const style = EDGE_STYLES[d.type] || EDGE_STYLES.ENROLLMENT;
      const sp = pos.get(d.source);
      const tp = pos.get(d.target);
      if (!sp || !tp) return;

      // Offset endpoints by node radius
      const srcRadius = d.source === 'policy-engine' ? ENGINE_RADIUS : AGENT_RADIUS;
      const tgtRadius = d.target === 'policy-engine' ? ENGINE_RADIUS : AGENT_RADIUS;

      // Compute cubic bezier
      const dx = tp.x - sp.x;
      const cpOffset = Math.abs(dx) * 0.4;
      const path = `M${sp.x},${sp.y} C${sp.x + cpOffset},${sp.y} ${tp.x - cpOffset},${tp.y} ${tp.x},${tp.y}`;

      el.attr('d', path)
        .attr('stroke', style.stroke)
        .attr('stroke-width', style.width)
        .attr('marker-end', `url(#arrow-${d.type})`);

      if (style.dash) {
        el.attr('stroke-dasharray', style.dash);
      } else {
        el.attr('stroke-dasharray', null);
      }

      // Path emphasis animations
      el.classed('edge-animated', false)
        .classed('edge-pulse-amber', false)
        .classed('edge-pulse-green', false)
        .classed('edge-pulse-cyan', false)
        .classed('edge-denied', false);

      if (d.animated) {
        if (d.type === 'PROPOSAL') el.classed('edge-pulse-amber', true);
        else if (d.type === 'APPROVAL') el.classed('edge-pulse-green', true);
        else if (d.type === 'EXECUTION') el.classed('edge-pulse-cyan', true);
        else if (style.anim) el.classed('edge-animated', true);
      }
      if (d.type === 'DENIAL') el.classed('edge-denied', true);
    });

    // Opacity based on selection and focus mode
    merged.each(function (d) {
      const el = d3.select(this);
      if (focusMode && focusNodeIds) {
        const inFocus = focusNodeIds.has(d.source) && focusNodeIds.has(d.target);
        el.classed('focus-dimmed', !inFocus).classed('focus-visible', inFocus);
      } else {
        el.classed('focus-dimmed', false).classed('focus-visible', false);
      }
    });

    merged.transition().duration(TRANSITION_MS)
      .attr('opacity', (d) => {
        if (focusMode && focusNodeIds) {
          return (focusNodeIds.has(d.source) && focusNodeIds.has(d.target)) ? 1 : 0.05;
        }
        if (!selection) return 0.8;
        return selectedEdgeIds.has(d.id) ? 1 : 0.15;
      });
  }

  // -----------------------------------------------------------------------
  // Node rendering
  // -----------------------------------------------------------------------

  _renderNodes(nodes, selection, hasActiveChains, focusMode = false, focusNodeIds = null) {
    const pos = this._positions;
    const selectedId = selection ? selection.id : null;
    const self = this;

    const nodeSel = this._nodeG.selectAll('.topo-node').data(nodes, (d) => d.id);

    // EXIT
    nodeSel.exit()
      .transition().duration(200)
      .attr('transform', (d) => {
        const p = pos.get(d.id) || { x: 0, y: 0 };
        return `translate(${p.x},${p.y}) scale(0)`;
      })
      .remove();

    // ENTER
    const enter = nodeSel.enter()
      .append('g')
      .attr('class', 'topo-node')
      .attr('cursor', 'pointer')
      .attr('opacity', 0)
      .attr('transform', (d) => {
        const p = pos.get(d.id) || { x: 0, y: 0 };
        return `translate(${p.x},${p.y}) scale(1)`;
      });

    // Build inner elements on enter
    enter.each(function (d) {
      const g = d3.select(this);

      if (d.type === 'POLICY_ENGINE') {
        // Hexagon
        g.append('path')
          .attr('class', 'engine-shape')
          .attr('d', hexagonPath(0, 0, ENGINE_RADIUS))
          .attr('fill', 'url(#engine-gradient)')
          .attr('stroke', '#6c5ce7')
          .attr('stroke-width', 2);

        // Label inside
        g.append('text')
          .attr('class', 'engine-label')
          .attr('text-anchor', 'middle')
          .attr('dominant-baseline', 'central')
          .attr('fill', '#ffffff')
          .attr('font-size', '15px')
          .attr('font-weight', '700')
          .attr('font-family', "'Inter', sans-serif")
          .text('Policy')
          .attr('y', -9);
        g.append('text')
          .attr('class', 'engine-label-2')
          .attr('text-anchor', 'middle')
          .attr('dominant-baseline', 'central')
          .attr('fill', '#ffffff')
          .attr('font-size', '15px')
          .attr('font-weight', '700')
          .attr('font-family', "'Inter', sans-serif")
          .text('Engine')
          .attr('y', 11);
      } else {
        // Agent circle
        g.append('circle')
          .attr('class', 'agent-circle')
          .attr('r', AGENT_RADIUS)
          .attr('stroke-width', 2);

        // Trust score arc
        g.append('path')
          .attr('class', 'trust-arc')
          .attr('fill', '#6c5ce7')
          .attr('opacity', 0.7);

        // Status dot
        g.append('circle')
          .attr('class', 'status-dot')
          .attr('r', 4)
          .attr('cx', AGENT_RADIUS * 0.65)
          .attr('cy', -AGENT_RADIUS * 0.65);

        // Label above
        g.append('text')
          .attr('class', 'node-label')
          .attr('text-anchor', 'middle')
          .attr('fill', '#e8e8ef')
          .attr('font-size', '14px')
          .attr('font-weight', '600')
          .attr('font-family', "'Inter', sans-serif")
          .attr('y', -AGENT_RADIUS - 12);

        // Tier badge below
        g.append('text')
          .attr('class', 'tier-badge')
          .attr('text-anchor', 'middle')
          .attr('fill', '#9898a8')
          .attr('font-size', '10px')
          .attr('font-family', "'JetBrains Mono', monospace")
          .attr('y', AGENT_RADIUS + 20);
      }
    });

    // ENTER + UPDATE
    const merged = enter.merge(nodeSel);

    // Update positions with transition
    merged.transition().duration(TRANSITION_MS).ease(d3.easeCubicOut)
      .attr('transform', (d) => {
        const p = pos.get(d.id) || { x: 0, y: 0 };
        return `translate(${p.x},${p.y}) scale(1)`;
      });

    // Update node visuals
    merged.each(function (d) {
      const g = d3.select(this);
      const isSelected = d.id === selectedId;

      if (d.type === 'POLICY_ENGINE') {
        g.select('.engine-shape')
          .classed('engine-pulsing', hasActiveChains)
          .attr('filter', isSelected ? 'url(#glow-selected)' : null);

        g.on('click', () => GavelState.setSelection('engine', 'policy-engine'));
      } else {
        const color = STATUS_COLORS[d.status] || STATUS_COLORS.IDLE;

        g.select('.agent-circle')
          .transition().duration(400)
          .attr('fill', color)
          .attr('stroke', isSelected ? '#fdcb6e' : 'rgba(255,255,255,0.08)')
          .attr('filter', isSelected ? 'url(#glow-selected)' : null);

        g.select('.trust-arc')
          .attr('d', trustArc(d.trustScore, AGENT_RADIUS));

        g.select('.status-dot')
          .attr('fill', color);

        g.select('.node-label')
          .text(d.label);

        g.select('.tier-badge')
          .text(TIER_NAMES[d.tier] || TIER_NAMES[0]);

        g.on('click', () => GavelState.setSelection('agent', d.id));
      }

      // Hover behavior
      g.on('mouseover', function (event) {
        d3.select(this).transition().duration(150)
          .attr('transform', () => {
            const p = pos.get(d.id) || { x: 0, y: 0 };
            return `translate(${p.x},${p.y}) scale(1.1)`;
          });

        let tip = '';
        if (d.type === 'POLICY_ENGINE') {
          tip = 'Policy Engine\nGavel governance core';
        } else {
          tip = `${d.id}\nType: ${d.data.agent_type || 'unknown'}\nTrust: ${d.trustScore}/1000`;
        }
        self._tooltip
          .style('display', 'block')
          .style('left', (event.pageX + 12) + 'px')
          .style('top', (event.pageY - 10) + 'px')
          .text(tip);
      })
      .on('mousemove', function (event) {
        self._tooltip
          .style('left', (event.pageX + 12) + 'px')
          .style('top', (event.pageY - 10) + 'px');
      })
      .on('mouseout', function () {
        d3.select(this).transition().duration(150)
          .attr('transform', () => {
            const p = pos.get(d.id) || { x: 0, y: 0 };
            return `translate(${p.x},${p.y}) scale(1)`;
          });
        self._tooltip.style('display', 'none');
      });

      // Focus mode and selection dimming
      if (focusMode && focusNodeIds) {
        const inFocus = focusNodeIds.has(d.id);
        g.classed('focus-dimmed', !inFocus).classed('focus-visible', inFocus);
        g.transition().duration(TRANSITION_MS).attr('opacity', inFocus ? 1 : 0.08);
      } else if (selection && d.id !== selectedId) {
        g.classed('focus-dimmed', false).classed('focus-visible', false);
        g.transition().duration(TRANSITION_MS).attr('opacity', 0.4);
      } else {
        g.classed('focus-dimmed', false).classed('focus-visible', false);
        g.transition().duration(TRANSITION_MS).attr('opacity', 1);
      }
    });
  }

  // -----------------------------------------------------------------------
  // Public API
  // -----------------------------------------------------------------------

  resetZoom() {
    this._updateSize();
    this._svg.transition().duration(500)
      .call(this._zoom.transform, d3.zoomIdentity
        .translate(this._width * 0.05, this._height * 0.05)
        .scale(0.9));
  }

  exportSVG() {
    const svgEl = this._svg.node();
    if (!svgEl) return;

    // Clone SVG
    const clone = svgEl.cloneNode(true);

    // Set explicit dimensions
    clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
    clone.setAttribute('width', this._width);
    clone.setAttribute('height', this._height);

    // Inline background
    clone.style.backgroundColor = '#0c0c14';

    // Inline font
    const styleEl = document.createElementNS('http://www.w3.org/2000/svg', 'style');
    styleEl.textContent = `
      @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
      text { font-family: 'Inter', sans-serif; }
    `;
    clone.insertBefore(styleEl, clone.firstChild);

    // Inline computed styles on all elements
    const allEls = clone.querySelectorAll('*');
    for (const el of allEls) {
      const computed = window.getComputedStyle(el);
      if (el.tagName === 'path' || el.tagName === 'circle' || el.tagName === 'line') {
        el.style.fill = computed.fill;
        el.style.stroke = computed.stroke;
        el.style.strokeWidth = computed.strokeWidth;
        el.style.opacity = computed.opacity;
      }
      if (el.tagName === 'text') {
        el.style.fill = computed.fill;
        el.style.fontSize = computed.fontSize;
        el.style.fontFamily = computed.fontFamily;
        el.style.fontWeight = computed.fontWeight;
      }
    }

    const serializer = new XMLSerializer();
    const svgString = serializer.serializeToString(clone);
    const blob = new Blob([svgString], { type: 'image/svg+xml;charset=utf-8' });
    const url = URL.createObjectURL(blob);

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const a = document.createElement('a');
    a.href = url;
    a.download = `gavel-topology-${timestamp}.svg`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }
}
