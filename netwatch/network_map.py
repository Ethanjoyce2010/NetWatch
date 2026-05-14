"""
Network map visualization for NetWatch.

Generates a self-contained HTML/SVG graph of local processes, remote endpoints,
and connection counts. In live mode the CLI rewrites the file on each poll and
the page refreshes itself.
"""

from __future__ import annotations

import html
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from .models import Alert, ConnectionRecord, Severity


@dataclass
class NetworkMapData:
    """Aggregated process-to-endpoint graph data."""

    nodes: list[dict]
    edges: list[dict]
    process_count: int
    endpoint_count: int
    connection_count: int
    alert_count: int


class NetworkMapGenerator:
    """Builds an HTML network map from observed connection records."""

    def build_data(
        self,
        records: list[ConnectionRecord],
        alerts: Optional[list[Alert]] = None,
    ) -> NetworkMapData:
        """Aggregate records into graph nodes and weighted edges."""
        alerts = alerts or []
        process_alerts: dict[int, list[Alert]] = defaultdict(list)
        endpoint_alerts: dict[str, list[Alert]] = defaultdict(list)
        for alert in alerts:
            process_alerts[alert.pid].append(alert)
            remote_addr = alert.details.get("remote_addr") if alert.details else None
            if remote_addr:
                endpoint_alerts[str(remote_addr)].append(alert)

        processes: dict[int, dict] = {}
        endpoints: dict[str, dict] = {}
        edges: Counter[tuple[int, str, str]] = Counter()

        for rec in records:
            processes.setdefault(rec.pid, {
                "id": f"p:{rec.pid}",
                "kind": "process",
                "pid": rec.pid,
                "label": rec.process_name,
                "risk": self._risk_for_alerts(process_alerts.get(rec.pid, [])),
                "alerts": len(process_alerts.get(rec.pid, [])),
            })
            if rec.remote_addr:
                endpoint_key = rec.remote_addr
                endpoints.setdefault(endpoint_key, {
                    "id": f"r:{endpoint_key}",
                    "kind": "endpoint",
                    "label": endpoint_key,
                    "port_count": 0,
                    "alerts": len(endpoint_alerts.get(endpoint_key, [])),
                })
                endpoint_ports = endpoints[endpoint_key].setdefault("_ports", set())
                endpoint_ports.add(rec.remote_port)
                edges[(rec.pid, endpoint_key, rec.protocol)] += 1

        for endpoint in endpoints.values():
            endpoint["port_count"] = len(endpoint.pop("_ports", set()))

        nodes = list(processes.values()) + list(endpoints.values())
        edge_rows = [
            {
                "source": f"p:{pid}",
                "target": f"r:{remote}",
                "protocol": protocol,
                "count": count,
            }
            for (pid, remote, protocol), count in edges.items()
        ]

        return NetworkMapData(
            nodes=nodes,
            edges=edge_rows,
            process_count=len(processes),
            endpoint_count=len(endpoints),
            connection_count=len(records),
            alert_count=len(alerts),
        )

    def generate(
        self,
        output_path: str,
        records: list[ConnectionRecord],
        *,
        alerts: Optional[list[Alert]] = None,
        refresh_seconds: Optional[int] = None,
    ) -> str:
        """Generate a network-map HTML file and return the absolute path."""
        data = self.build_data(records, alerts=alerts)
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(self.render(data, refresh_seconds=refresh_seconds), encoding="utf-8")
        return str(out.resolve())

    def render(self, data: NetworkMapData, refresh_seconds: Optional[int] = None) -> str:
        """Render map data as self-contained HTML."""
        graph = {
            "nodes": data.nodes,
            "edges": data.edges,
        }
        meta_refresh = (
            f'<meta http-equiv="refresh" content="{int(refresh_seconds)}">'
            if refresh_seconds else ""
        )
        generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
{meta_refresh}
<title>NetWatch Network Map</title>
<style>
:root {{
  --bg: #0f172a;
  --panel: #111827;
  --text: #e5e7eb;
  --muted: #94a3b8;
  --line: #475569;
  --process: #38bdf8;
  --endpoint: #a7f3d0;
  --alert: #fb7185;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  font-family: Arial, sans-serif;
  background: var(--bg);
  color: var(--text);
}}
header {{
  padding: 16px 20px;
  background: var(--panel);
  border-bottom: 1px solid #334155;
}}
h1 {{ margin: 0 0 6px; font-size: 22px; }}
.meta {{ color: var(--muted); font-size: 13px; }}
.stats {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 10px;
  padding: 14px 20px;
}}
.stat {{
  background: var(--panel);
  border: 1px solid #334155;
  border-radius: 8px;
  padding: 12px;
}}
.value {{ display: block; font-size: 24px; font-weight: 700; }}
.label {{ color: var(--muted); font-size: 12px; }}
#map {{
  width: 100%;
  height: calc(100vh - 155px);
  min-height: 480px;
}}
line {{ stroke: var(--line); stroke-linecap: round; }}
.node text {{ fill: var(--text); font-size: 12px; pointer-events: none; }}
.node circle {{ stroke: #0f172a; stroke-width: 2; }}
.legend {{
  position: fixed;
  right: 16px;
  bottom: 16px;
  background: rgba(17, 24, 39, 0.92);
  border: 1px solid #334155;
  border-radius: 8px;
  padding: 10px 12px;
  color: var(--muted);
  font-size: 12px;
}}
</style>
</head>
<body>
<header>
  <h1>NetWatch Network Map</h1>
  <div class="meta">Generated {html.escape(generated)}{self._refresh_text(refresh_seconds)}</div>
</header>
<section class="stats">
  <div class="stat"><span class="value">{data.process_count}</span><span class="label">Processes</span></div>
  <div class="stat"><span class="value">{data.endpoint_count}</span><span class="label">Remote Endpoints</span></div>
  <div class="stat"><span class="value">{data.connection_count}</span><span class="label">Connections</span></div>
  <div class="stat"><span class="value">{data.alert_count}</span><span class="label">Alerts</span></div>
</section>
<svg id="map" role="img" aria-label="Network process to endpoint map"></svg>
<div class="legend">
  <div>Blue: process</div>
  <div>Green: remote endpoint</div>
  <div>Red ring: alert activity</div>
</div>
<script>
const graph = {json.dumps(graph)};
const svg = document.getElementById("map");
const width = svg.clientWidth || window.innerWidth;
const height = svg.clientHeight || 520;
svg.setAttribute("viewBox", `0 0 ${{width}} ${{height}}`);

const processes = graph.nodes.filter(n => n.kind === "process");
const endpoints = graph.nodes.filter(n => n.kind === "endpoint");
const byId = Object.fromEntries(graph.nodes.map(n => [n.id, n]));
const yFor = (index, total) => total <= 1 ? height / 2 : 50 + index * ((height - 100) / (total - 1));

processes.forEach((node, i) => {{
  node.x = Math.max(170, width * 0.24);
  node.y = yFor(i, processes.length);
}});
endpoints.forEach((node, i) => {{
  node.x = Math.min(width - 190, width * 0.76);
  node.y = yFor(i, endpoints.length);
}});

for (const edge of graph.edges) {{
  const source = byId[edge.source];
  const target = byId[edge.target];
  if (!source || !target) continue;
  const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
  line.setAttribute("x1", source.x);
  line.setAttribute("y1", source.y);
  line.setAttribute("x2", target.x);
  line.setAttribute("y2", target.y);
  line.setAttribute("stroke-width", Math.min(10, 1 + edge.count));
  line.setAttribute("opacity", "0.72");
  const title = document.createElementNS("http://www.w3.org/2000/svg", "title");
  title.textContent = `${{source.label}} -> ${{target.label}} (${{edge.protocol}}, ${{edge.count}} connection(s))`;
  line.appendChild(title);
  svg.appendChild(line);
}}

for (const node of graph.nodes) {{
  const group = document.createElementNS("http://www.w3.org/2000/svg", "g");
  group.setAttribute("class", "node");

  const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
  circle.setAttribute("cx", node.x);
  circle.setAttribute("cy", node.y);
  circle.setAttribute("r", node.kind === "process" ? 18 : 14);
  circle.setAttribute("fill", node.kind === "process" ? "var(--process)" : "var(--endpoint)");
  if (node.alerts > 0 || node.risk > 0) {{
    circle.setAttribute("stroke", "var(--alert)");
    circle.setAttribute("stroke-width", "4");
  }}
  group.appendChild(circle);

  const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
  text.setAttribute("x", node.kind === "process" ? node.x - 28 : node.x + 24);
  text.setAttribute("y", node.y + 4);
  text.setAttribute("text-anchor", node.kind === "process" ? "end" : "start");
  text.textContent = node.kind === "process" ? `${{node.label}} (${{node.pid}})` : node.label;
  group.appendChild(text);

  const title = document.createElementNS("http://www.w3.org/2000/svg", "title");
  title.textContent = JSON.stringify(node, null, 2);
  group.appendChild(title);
  svg.appendChild(group);
}}
</script>
</body>
</html>"""

    @staticmethod
    def _risk_for_alerts(alerts: list[Alert]) -> int:
        if not alerts:
            return 0
        score = sum(
            {
                Severity.LOW: 5,
                Severity.MEDIUM: 15,
                Severity.HIGH: 30,
                Severity.CRITICAL: 50,
            }.get(alert.severity, 5)
            for alert in alerts
        )
        return min(score, 100)

    @staticmethod
    def _refresh_text(refresh_seconds: Optional[int]) -> str:
        if not refresh_seconds:
            return ""
        return f" - auto-refreshes every {int(refresh_seconds)}s"
