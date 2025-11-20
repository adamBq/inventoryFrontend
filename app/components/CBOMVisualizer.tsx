"use client";

import React, {
  useState,
  useMemo,
  useCallback,
  useRef,
  ChangeEvent,
} from "react";
import {
  Upload,
  Shield,
  AlertTriangle,
  CheckCircle,
  FileCode,
  Key,
  Lock,
  Hash,
  Grid,
  BarChart3,
  XCircle,
  Network,
} from "lucide-react";
import ForceGraph2D, {
  ForceGraphMethods,
  GraphData,
  NodeObject,
  LinkObject,
} from "react-force-graph-2d";

// ---- Types ----

interface CbomProperty {
  name: string;
  value?: string;
}

interface EvidenceOccurrence {
  file?: string;
  line?: number;
  snippet?: string;
}

interface Evidence {
  occurrences: EvidenceOccurrence[];
}

interface CbomComponent {
  "bom-ref": string;
  name: string;
  type: string; // 'file' | 'data' | etc.
  properties?: CbomProperty[];
  hashes?: { alg?: string; content: string }[];
  evidence?: Evidence;
}

interface CbomDependency {
  ref: string;
  dependsOn?: string[];
}

interface CbomMetadata {
  timestamp?: string;
}

interface CbomData {
  components?: CbomComponent[];
  dependencies?: CbomDependency[];
  metadata?: CbomMetadata;
}

interface CryptoStats {
  total: number;
  byPrimitive: Record<string, number>;
  byProvider: Record<string, number>;
  byVulnerability: Record<string, number>;
  byOperation: Record<string, number>;
  weaknesses: {
    name: string;
    weakness: string;
    file: string;
  }[];
}

type GraphNode = NodeObject & {
  id: string;
  name: string;
  type: string;
  color?: string;
  component: CbomComponent;
};

type GraphLink = LinkObject & {
  source: string;
  target: string;
  value: number;
};

// ---- Component ----

const CBOMVisualizer: React.FC = () => {
  const [cbomData, setCbomData] = useState<CbomData | null>(null);
  const [activeTab, setActiveTab] = useState<
    "overview" | "graph" | "crypto" | "files"
  >("overview");
  const [selectedCategory, setSelectedCategory] = useState<string>("all");
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const graphRef = useRef<ForceGraphMethods | null>(null);

  const handleFileUpload = async (
    event: ChangeEvent<HTMLInputElement>
  ): Promise<void> => {
    const file = event.target.files?.[0];
    if (file) {
      try {
        const text = await file.text();
        const data = JSON.parse(text) as CbomData;
        setCbomData(data);
        setSelectedNode(null);
      } catch (error) {
        alert("Error parsing JSON file. Please ensure it's a valid CBOM file.");
        console.error(error);
      }
    }
  };

  const cryptoStats = useMemo<CryptoStats | null>(() => {
    if (!cbomData?.components) return null;

    const cryptoComponents = cbomData.components.filter(
      (c) => c.type === "data"
    );

    const stats: CryptoStats = {
      total: cryptoComponents.length,
      byPrimitive: {},
      byProvider: {},
      byVulnerability: {},
      byOperation: {},
      weaknesses: [],
    };

    cryptoComponents.forEach((comp) => {
      const props = (comp.properties ?? []).reduce<Record<string, string>>(
        (acc, p) => {
          acc[p.name] = p.value ?? "";
          return acc;
        },
        {}
      );

      // By primitive
      const primitive = props.primitive || "unknown";
      stats.byPrimitive[primitive] = (stats.byPrimitive[primitive] || 0) + 1;

      // By provider
      const provider = props.provider || "unknown";
      stats.byProvider[provider] = (stats.byProvider[provider] || 0) + 1;

      // By vulnerability
      const vuln = props["pqm.vulnerability"] || "unknown";
      stats.byVulnerability[vuln] =
        (stats.byVulnerability[vuln] || 0) + 1;

      // By operation
      const op = props.operation || "unknown";
      stats.byOperation[op] = (stats.byOperation[op] || 0) + 1;

      // Weaknesses
      if (props.weaknesses && props.weaknesses.trim()) {
        const firstOcc =
          comp.evidence?.occurrences?.[0]?.file ?? "unknown";
        stats.weaknesses.push({
          name: comp.name,
          weakness: props.weaknesses,
          file: firstOcc,
        });
      }
    });

    return stats;
  }, [cbomData]);

  const graphData = useMemo<GraphData>(() => {
    if (!cbomData?.components) return { nodes: [], links: [] };

    const nodes: GraphNode[] = [];
    const links: GraphLink[] = [];
    const nodeMap = new Map<string, GraphNode>();

    // Add all components as nodes
    cbomData.components.forEach((comp) => {
      const node: GraphNode = {
        id: comp["bom-ref"],
        name: comp.name,
        type: comp.type,
        component: comp,
      };

      // Add color based on type
      if (comp.type === "file") {
        node.color = "#60a5fa"; // blue
      } else if (comp.type === "data") {
        const props = (comp.properties ?? []).reduce<
          Record<string, string>
        >((acc, p) => {
          acc[p.name] = p.value ?? "";
          return acc;
        }, {});

        // Color by vulnerability
        const vuln = props["pqm.vulnerability"];
        if (vuln === "quantum-vulnerable") {
          node.color = "#ef4444"; // red
        } else if (vuln === "symmetric-safe") {
          node.color = "#10b981"; // green
        } else {
          node.color = "#9ca3af"; // gray
        }
      } else {
        node.color = "#9ca3af";
      }

      nodes.push(node);
      nodeMap.set(node.id, node);
    });

    // Add dependencies as links
    if (cbomData.dependencies) {
      cbomData.dependencies.forEach((dep) => {
        const sourceNode = nodeMap.get(dep.ref);
        if (dep.dependsOn && sourceNode) {
          dep.dependsOn.forEach((targetRef) => {
            const targetNode = nodeMap.get(targetRef);
            if (targetNode) {
              links.push({
                source: dep.ref,
                target: targetRef,
                value: 1,
              });
            }
          });
        }
      });
    }

    return { nodes, links };
  }, [cbomData]);

  const handleNodeClick = useCallback((node: NodeObject) => {
    setSelectedNode(node as GraphNode);
  }, []);

  const getVulnerabilityColor = (vuln?: string) => {
    switch (vuln) {
      case "quantum-vulnerable":
        return "text-red-600 bg-red-50";
      case "symmetric-safe":
        return "text-green-600 bg-green-50";
      case "unknown":
        return "text-gray-600 bg-gray-50";
      default:
        return "text-blue-600 bg-blue-50";
    }
  };

  const getPrimitiveIcon = (primitive?: string) => {
    switch (primitive) {
      case "signature":
        return <Key className="w-4 h-4" />;
      case "aead":
      case "cipher":
        return <Lock className="w-4 h-4" />;
      case "hash":
      case "mac":
        return <Hash className="w-4 h-4" />;
      case "kdf":
      case "rng":
        return <Grid className="w-4 h-4" />;
      default:
        return <Shield className="w-4 h-4" />;
    }
  };

  if (!cbomData) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 p-8">
        <div className="max-w-4xl mx-auto">
          <div className="bg-white rounded-lg shadow-lg p-12 text-center">
            <Shield className="w-16 h-16 text-indigo-600 mx-auto mb-6" />
            <h1 className="text-3xl font-bold text-gray-800 mb-4">
              CBOM Cryptographic Inventory Visualizer
            </h1>
            <p className="text-gray-600 mb-8">
              Upload a CycloneDX CBOM JSON file to analyze cryptographic
              components
            </p>
            <label className="inline-flex items-center gap-3 px-6 py-3 bg-indigo-600 text-white rounded-lg cursor-pointer hover:bg-indigo-700 transition-colors">
              <Upload className="w-5 h-5" />
              <span className="font-medium">Upload CBOM File</span>
              <input
                type="file"
                accept=".json"
                onChange={handleFileUpload}
                className="hidden"
              />
            </label>
          </div>
        </div>
      </div>
    );
  }

  const cryptoComponents =
    cbomData.components?.filter((c) => c.type === "data") ?? [];
  const fileComponents =
    cbomData.components?.filter((c) => c.type === "file") ?? [];

  const filteredCrypto = selectedCategory === "all"
    ? cryptoComponents
    : cryptoComponents.filter((c) => {
        const props = (c.properties ?? []).reduce<Record<string, string>>(
          (acc, p) => {
            acc[p.name] = p.value ?? "";
            return acc;
          },
          {}
        );
        return props.primitive === selectedCategory;
      });

  return (
    <div className="min-h-screen bg-gray-50 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="bg-white rounded-lg shadow-md p-6 mb-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <Shield className="w-8 h-8 text-indigo-600" />
              <div>
                <h1 className="text-2xl font-bold text-gray-800">
                  CBOM Analysis
                </h1>
                <p className="text-sm text-gray-600">
                  {cbomData.metadata?.timestamp || "No timestamp"}
                </p>
              </div>
            </div>
            <label className="inline-flex items-center gap-2 px-4 py-2 bg-indigo-100 text-indigo-700 rounded-lg cursor-pointer hover:bg-indigo-200 transition-colors text-sm">
              <Upload className="w-4 h-4" />
              Upload New
              <input
                type="file"
                accept=".json"
                onChange={handleFileUpload}
                className="hidden"
              />
            </label>
          </div>
        </div>

        {/* Tabs */}
        <div className="bg-white rounded-lg shadow-md mb-6">
          <div className="flex border-b">
            <button
              onClick={() => setActiveTab("overview")}
              className={`px-6 py-3 font-medium transition-colors ${
                activeTab === "overview"
                  ? "text-indigo-600 border-b-2 border-indigo-600"
                  : "text-gray-600 hover:text-gray-800"
              }`}
            >
              <div className="flex items-center gap-2">
                <BarChart3 className="w-4 h-4" />
                Overview
              </div>
            </button>
            <button
              onClick={() => setActiveTab("graph")}
              className={`px-6 py-3 font-medium transition-colors ${
                activeTab === "graph"
                  ? "text-indigo-600 border-b-2 border-indigo-600"
                  : "text-gray-600 hover:text-gray-800"
              }`}
            >
              <div className="flex items-center gap-2">
                <Network className="w-4 h-4" />
                Graph
              </div>
            </button>
            <button
              onClick={() => setActiveTab("crypto")}
              className={`px-6 py-3 font-medium transition-colors ${
                activeTab === "crypto"
                  ? "text-indigo-600 border-b-2 border-indigo-600"
                  : "text-gray-600 hover:text-gray-800"
              }`}
            >
              <div className="flex items-center gap-2">
                <Lock className="w-4 h-4" />
                Cryptography
              </div>
            </button>
            <button
              onClick={() => setActiveTab("files")}
              className={`px-6 py-3 font-medium transition-colors ${
                activeTab === "files"
                  ? "text-indigo-600 border-b-2 border-indigo-600"
                  : "text-gray-600 hover:text-gray-800"
              }`}
            >
              <div className="flex items-center gap-2">
                <FileCode className="w-4 h-4" />
                Files
              </div>
            </button>
          </div>
        </div>

        {/* Graph Tab */}
        {activeTab === "graph" && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Graph Visualization */}
            <div
              className="lg:col-span-2 bg-white rounded-lg shadow-md overflow-hidden"
              style={{ height: "700px" }}
            >
              <div className="bg-gray-50 border-b px-4 py-3">
                <h3 className="font-semibold text-gray-800">
                  Dependency Graph
                </h3>
                <div className="flex items-center gap-4 mt-2 text-xs">
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-full bg-blue-400" />
                    <span className="text-gray-600">Files</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-full bg-red-400" />
                    <span className="text-gray-600">
                      Quantum Vulnerable
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-full bg-green-400" />
                    <span className="text-gray-600">Symmetric Safe</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-full bg-gray-400" />
                    <span className="text-gray-600">Unknown/Other</span>
                  </div>
                </div>
              </div>
              <ForceGraph2D
                ref={graphRef as any}
                graphData={graphData}
                nodeLabel="name"
                nodeColor="color"
                nodeRelSize={6}
                linkDirectionalParticles={2}
                linkDirectionalParticleWidth={2}
                onNodeClick={handleNodeClick}
                nodeCanvasObject={(
                  node: NodeObject,
                  ctx: CanvasRenderingContext2D,
                  globalScale: number
                ) => {
                  const n = node as GraphNode;
                  const label = n.name;
                  const fontSize = 12 / globalScale;
                  ctx.font = `${fontSize}px Sans-Serif`;

                  // Draw node circle
                  ctx.beginPath();
                  ctx.arc(
                    n.x ?? 0,
                    n.y ?? 0,
                    5,
                    0,
                    2 * Math.PI,
                    false
                  );
                  ctx.fillStyle = n.color ?? "#9ca3af";
                  ctx.fill();

                  // Draw label
                  ctx.textAlign = "center";
                  ctx.textBaseline = "middle";
                  ctx.fillStyle = "#1f2937";
                  ctx.fillText(label, n.x ?? 0, (n.y ?? 0) + 10);

                  // Highlight selected node
                  if (selectedNode && selectedNode.id === n.id) {
                    ctx.beginPath();
                    ctx.arc(
                      n.x ?? 0,
                      n.y ?? 0,
                      8,
                      0,
                      2 * Math.PI,
                      false
                    );
                    ctx.strokeStyle = "#4f46e5";
                    ctx.lineWidth = 2;
                    ctx.stroke();
                  }
                }}
                linkColor={() => "#cbd5e1"}
                linkWidth={1.5}
                cooldownTicks={100}
                d3VelocityDecay={0.3}
              />
            </div>

            {/* Node Details Panel */}
            <div
              className="bg-white rounded-lg shadow-md p-6"
              style={{ height: "700px", overflowY: "auto" }}
            >
              {selectedNode ? (
                <div>
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-bold text-gray-800">
                      Node Details
                    </h3>
                    <button
                      onClick={() => setSelectedNode(null)}
                      className="text-gray-400 hover:text-gray-600"
                    >
                      <XCircle className="w-5 h-5" />
                    </button>
                  </div>

                  <div className="space-y-4">
                    <div>
                      <span className="text-xs font-medium text-gray-500">
                        Type
                      </span>
                      <div className="mt-1">
                        <span
                          className={`inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium ${
                            selectedNode.type === "file"
                              ? "bg-blue-100 text-blue-700"
                              : "bg-purple-100 text-purple-700"
                          }`}
                        >
                          {selectedNode.type === "file" ? (
                            <FileCode className="w-3 h-3" />
                          ) : (
                            <Shield className="w-3 h-3" />
                          )}
                          {selectedNode.type}
                        </span>
                      </div>
                    </div>

                    <div>
                      <span className="text-xs font-medium text-gray-500">
                        Name
                      </span>
                      <div className="mt-1 text-sm font-medium text-gray-800 break-all">
                        {selectedNode.name}
                      </div>
                    </div>

                    {selectedNode.component.hashes &&
                      selectedNode.component.hashes[0]?.content && (
                        <div>
                          <span className="text-xs font-medium text-gray-500">
                            Hash
                          </span>
                          <div className="mt-1 text-xs font-mono text-gray-600 break-all bg-gray-50 p-2 rounded">
                            {selectedNode.component.hashes[0].content}
                          </div>
                        </div>
                      )}

                    {selectedNode.type === "data" &&
                      selectedNode.component.properties && (
                        <div>
                          <span className="text-xs font-medium text-gray-500 mb-2 block">
                            Properties
                          </span>
                          <div className="space-y-2">
                            {selectedNode.component.properties.map(
                              (prop, i) => (
                                <div
                                  key={`${prop.name}-${i}`}
                                  className="bg-gray-50 p-2 rounded"
                                >
                                  <div className="text-xs font-medium text-gray-700">
                                    {prop.name}
                                  </div>
                                  <div className="text-xs text-gray-600 mt-1">
                                    {prop.value || "N/A"}
                                  </div>
                                </div>
                              )
                            )}
                          </div>
                        </div>
                      )}

                    {selectedNode.type === "file" &&
                      selectedNode.component.properties && (
                        <div>
                          <span className="text-xs font-medium text-gray-500 mb-2 block">
                            Impact
                          </span>
                          <div className="space-y-2">
                            {selectedNode.component.properties.map(
                              (prop, i) => (
                                <div
                                  key={`${prop.name}-${i}`}
                                  className="bg-gray-50 p-2 rounded"
                                >
                                  <div className="text-xs font-medium text-gray-700">
                                    {prop.name}
                                  </div>
                                  <div className="text-xs text-gray-600 mt-1">
                                    {prop.value || "N/A"}
                                  </div>
                                </div>
                              )
                            )}
                          </div>
                        </div>
                      )}

                    {selectedNode.component.evidence?.occurrences && (
                      <div>
                        <span className="text-xs font-medium text-gray-500 mb-2 block">
                          Evidence (
                          {selectedNode.component.evidence.occurrences.length}{" "}
                          occurrences)
                        </span>
                        <div className="space-y-2 max-h-64 overflow-y-auto">
                          {selectedNode.component.evidence.occurrences.map(
                            (occ, i) => (
                              <div
                                key={`${occ.file}-${occ.line}-${i}`}
                                className="bg-gray-50 p-2 rounded"
                              >
                                <div className="text-xs font-medium text-gray-800">
                                  {occ.file}:{occ.line}
                                </div>
                                <div className="text-xs text-gray-600 mt-1 font-mono break-all">
                                  {occ.snippet}
                                </div>
                              </div>
                            )
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center h-full text-center">
                  <Network className="w-16 h-16 text-gray-300 mb-4" />
                  <p className="text-gray-500">
                    Click on a node to view details
                  </p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Overview Tab */}
        {activeTab === "overview" && cryptoStats && (
          <div className="space-y-6">
            {/* Summary Cards */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="bg-white rounded-lg shadow-md p-6">
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-sm font-medium text-gray-600">
                    Total Crypto
                  </h3>
                  <Shield className="w-5 h-5 text-indigo-600" />
                </div>
                <p className="text-3xl font-bold text-gray-800">
                  {cryptoStats.total}
                </p>
              </div>

              <div className="bg-white rounded-lg shadow-md p-6">
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-sm font-medium text-gray-600">
                    Quantum Vulnerable
                  </h3>
                  <AlertTriangle className="w-5 h-5 text-red-600" />
                </div>
                <p className="text-3xl font-bold text-red-600">
                  {cryptoStats.byVulnerability["quantum-vulnerable"] || 0}
                </p>
              </div>

              <div className="bg-white rounded-lg shadow-md p-6">
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-sm font-medium text-gray-600">
                    Symmetric Safe
                  </h3>
                  <CheckCircle className="w-5 h-5 text-green-600" />
                </div>
                <p className="text-3xl font-bold text-green-600">
                  {cryptoStats.byVulnerability["symmetric-safe"] || 0}
                </p>
              </div>

              <div className="bg-white rounded-lg shadow-md p-6">
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-sm font-medium text-gray-600">
                    Weaknesses
                  </h3>
                  <XCircle className="w-5 h-5 text-orange-600" />
                </div>
                <p className="text-3xl font-bold text-orange-600">
                  {cryptoStats.weaknesses.length}
                </p>
              </div>
            </div>

            {/* Charts */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* By Primitive */}
              <div className="bg-white rounded-lg shadow-md p-6">
                <h3 className="text-lg font-bold text-gray-800 mb-4">
                  By Primitive Type
                </h3>
                <div className="space-y-3">
                  {Object.entries(cryptoStats.byPrimitive).map(
                    ([key, value]) => (
                      <div key={key}>
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-sm font-medium text-gray-700 capitalize">
                            {key}
                          </span>
                          <span className="text-sm font-bold text-gray-800">
                            {value}
                          </span>
                        </div>
                        <div className="w-full bg-gray-200 rounded-full h-2">
                          <div
                            className="bg-indigo-600 h-2 rounded-full"
                            style={{
                              width: `${
                                (value / cryptoStats.total) * 100
                              }%`,
                            }}
                          />
                        </div>
                      </div>
                    )
                  )}
                </div>
              </div>

              {/* By Provider */}
              <div className="bg-white rounded-lg shadow-md p-6">
                <h3 className="text-lg font-bold text-gray-800 mb-4">
                  By Provider
                </h3>
                <div className="space-y-3">
                  {Object.entries(cryptoStats.byProvider).map(
                    ([key, value]) => (
                      <div key={key}>
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-sm font-medium text-gray-700">
                            {key}
                          </span>
                          <span className="text-sm font-bold text-gray-800">
                            {value}
                          </span>
                        </div>
                        <div className="w-full bg-gray-200 rounded-full h-2">
                          <div
                            className="bg-green-600 h-2 rounded-full"
                            style={{
                              width: `${
                                (value / cryptoStats.total) * 100
                              }%`,
                            }}
                          />
                        </div>
                      </div>
                    )
                  )}
                </div>
              </div>
            </div>

            {/* Weaknesses Alert */}
            {cryptoStats.weaknesses.length > 0 && (
              <div className="bg-orange-50 border border-orange-200 rounded-lg p-6">
                <div className="flex items-center gap-2 mb-4">
                  <AlertTriangle className="w-5 h-5 text-orange-600" />
                  <h3 className="text-lg font-bold text-orange-800">
                    Identified Weaknesses
                  </h3>
                </div>
                <div className="space-y-2">
                  {cryptoStats.weaknesses.map((w, i) => (
                    <div
                      key={`${w.name}-${i}`}
                      className="bg-white rounded p-3 text-sm"
                    >
                      <div className="font-medium text-gray-800">
                        {w.name}
                      </div>
                      <div className="text-orange-600">{w.weakness}</div>
                      <div className="text-gray-500 text-xs mt-1">
                        {w.file}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Crypto Tab */}
        {activeTab === "crypto" && cryptoStats && (
          <div className="space-y-6">
            {/* Filter */}
            <div className="bg-white rounded-lg shadow-md p-4">
              <div className="flex items-center gap-4">
                <span className="text-sm font-medium text-gray-700">
                  Filter by:
                </span>
                <select
                  value={selectedCategory}
                  onChange={(e) => setSelectedCategory(e.target.value)}
                  className="px-4 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                >
                  <option value="all">All Primitives</option>
                  {Object.keys(cryptoStats.byPrimitive).map((p) => (
                    <option key={p} value={p}>
                      {p}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Crypto Components */}
            <div className="grid grid-cols-1 gap-4">
              {filteredCrypto.map((comp) => {
                const props = (comp.properties ?? []).reduce<
                  Record<string, string>
                >((acc, p) => {
                  acc[p.name] = p.value ?? "";
                  return acc;
                }, {});

                return (
                  <div
                    key={comp["bom-ref"]}
                    className="bg-white rounded-lg shadow-md p-6"
                  >
                    <div className="flex items-start justify-between mb-4">
                      <div className="flex items-center gap-3">
                        {getPrimitiveIcon(props.primitive)}
                        <div>
                          <h3 className="text-lg font-bold text-gray-800">
                            {comp.name}
                          </h3>
                          <div className="flex items-center gap-2 mt-1">
                            <span className="text-xs px-2 py-1 rounded bg-gray-100 text-gray-700">
                              {props.primitive}
                            </span>
                            <span className="text-xs px-2 py-1 rounded bg-blue-100 text-blue-700">
                              {props.provider}
                            </span>
                            <span
                              className={`text-xs px-2 py-1 rounded ${getVulnerabilityColor(
                                props["pqm.vulnerability"]
                              )}`}
                            >
                              {props["pqm.vulnerability"]}
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>

                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                      {Object.entries(props).map(([key, value]) => {
                        if (
                          key === "primitive" ||
                          key === "provider" ||
                          key === "pqm.vulnerability"
                        )
                          return null;
                        return (
                          <div key={key}>
                            <div className="text-xs text-gray-500 mb-1">
                              {key}
                            </div>
                            <div className="text-sm font-medium text-gray-800">
                              {value || "N/A"}
                            </div>
                          </div>
                        );
                      })}
                    </div>

                    {comp.evidence?.occurrences && (
                      <details className="mt-4">
                        <summary className="text-sm font-medium text-indigo-600 cursor-pointer hover:text-indigo-800">
                          View Evidence (
                          {comp.evidence.occurrences.length} occurrences)
                        </summary>
                        <div className="mt-3 space-y-2 pl-4">
                          {comp.evidence.occurrences.map((occ, i) => (
                            <div
                              key={`${occ.file}-${occ.line}-${i}`}
                              className="text-xs bg-gray-50 p-3 rounded"
                            >
                              <div className="font-medium text-gray-800">
                                {occ.file}:{occ.line}
                              </div>
                              <div className="text-gray-600 mt-1 font-mono">
                                {occ.snippet}
                              </div>
                            </div>
                          ))}
                        </div>
                      </details>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Files Tab */}
        {activeTab === "files" && (
          <div className="bg-white rounded-lg shadow-md p-6">
            <h3 className="text-lg font-bold text-gray-800 mb-4">
              Source Files
            </h3>
            <div className="space-y-2">
              {fileComponents.map((file) => {
                const impactCount =
                  file.properties?.find(
                    (p) => p.name === "impact.outbound.count"
                  )?.value || "0";
                return (
                  <div
                    key={file["bom-ref"]}
                    className="border border-gray-200 rounded-lg p-4 hover:bg-gray-50 transition-colors"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <FileCode className="w-5 h-5 text-gray-600" />
                        <span className="font-medium text-gray-800">
                          {file.name}
                        </span>
                      </div>
                      <span className="text-sm text-gray-600">
                        {impactCount} outbound calls
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default CBOMVisualizer;
