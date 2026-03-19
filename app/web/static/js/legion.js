const workspaceState = {
    hosts: [],
    hostFilter: "hide_down",
    hostServiceFilter: "",
    services: [],
    tools: [],
    toolsHydrated: false,
    toolsLoading: false,
    selectedHostId: null,
    hostDetail: null,
};

const graphWorkspaceState = {
    viewId: "attack_surface",
    groupBy: "finding",
    renderMode: "auto",
    zoomPercent: 70,
    detailMode: "floating",
    filtersExpanded: false,
    data: {
        nodes: [],
        edges: [],
        meta: {},
    },
    filtered: {
        nodes: [],
        edges: [],
        groups: [],
        positions: {},
        width: 1600,
        height: 900,
    },
    loading: false,
    needsRefresh: false,
    refreshTimer: null,
    focusDepth: 1,
    focusSeedNodeIds: [],
    focusSeedLabel: "",
    expandedSummaryIds: {},
    metadataLoaded: false,
    layouts: [],
    activeLayoutId: "",
    positions: {},
    pinnedNodeIds: {},
    selectedKind: "",
    selectedRef: "",
    selectedPayload: null,
    relatedContent: [],
    toolMenuCache: {},
    contentRequestId: 0,
    annotations: [],
    drag: null,
    suppressClickUntil: 0,
};

const GRAPH_WORKSPACE_HEIGHT_STORAGE_KEY = "legion.graphWorkspaceHeightPx";
const GRAPH_WORKSPACE_DEFAULT_HEIGHT = 680;
const GRAPH_WORKSPACE_MIN_HEIGHT = 520;
const GRAPH_WORKSPACE_MAX_HEIGHT = 1600;
const GRAPH_EDGE_HIGHLIGHT_COLOR = "#ff9f43";
let graphWorkspaceResizeState = null;

const GRAPH_VIEW_PRESETS = {
    attack_surface: {
        label: "attack surface",
        defaultGroup: "finding",
        nodeTypes: ["scope", "subnet", "host", "fqdn", "port", "service", "url", "technology", "finding", "cpe", "cve", "screenshot"],
    },
    host_service_topology: {
        label: "host/service topology",
        defaultGroup: "host",
        nodeTypes: ["host", "fqdn", "port", "service", "technology", "url", "action", "evidence_record", "artifact", "screenshot"],
    },
    web_application_map: {
        label: "web application map",
        defaultGroup: "service",
        nodeTypes: ["host", "fqdn", "service", "url", "technology", "finding", "cpe", "cve", "screenshot", "artifact", "action"],
    },
    credential_identity_session: {
        label: "credential / identity / session",
        defaultGroup: "host",
        nodeTypes: ["host", "credential", "identity", "session", "action", "artifact", "evidence_record"],
        edgeTypes: ["contains", "authenticated_as", "captured", "produced", "pivoted_to", "validated_by"],
    },
    exploitation_chain: {
        label: "exploitation chain",
        defaultGroup: "finding",
        nodeTypes: ["host", "finding", "cve", "exploit_reference", "credential", "identity", "session", "action", "artifact", "screenshot", "evidence_record"],
        edgeTypes: ["contains", "affected_by", "supports_exploit", "validated_by", "authenticated_as", "pivoted_to", "produced", "derived_from"],
    },
};

const GRAPH_SOURCE_KIND_LABELS = {
    observed: "observed",
    inferred: "inferred",
    ai_suggested: "ai suggested",
    user_entered: "user entered",
};

const GRAPH_SOURCE_KIND_STYLES = {
    observed: {
        stroke: "#7ee3cb",
        edgeStroke: "#5f8f89",
        fill: "rgba(126, 227, 203, 0.16)",
        fillOpaque: "#17322f",
        dash: "",
    },
    inferred: {
        stroke: "#f1cd6b",
        edgeStroke: "#9d8555",
        fill: "rgba(241, 205, 107, 0.16)",
        fillOpaque: "#3a3118",
        dash: "7 5",
    },
    ai_suggested: {
        stroke: "#a38dff",
        edgeStroke: "#756ca8",
        fill: "rgba(163, 141, 255, 0.16)",
        fillOpaque: "#282042",
        dash: "2 5",
    },
    user_entered: {
        stroke: "#9ad2ff",
        edgeStroke: "#6e93ac",
        fill: "rgba(154, 210, 255, 0.16)",
        fillOpaque: "#1d3141",
        dash: "",
    },
};

const GRAPH_NODE_COLORS = {
    scope: "#9ad2ff",
    subnet: "#7b83ff",
    host: "#86d993",
    fqdn: "#98d6ff",
    port: "#f0c96f",
    service: "#ff9c6f",
    url: "#6ce0c7",
    technology: "#8ac7ff",
    cpe: "#b4bbdd",
    cve: "#ff7c99",
    finding: "#ff6f91",
    credential: "#ffd37b",
    identity: "#ffe7a8",
    session: "#69d4ff",
    exploit_reference: "#ffb16f",
    screenshot: "#8fd0ff",
    artifact: "#9bc9b7",
    action: "#d1a8ff",
    evidence_record: "#b7bdd8",
};

const GRAPH_NODE_SIZE = {
    width: 148,
    height: 58,
};

const GRAPH_TYPE_ORDER = [
    "finding",
    "cve",
    "exploit_reference",
    "credential",
    "identity",
    "session",
    "scope",
    "subnet",
    "host",
    "fqdn",
    "service",
    "url",
    "port",
    "technology",
    "cpe",
    "screenshot",
    "action",
    "artifact",
    "evidence_record",
];

const GRAPH_SEVERITY_ORDER = {
    critical: 0,
    high: 1,
    medium: 2,
    moderate: 2,
    low: 3,
    info: 4,
    informational: 4,
};

const GRAPH_LARGE_NODE_THRESHOLD = 1000;
const GRAPH_LARGE_EDGE_THRESHOLD = 3000;
const GRAPH_MATRIX_NODE_THRESHOLD = 1600;
const GRAPH_MATRIX_EDGE_THRESHOLD = 4500;
const GRAPH_MATRIX_GROUP_LIMIT = 24;

const processOutputState = {
    processId: null,
    offset: 0,
    complete: true,
    status: "",
    text: "",
    modalOpen: false,
    refreshTimer: null,
    refreshInFlight: false,
};

const scriptOutputState = {
    scriptDbId: null,
    processId: 0,
    scriptId: "",
    source: "",
    output: "",
    command: "",
    status: "",
    downloadName: "",
    modalOpen: false,
};

const screenshotModalState = {
    modalOpen: false,
    url: "",
    filename: "",
    port: "",
};

const providerLogsState = {
    modalOpen: false,
    text: "",
    count: 0,
};

const hostRemoveState = {
    modalOpen: false,
    hostId: null,
    hostIp: "",
    hostName: "",
};

const nmapWizardState = {
    step: 1,
    lastMode: "",
    postSubmitLock: true,
};

const PROCESS_OUTPUT_REFRESH_MS = 2000;

const startupWizardState = {
    open: false,
    step: 1,
    busy: false,
    summary: {
        project: "",
        imports: "",
        scheduler: "",
    },
};

const uiModalState = {
    schedulerOpen: false,
    reportProviderOpen: false,
    settingsOpen: false,
    nmapScanOpen: false,
    manualScanOpen: false,
    hostSelectionOpen: false,
    scriptCveOpen: false,
    providerLogsOpen: false,
    jobsOpen: false,
    submittedScansOpen: false,
    schedulerDecisionsOpen: false,
    hostRemoveOpen: false,
    graphNoteOpen: false,
};

const ribbonMenuState = {
    openMenuId: null,
};

const STARTUP_WIZARD_SESSION_KEY = "legion_startup_wizard_done";

function updateBodyModalState() {
    const anyModalOpen = Boolean(
        processOutputState.modalOpen
        || scriptOutputState.modalOpen
        || screenshotModalState.modalOpen
        || startupWizardState.open
        || uiModalState.schedulerOpen
        || uiModalState.reportProviderOpen
        || uiModalState.settingsOpen
        || uiModalState.nmapScanOpen
        || uiModalState.manualScanOpen
        || uiModalState.hostSelectionOpen
        || uiModalState.scriptCveOpen
        || uiModalState.providerLogsOpen
        || uiModalState.jobsOpen
        || uiModalState.submittedScansOpen
        || uiModalState.schedulerDecisionsOpen
        || uiModalState.hostRemoveOpen
        || uiModalState.graphNoteOpen
    );
    document.body.classList.toggle("modal-open", anyModalOpen);
}

function setText(id, value) {
    const node = document.getElementById(id);
    if (!node) {
        return;
    }
    node.textContent = value ?? "";
}

function setValue(id, value) {
    const node = document.getElementById(id);
    if (!node) {
        return;
    }
    node.value = value ?? "";
}

function setChecked(id, checked) {
    const node = document.getElementById(id);
    if (!node) {
        return;
    }
    node.checked = Boolean(checked);
}

function getChecked(id) {
    const node = document.getElementById(id);
    return node ? Boolean(node.checked) : false;
}

function getValue(id) {
    const node = document.getElementById(id);
    return node ? node.value : "";
}

function makeCell(value) {
    const td = document.createElement("td");
    td.textContent = value ?? "";
    return td;
}

function buildHostActionButton(action, hostId) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "icon-btn";
    button.dataset.hostAction = String(action || "");
    button.dataset.hostId = String(hostId || "");

    if (action === "rescan") {
        button.title = "Rescan";
        button.setAttribute("aria-label", "Rescan");
        button.innerHTML = '<i class="fa-solid fa-rotate-right" aria-hidden="true"></i>';
        return button;
    }
    if (action === "refresh-screenshots") {
        button.title = "Refresh screenshots";
        button.setAttribute("aria-label", "Refresh screenshots");
        button.innerHTML = '<i class="fa-solid fa-camera-retro" aria-hidden="true"></i>';
        return button;
    }
    if (action === "dig-deeper") {
        button.title = "Dig Deeper";
        button.setAttribute("aria-label", "Dig Deeper");
        button.innerHTML = '<i class="fa-solid fa-brain" aria-hidden="true"></i>';
        return button;
    }
    if (action === "remove") {
        button.classList.add("icon-btn-danger");
        button.title = "Remove host";
        button.setAttribute("aria-label", "Remove host");
        button.innerHTML = '<i class="fa-solid fa-trash" aria-hidden="true"></i>';
        return button;
    }
    return button;
}

function buildSubnetActionButton(action, subnet) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "icon-btn";
    button.dataset.subnetAction = String(action || "");
    button.dataset.subnet = String(subnet || "");

    if (action === "rescan") {
        button.title = "Rescan subnet";
        button.setAttribute("aria-label", "Rescan subnet");
        button.innerHTML = '<i class="fa-solid fa-rotate-right" aria-hidden="true"></i>';
        return button;
    }
    return button;
}

function buildScreenshotActionButton(action, payload) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "icon-btn";
    button.dataset.screenshotAction = String(action || "");
    button.dataset.hostId = String(payload?.hostId || "");
    button.dataset.port = String(payload?.port || "");
    button.dataset.protocol = String(payload?.protocol || "tcp");
    button.dataset.artifactRef = String(payload?.artifactRef || "");
    button.dataset.filename = String(payload?.filename || "");

    if (action === "refresh") {
        button.title = "Re-screenshot";
        button.setAttribute("aria-label", "Re-screenshot");
        button.innerHTML = '<i class="fa-solid fa-camera-retro" aria-hidden="true"></i>';
        return button;
    }
    if (action === "delete") {
        button.classList.add("icon-btn-danger");
        button.title = "Delete screenshot";
        button.setAttribute("aria-label", "Delete screenshot");
        button.innerHTML = '<i class="fa-solid fa-trash" aria-hidden="true"></i>';
        return button;
    }
    return button;
}

function graphHostRowById(hostId) {
    const targetId = parseInt(hostId, 10);
    if (!Number.isFinite(targetId) || targetId <= 0) {
        return null;
    }
    return (workspaceState.hosts || []).find((host) => parseInt(host?.id, 10) === targetId) || null;
}

function graphConnectedServiceContextForPortNode(entity) {
    const nodeId = String(entity?.node_id || "");
    if (!nodeId) {
        return {serviceName: "", serviceLabel: ""};
    }
    const edges = Array.isArray(graphWorkspaceState.data?.edges) ? graphWorkspaceState.data.edges : [];
    const nodes = Array.isArray(graphWorkspaceState.data?.nodes) ? graphWorkspaceState.data.nodes : [];
    const serviceEdge = edges.find((edge) => {
        return (
            String(edge?.from_node_id || "") === nodeId
            && String(edge?.type || "").trim().toLowerCase() === "exposes"
        );
    });
    if (!serviceEdge) {
        return {serviceName: "", serviceLabel: ""};
    }
    const serviceNode = nodes.find((node) => String(node?.node_id || "") === String(serviceEdge.to_node_id || ""));
    if (!serviceNode || String(serviceNode?.type || "").trim().toLowerCase() !== "service") {
        return {serviceName: "", serviceLabel: ""};
    }
    const serviceName = String(graphPropertyValue(serviceNode, "service") || "").trim().replace(/\?+$/, "").toLowerCase();
    const serviceLabel = String(serviceNode?.label || serviceName || "").trim();
    return {serviceName, serviceLabel};
}

function graphToolLaunchContextForEntity(entity) {
    if (!entity) {
        return null;
    }
    const entityType = String(entity?.type || "").trim().toLowerCase();
    if (!["port", "service"].includes(entityType)) {
        return null;
    }
    const hostId = graphEntityHostId(entity);
    const hostRow = graphHostRowById(hostId);
    const hostIp = String(hostRow?.ip || graphPropertyValue(entity, "ip") || "").trim();
    const port = String(graphPropertyValue(entity, "port") || "").trim();
    const protocol = String(graphPropertyValue(entity, "protocol") || "tcp").trim().toLowerCase() || "tcp";
    if (!hostId || !hostIp || !port) {
        return null;
    }
    let serviceName = "";
    let serviceLabel = "";
    if (entityType === "service") {
        serviceName = String(graphPropertyValue(entity, "service") || entity.label || "").trim().replace(/\?+$/, "").toLowerCase();
        serviceLabel = String(entity.label || serviceName || "").trim();
    } else {
        const derived = graphConnectedServiceContextForPortNode(entity);
        serviceName = derived.serviceName;
        serviceLabel = derived.serviceLabel;
    }
    return {
        entityType,
        hostId,
        hostIp,
        hostname: String(hostRow?.hostname || "").trim(),
        port,
        protocol,
        serviceName,
        serviceLabel: serviceLabel || serviceName || "",
    };
}

function closeGraphActionMenus() {
    document.querySelectorAll(".graph-action-menu.is-open").forEach((menu) => {
        menu.classList.remove("is-open");
        const toggle = menu.querySelector(".panel-menu-button");
        if (toggle) {
            toggle.setAttribute("aria-expanded", "false");
        }
    });
}

async function graphGetApplicableTools(serviceName) {
    const key = String(serviceName || "").trim().toLowerCase();
    if (!key) {
        return [];
    }
    if (Array.isArray(graphWorkspaceState.toolMenuCache[key])) {
        return graphWorkspaceState.toolMenuCache[key];
    }
    const body = await fetchJson(`/api/workspace/tools?service=${encodeURIComponent(key)}&limit=500`);
    const tools = Array.isArray(body?.tools) ? body.tools.filter((item) => Boolean(item?.runnable)) : [];
    graphWorkspaceState.toolMenuCache[key] = tools;
    return tools;
}

async function runGraphNodeToolAction(context, tool) {
    if (!context || !tool?.tool_id) {
        return;
    }
    try {
        const body = await postJson("/api/workspace/tools/run", {
            host_ip: context.hostIp,
            port: context.port,
            protocol: context.protocol,
            tool_id: String(tool.tool_id || ""),
        });
        setWorkspaceStatus(`${tool.label || tool.tool_id} queued for ${context.hostIp}:${context.port}/${context.protocol} (job ${body?.job?.id || "?"})`);
        await pollSnapshot();
    } catch (err) {
        setWorkspaceStatus(`Tool launch failed: ${err.message}`, true);
    }
}

function buildGraphToolMenu(context) {
    const menu = document.createElement("div");
    menu.className = "panel-menu graph-action-menu";

    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "panel-menu-button";
    toggle.title = "Launch Action";
    toggle.setAttribute("aria-label", "Launch Action");
    toggle.setAttribute("aria-haspopup", "menu");
    toggle.setAttribute("aria-expanded", "false");
    toggle.innerHTML = '<i class="fa-solid fa-bars" aria-hidden="true"></i>';
    menu.appendChild(toggle);

    const submenu = document.createElement("div");
    submenu.className = "ribbon-submenu panel-submenu";
    submenu.setAttribute("role", "menu");
    submenu.setAttribute("aria-label", "Applicable actions");
    menu.appendChild(submenu);

    const serviceKey = String(context?.serviceName || "").trim();
    if (!serviceKey) {
        toggle.disabled = true;
        toggle.title = "No applicable service-specific actions";
        toggle.setAttribute("aria-label", "No applicable service-specific actions");
        const empty = document.createElement("div");
        empty.className = "graph-action-menu-status";
        empty.textContent = "No applicable service-specific actions.";
        submenu.appendChild(empty);
        return menu;
    }

    let loaded = false;
    toggle.addEventListener("click", async (event) => {
        event.preventDefault();
        event.stopPropagation();
        const willOpen = !menu.classList.contains("is-open");
        closeGraphActionMenus();
        if (!willOpen) {
            return;
        }
        menu.classList.add("is-open");
        toggle.setAttribute("aria-expanded", "true");
        if (loaded) {
            return;
        }
        submenu.innerHTML = "";
        const loading = document.createElement("div");
        loading.className = "graph-action-menu-status";
        loading.textContent = "Loading actions...";
        submenu.appendChild(loading);
        try {
            const tools = await graphGetApplicableTools(serviceKey);
            submenu.innerHTML = "";
            if (!tools.length) {
                const empty = document.createElement("div");
                empty.className = "graph-action-menu-status";
                empty.textContent = "No applicable actions.";
                submenu.appendChild(empty);
            } else {
                tools.forEach((tool) => {
                    const item = document.createElement("button");
                    item.type = "button";
                    item.className = "ribbon-submenu-item";
                    item.textContent = String(tool.label || tool.tool_id || "tool");
                    item.title = String(tool.command_template || tool.tool_id || "");
                    item.addEventListener("click", async (clickEvent) => {
                        clickEvent.preventDefault();
                        clickEvent.stopPropagation();
                        closeGraphActionMenus();
                        await runGraphNodeToolAction(context, tool);
                    });
                    submenu.appendChild(item);
                });
            }
            loaded = true;
        } catch (err) {
            submenu.innerHTML = "";
            const failed = document.createElement("div");
            failed.className = "graph-action-menu-status";
            failed.textContent = `Failed to load actions: ${err.message}`;
            submenu.appendChild(failed);
        }
    });

    submenu.addEventListener("click", (event) => {
        event.stopPropagation();
    });
    return menu;
}

async function handleHostActionButtonAction(actionBtn) {
    const hostId = parseInt(actionBtn?.dataset?.hostId, 10);
    const action = String(actionBtn?.dataset?.hostAction || "");
    if (!hostId) {
        return true;
    }
    if (action === "rescan") {
        await rescanHostAction(hostId);
        return true;
    }
    if (action === "refresh-screenshots") {
        await refreshHostScreenshotsAction(hostId);
        return true;
    }
    if (action === "dig-deeper") {
        await digDeeperHostAction(hostId);
        return true;
    }
    if (action === "remove") {
        requestHostRemoveAction(hostId);
        return true;
    }
    return false;
}

async function handleSubnetActionButtonAction(actionBtn) {
    const subnet = String(actionBtn?.dataset?.subnet || "").trim();
    const action = String(actionBtn?.dataset?.subnetAction || "");
    if (!subnet) {
        return true;
    }
    if (action === "rescan") {
        await rescanSubnetAction(subnet);
        return true;
    }
    return false;
}

async function handleScreenshotActionButtonAction(actionBtn) {
    const hostId = parseInt(actionBtn?.dataset?.hostId, 10);
    const action = String(actionBtn?.dataset?.screenshotAction || "");
    const port = String(actionBtn?.dataset?.port || "").trim();
    const protocol = String(actionBtn?.dataset?.protocol || "tcp").trim().toLowerCase() || "tcp";
    const artifactRef = String(actionBtn?.dataset?.artifactRef || "").trim();
    const filename = String(actionBtn?.dataset?.filename || "").trim();
    if (!hostId) {
        return true;
    }
    if (action === "refresh") {
        await refreshGraphScreenshotAction({hostId, port, protocol});
        return true;
    }
    if (action === "delete") {
        await deleteGraphScreenshotAction({hostId, port, protocol, artifactRef, filename});
        return true;
    }
    return false;
}

async function deleteGraphPortAction(context) {
    if (!context?.hostId || !context?.port) {
        return;
    }
    const label = `${context.hostIp}:${context.port}/${context.protocol}`;
    if (!window.confirm(`Delete port ${label}?`)) {
        return;
    }
    try {
        await postJson("/api/workspace/ports/delete", {
            host_id: context.hostId,
            port: context.port,
            protocol: context.protocol,
        });
        setWorkspaceStatus(`Deleted port ${label}`);
        await pollSnapshot();
    } catch (err) {
        setWorkspaceStatus(`Delete port failed: ${err.message}`, true);
    }
}

async function deleteGraphServiceAction(context) {
    if (!context?.hostId || !context?.port) {
        return;
    }
    const label = `${context.serviceLabel || context.serviceName || "service"} on ${context.hostIp}:${context.port}/${context.protocol}`;
    if (!window.confirm(`Delete ${label}?`)) {
        return;
    }
    try {
        await postJson("/api/workspace/services/delete", {
            host_id: context.hostId,
            port: context.port,
            protocol: context.protocol,
            service: context.serviceName,
        });
        setWorkspaceStatus(`Deleted ${label}`);
        await pollSnapshot();
    } catch (err) {
        setWorkspaceStatus(`Delete service failed: ${err.message}`, true);
    }
}

const ANSI_FG_CLASS_BY_CODE = {
    30: "ansi-fg-black",
    31: "ansi-fg-red",
    32: "ansi-fg-green",
    33: "ansi-fg-yellow",
    34: "ansi-fg-blue",
    35: "ansi-fg-magenta",
    36: "ansi-fg-cyan",
    37: "ansi-fg-white",
    90: "ansi-fg-bright-black",
    91: "ansi-fg-bright-red",
    92: "ansi-fg-bright-green",
    93: "ansi-fg-bright-yellow",
    94: "ansi-fg-bright-blue",
    95: "ansi-fg-bright-magenta",
    96: "ansi-fg-bright-cyan",
    97: "ansi-fg-bright-white",
};

const ANSI_BG_CLASS_BY_CODE = {
    40: "ansi-bg-black",
    41: "ansi-bg-red",
    42: "ansi-bg-green",
    43: "ansi-bg-yellow",
    44: "ansi-bg-blue",
    45: "ansi-bg-magenta",
    46: "ansi-bg-cyan",
    47: "ansi-bg-white",
    100: "ansi-bg-bright-black",
    101: "ansi-bg-bright-red",
    102: "ansi-bg-bright-green",
    103: "ansi-bg-bright-yellow",
    104: "ansi-bg-bright-blue",
    105: "ansi-bg-bright-magenta",
    106: "ansi-bg-bright-cyan",
    107: "ansi-bg-bright-white",
};

function escapeHtml(text) {
    return String(text || "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

function resetAnsiState(state) {
    state.bold = false;
    state.fg = "";
    state.bg = "";
}

function applyAnsiSgrCodes(codes, state) {
    const values = Array.isArray(codes) && codes.length ? codes : [0];
    for (let index = 0; index < values.length; index += 1) {
        const code = Number(values[index]);
        if (!Number.isFinite(code)) {
            continue;
        }
        if (code === 0) {
            resetAnsiState(state);
            continue;
        }
        if (code === 1) {
            state.bold = true;
            continue;
        }
        if (code === 22) {
            state.bold = false;
            continue;
        }
        if (code === 39) {
            state.fg = "";
            continue;
        }
        if (code === 49) {
            state.bg = "";
            continue;
        }
        if (ANSI_FG_CLASS_BY_CODE[code]) {
            state.fg = ANSI_FG_CLASS_BY_CODE[code];
            continue;
        }
        if (ANSI_BG_CLASS_BY_CODE[code]) {
            state.bg = ANSI_BG_CLASS_BY_CODE[code];
            continue;
        }
        if (code === 38 || code === 48 || code === 58) {
            const mode = Number(values[index + 1]);
            if (mode === 5) {
                index += 2;
            } else if (mode === 2) {
                index += 4;
            }
        }
    }
}

function ansiClassesForState(state) {
    const classes = ["ansi-segment"];
    if (state.bold) {
        classes.push("ansi-bold");
    }
    if (state.fg) {
        classes.push(state.fg);
    }
    if (state.bg) {
        classes.push(state.bg);
    }
    return classes.join(" ");
}

function ansiTextToHtml(text) {
    const raw = String(text || "").replace(/\r\n/g, "\n");
    const sgrPattern = /\u001b\[([0-9;]*)m/g;
    const state = {bold: false, fg: "", bg: ""};
    let cursor = 0;
    let html = "";

    raw.replace(sgrPattern, (match, params, offset) => {
        if (offset > cursor) {
            const chunk = raw.slice(cursor, offset);
            html += `<span class="${ansiClassesForState(state)}">${escapeHtml(chunk)}</span>`;
        }
        const codes = String(params || "")
            .split(";")
            .map((value) => value.trim())
            .filter((value) => value.length > 0)
            .map((value) => parseInt(value, 10))
            .filter((value) => Number.isFinite(value));
        applyAnsiSgrCodes(codes, state);
        cursor = offset + match.length;
        return match;
    });

    if (cursor < raw.length) {
        html += `<span class="${ansiClassesForState(state)}">${escapeHtml(raw.slice(cursor))}</span>`;
    }

    return html || "";
}

function renderAnsiOutput(nodeId, text) {
    const node = document.getElementById(nodeId);
    if (!node) {
        return;
    }
    const nearBottom = Math.abs((node.scrollTop + node.clientHeight) - node.scrollHeight) < 24;
    node.innerHTML = ansiTextToHtml(text || "");
    if (nearBottom) {
        node.scrollTop = node.scrollHeight;
    }
}

function formatTargetLabel(host, port = "", protocol = "") {
    const hostText = String(host || "").trim();
    const portText = String(port || "").trim();
    const protocolText = String(protocol || "").trim();
    if (!portText && !protocolText) {
        return hostText;
    }
    if (!protocolText) {
        return `${hostText}:${portText}`;
    }
    if (!portText) {
        return hostText ? `${hostText}/${protocolText}` : `/${protocolText}`;
    }
    return `${hostText}:${portText}/${protocolText}`;
}

function summarizeBannerText(raw, maxLen = 160) {
    const normalized = String(raw || "").replace(/\s+/g, " ").trim();
    if (!normalized) {
        return "";
    }
    if (normalized.length <= maxLen) {
        return normalized;
    }
    return `${normalized.slice(0, maxLen - 3)}...`;
}

function extractBannerForPort(portRow) {
    const scripts = Array.isArray(portRow?.scripts) ? portRow.scripts : [];
    const priorityPredicates = [
        (scriptId) => scriptId === "banner",
        (scriptId) => scriptId.includes("banner"),
        (scriptId) => scriptId === "http-title",
        (scriptId) => scriptId === "dns-nsid",
    ];
    for (const predicate of priorityPredicates) {
        for (const script of scripts) {
            const scriptId = String(script?.script_id || "").trim().toLowerCase();
            if (!scriptId || !predicate(scriptId)) {
                continue;
            }
            const output = summarizeBannerText(script?.output || "");
            if (output) {
                return output;
            }
        }
    }
    const service = portRow?.service || {};
    const serviceBanner = summarizeBannerText(
        [service.product, service.version, service.extrainfo].filter(Boolean).join(" ")
    );
    return serviceBanner;
}

function formatEtaSeconds(value) {
    const parsed = Number(value);
    if (!Number.isFinite(parsed) || parsed <= 0) {
        return "";
    }
    const total = Math.max(0, Math.floor(parsed));
    const hours = Math.floor(total / 3600);
    const minutes = Math.floor((total % 3600) / 60);
    const seconds = total % 60;
    if (hours > 0) {
        return `${hours}h ${String(minutes).padStart(2, "0")}m ${String(seconds).padStart(2, "0")}s`;
    }
    return `${minutes}m ${String(seconds).padStart(2, "0")}s`;
}

function isProcessRunning(status) {
    const normalized = String(status || "").trim().toLowerCase();
    return normalized === "running" || normalized === "waiting";
}

function getProcessStatusClass(status) {
    const normalized = String(status || "").trim().toLowerCase();
    if (normalized === "running") {
        return "process-status-running";
    }
    if (normalized === "crashed") {
        return "process-status-crashed";
    }
    if (normalized === "problem") {
        return "process-status-problem";
    }
    return "";
}

function setActionStatus(text, isError = false) {
    const node = document.getElementById("action-status");
    if (!node) {
        return;
    }
    node.textContent = text;
    node.style.color = isError ? "#ff9b9b" : "";
}

function setWorkspaceStatus(text, isError = false) {
    const node = document.getElementById("workspace-status");
    if (!node) {
        return;
    }
    node.textContent = text;
    node.style.color = isError ? "#ff9b9b" : "";
}

function setStartupWizardStatus(text, isError = false) {
    const node = document.getElementById("startup-wizard-status");
    if (!node) {
        return;
    }
    node.textContent = text || "";
    node.style.color = isError ? "#ff9b9b" : "";
}

function renderProject(project) {
    setText("project-name", project.name || "");
    setText("project-kind", project.is_temporary ? "temporary" : "saved");
    setText("project-output-folder", project.output_folder || "");
    setText("project-running-folder", project.running_folder || "");

    const currentSavePath = getValue("project-save-path").trim();
    if (!currentSavePath && project.name) {
        setValue("project-save-path", project.name);
    }
}

function clearHostDetailView({resetForms = true} = {}) {
    workspaceState.hostDetail = null;
    setText("host-detail-name", "");
    setValue("workspace-note", "");
    setValue("workspace-tool-host-ip", "");

    if (resetForms) {
        setValue("workspace-tool-port", "");
        setValue("workspace-tool-protocol", "tcp");
        setValue("workspace-script-id", "");
        setValue("workspace-script-port", "");
        setValue("workspace-script-protocol", "tcp");
        setValue("workspace-script-output", "");
        setValue("workspace-cve-name", "");
        setValue("workspace-cve-severity", "");
    }

    [
        "host-detail-ports",
        "host-detail-scripts",
        "host-detail-cves",
        "host-detail-ai-technologies",
        "host-detail-ai-findings",
        "host-detail-ai-manual-tests",
        "host-detail-screenshots",
    ].forEach((id) => {
        const node = document.getElementById(id);
        if (node) {
            node.innerHTML = "";
        }
    });

    setText("host-ai-analysis-status", "");
    setText("host-ai-tech-count", 0);
    setText("host-ai-finding-count", 0);
    setText("host-ai-manual-count", 0);
    setText("host-screenshot-count", 0);
}

function resetWorkspaceDisplayForProjectSwitch({clearProjectPaths = false} = {}) {
    workspaceState.hosts = [];
    workspaceState.services = [];
    workspaceState.tools = [];
    workspaceState.toolsHydrated = false;
    workspaceState.toolsLoading = false;
    workspaceState.selectedHostId = null;
    workspaceState.hostDetail = null;
    graphWorkspaceState.data = {nodes: [], edges: [], meta: {}};
    graphWorkspaceState.filtered = {nodes: [], edges: [], groups: [], positions: {}, width: 1600, height: 900};
    graphWorkspaceState.activeLayoutId = "";
    graphWorkspaceState.positions = {};
    graphWorkspaceState.pinnedNodeIds = {};
    graphWorkspaceState.selectedKind = "";
    graphWorkspaceState.selectedRef = "";
    graphWorkspaceState.selectedPayload = null;
    graphWorkspaceState.metadataLoaded = false;
    graphWorkspaceState.layouts = [];
    graphWorkspaceState.annotations = [];

    renderSummary({
        hosts: 0,
        open_ports: 0,
        services: 0,
        cves: 0,
        running_processes: 0,
        finished_processes: 0,
    });
    renderHosts([]);
    renderServices([]);
    renderTools([]);
    renderProcesses([]);
    renderDecisions([]);
    renderApprovals([]);
    renderJobs([]);
    clearHostDetailView({resetForms: true});
    closeProcessOutputModal(true);
    closeScriptOutputModal(true);
    closeScreenshotModal(true);
    closeHostRemoveModalAction(true);
    graphUpdateHostFilterOptions();
    graphRenderLayoutOptions();
    graphRenderWorkspace();

    if (clearProjectPaths) {
        setValue("project-open-path", "");
        setValue("project-save-path", "");
    }
}

function renderHostSelector(hosts) {
    const select = document.getElementById("workspace-host-select");
    if (!select) {
        return;
    }
    const previous = workspaceState.selectedHostId;
    select.innerHTML = "";

    hosts.forEach((host) => {
        const option = document.createElement("option");
        option.value = String(host.id);
        option.textContent = `${host.ip || ""} ${host.hostname ? `(${host.hostname})` : ""}`.trim();
        select.appendChild(option);
    });

    if (!hosts.length) {
        workspaceState.selectedHostId = null;
        clearHostDetailView({resetForms: true});
        return;
    }

    const hasPrevious = hosts.some((host) => String(host.id) === String(previous));
    workspaceState.selectedHostId = hasPrevious ? previous : hosts[0].id;
    select.value = String(workspaceState.selectedHostId);
}

function renderHostSelectionState({syncGraph = false, preserveGraphDetail = true} = {}) {
    const selectedHostId = String(workspaceState.selectedHostId || "");
    const select = document.getElementById("workspace-host-select");
    if (select) {
        const hasSelectedOption = Array.from(select.options || []).some((option) => {
            return String(option.value || "") === selectedHostId;
        });
        if (hasSelectedOption) {
            select.value = selectedHostId;
        } else {
            select.value = "";
        }
    }

    const body = document.getElementById("hosts-body");
    if (body) {
        Array.from(body.querySelectorAll("tr[data-host-id]")).forEach((row) => {
            const isSelected = selectedHostId && String(row.dataset.hostId || "") === selectedHostId;
            row.classList.toggle("is-selected", Boolean(isSelected));
            row.setAttribute("aria-selected", isSelected ? "true" : "false");
        });
    }

    if (syncGraph) {
        graphRenderWorkspace({preserveDetail: preserveGraphDetail});
    }
}

async function selectHost(hostId, {loadDetail = true, syncGraph = true, preserveGraphDetail = true} = {}) {
    const normalizedHostId = parseInt(hostId, 10);
    if (!Number.isFinite(normalizedHostId) || normalizedHostId <= 0) {
        workspaceState.selectedHostId = null;
        workspaceState.hostDetail = null;
        clearHostDetailView({resetForms: true});
        renderHostSelectionState({syncGraph, preserveGraphDetail});
        return;
    }

    const hostChanged = String(workspaceState.selectedHostId || "") !== String(normalizedHostId);
    workspaceState.selectedHostId = normalizedHostId;
    renderHostSelectionState({syncGraph, preserveGraphDetail});

    if (!loadDetail) {
        return;
    }
    if (!hostChanged && workspaceState.hostDetail) {
        return;
    }

    workspaceState.hostDetail = null;
    try {
        await loadHostDetail(normalizedHostId);
    } catch (err) {
        setWorkspaceStatus(`Load host detail failed: ${err.message}`, true);
    }
}

function renderHosts(hosts) {
    workspaceState.hosts = Array.isArray(hosts) ? hosts : [];
    const body = document.getElementById("hosts-body");
    if (!body) {
        return;
    }
    body.innerHTML = "";
    workspaceState.hosts.forEach((host) => {
        const tr = document.createElement("tr");
        tr.dataset.hostId = String(host.id || "");
        const ipCell = document.createElement("td");
        const ipWrap = document.createElement("span");
        const icon = document.createElement("i");
        const osIcon = getHostOsIcon(host.os || "");
        icon.className = `${osIcon.className} host-os-icon`;
        icon.setAttribute("aria-hidden", "true");
        icon.title = osIcon.label;
        ipWrap.className = "host-ip-with-icon";
        ipWrap.appendChild(icon);
        ipWrap.appendChild(document.createTextNode(host.ip || ""));
        ipCell.appendChild(ipWrap);
        tr.appendChild(ipCell);
        tr.appendChild(makeCell(host.hostname));
        tr.appendChild(makeCell(host.status));
        tr.appendChild(makeCell(host.os));
        tr.appendChild(makeCell(host.open_ports));
        const actionsCell = document.createElement("td");
        actionsCell.className = "host-actions";
        ["rescan", "refresh-screenshots", "dig-deeper", "remove"].forEach((action) => {
            actionsCell.appendChild(buildHostActionButton(action, host.id || ""));
        });

        tr.appendChild(actionsCell);
        body.appendChild(tr);
    });
    setText("host-count", workspaceState.hosts.length);
    renderHostSelector(workspaceState.hosts);
    renderHostSelectionState();
    graphUpdateHostFilterOptions();
}

function hostMatchesServiceFilter(host, serviceFilter) {
    const normalized = String(serviceFilter || "").trim().toLowerCase();
    if (!normalized) {
        return true;
    }
    return Array.isArray(host?.services)
        && host.services.some((item) => String(item || "").trim().toLowerCase() === normalized);
}

function renderServices(services) {
    workspaceState.services = Array.isArray(services) ? services : [];
    const body = document.getElementById("services-body");
    if (!body) {
        return;
    }
    body.innerHTML = "";
    workspaceState.services.forEach((service) => {
        const tr = document.createElement("tr");
        const filterCell = document.createElement("td");
        const filterButton = document.createElement("button");
        filterButton.type = "button";
        filterButton.className = "icon-btn";
        filterButton.title = `Show hosts for ${service.service || "service"}`;
        filterButton.setAttribute("aria-label", `Show hosts for ${service.service || "service"}`);
        filterButton.innerHTML = '<i class="fa-solid fa-filter" aria-hidden="true"></i>';
        if (String(workspaceState.hostServiceFilter || "").trim().toLowerCase() === String(service.service || "").trim().toLowerCase()) {
            filterButton.classList.add("is-active");
        }
        filterButton.addEventListener("click", async () => {
            await setHostServiceFilterAction(service.service || "");
        });
        filterCell.className = "service-filter-cell";
        filterCell.appendChild(filterButton);
        tr.appendChild(filterCell);
        tr.appendChild(makeCell(service.service || ""));
        tr.appendChild(makeCell(service.host_count || 0));
        tr.appendChild(makeCell(service.port_count || 0));
        tr.appendChild(makeCell(Array.isArray(service.protocols) ? service.protocols.join(",") : ""));
        body.appendChild(tr);
    });
    setText("service-count", workspaceState.services.length);
}

function setServicesPanelCollapsed(collapsed) {
    const body = document.getElementById("services-panel-body");
    const button = document.getElementById("services-panel-toggle-button");
    if (!body || !button) {
        return;
    }
    const nextCollapsed = Boolean(collapsed);
    body.hidden = nextCollapsed;
    button.classList.toggle("is-collapsed", nextCollapsed);
    button.setAttribute("aria-expanded", nextCollapsed ? "false" : "true");
    button.title = nextCollapsed ? "Show Services" : "Hide Services";
    button.setAttribute("aria-label", nextCollapsed ? "Show Services" : "Hide Services");
}

function toggleServicesPanelAction() {
    const body = document.getElementById("services-panel-body");
    if (!body) {
        return;
    }
    setServicesPanelCollapsed(!body.hidden);
}

function getHostOsIcon(osText) {
    const token = String(osText || "").toLowerCase();
    if (token.includes("windows") || token.includes("microsoft")) {
        return {className: "fa-brands fa-windows", label: "Windows"};
    }
    if (token.includes("linux") || token.includes("ubuntu") || token.includes("debian") || token.includes("centos")) {
        return {className: "fa-brands fa-linux", label: "Linux"};
    }
    if (token.includes("darwin") || token.includes("mac os") || token.includes("osx") || token.includes("macos")) {
        return {className: "fa-brands fa-apple", label: "macOS"};
    }
    if (token.includes("solaris") || token.includes("sunos")) {
        return {className: "fa-solid fa-sun", label: "Solaris"};
    }
    if (token.includes("freebsd") || token.includes("openbsd") || token.includes("netbsd") || token.includes("unix")) {
        return {className: "fa-solid fa-terminal", label: "Unix"};
    }
    if (token.includes("cisco")) {
        return {className: "fa-solid fa-network-wired", label: "Network device"};
    }
    return {className: "fa-solid fa-computer", label: "Unknown OS"};
}

function renderTools(tools) {
    workspaceState.tools = Array.isArray(tools) ? tools : [];
    const body = document.getElementById("tools-body");
    if (body) {
        body.innerHTML = "";
        workspaceState.tools.forEach((tool) => {
            const tr = document.createElement("tr");
            tr.dataset.toolId = String(tool.tool_id || "");
            tr.appendChild(makeCell(tool.label || ""));
            tr.appendChild(makeCell(tool.tool_id || ""));
            tr.appendChild(makeCell(tool.run_count || 0));
            tr.appendChild(makeCell(tool.last_status || ""));
            tr.appendChild(makeCell(Array.isArray(tool.danger_categories) ? tool.danger_categories.join(",") : ""));
            body.appendChild(tr);
        });
    }

    const toolSelect = document.getElementById("workspace-tool-select");
    if (toolSelect) {
        const current = toolSelect.value;
        toolSelect.innerHTML = "";
        workspaceState.tools
            .filter((tool) => tool.runnable !== false)
            .forEach((tool) => {
            const option = document.createElement("option");
            option.value = String(tool.tool_id || "");
            option.textContent = `${tool.label || tool.tool_id} (${tool.tool_id || ""})`;
            toolSelect.appendChild(option);
        });
        if (current && workspaceState.tools.some((tool) => String(tool.tool_id) === current && tool.runnable !== false)) {
            toolSelect.value = current;
        }
    }

    setText("tool-count", workspaceState.tools.length);
}

function renderProcesses(processes) {
    const body = document.getElementById("processes-body");
    if (!body) {
        return;
    }
    body.innerHTML = "";
    (processes || []).forEach((process) => {
        const tr = document.createElement("tr");
        tr.dataset.processId = String(process.id || "");
        tr.appendChild(makeCell(process.id));
        tr.appendChild(makeCell(process.name));
        const target = formatTargetLabel(process.hostIp, process.port, process.protocol);
        tr.appendChild(makeCell(target));
        const statusCell = document.createElement("td");
        const statusWrap = document.createElement("span");
        statusWrap.className = "process-status";
        const statusClass = getProcessStatusClass(process.status);
        if (statusClass) {
            statusWrap.classList.add(statusClass);
        }
        if (isProcessRunning(process.status)) {
            const spinner = document.createElement("span");
            spinner.className = "process-spinner";
            spinner.setAttribute("aria-hidden", "true");
            statusWrap.appendChild(spinner);
        }
        const statusText = document.createElement("span");
        statusText.textContent = process.status || "";
        statusWrap.appendChild(statusText);
        statusCell.appendChild(statusWrap);
        tr.appendChild(statusCell);

        let percentDisplay = process.percent || "";
        const numericPercent = Number(String(percentDisplay).replace("%", "").trim());
        if (Number.isFinite(numericPercent)) {
            percentDisplay = `${numericPercent.toFixed(1)}%`;
        }
        tr.appendChild(makeCell(percentDisplay));
        tr.appendChild(makeCell(formatEtaSeconds(process.estimatedRemaining)));

        const actions = document.createElement("td");
        actions.className = "process-actions";

        const viewBtn = document.createElement("button");
        viewBtn.type = "button";
        viewBtn.className = "icon-btn";
        viewBtn.title = "Output";
        viewBtn.setAttribute("aria-label", "Output");
        viewBtn.innerHTML = '<i class="fa-solid fa-terminal" aria-hidden="true"></i>';
        viewBtn.dataset.processAction = "output";
        viewBtn.dataset.processId = String(process.id || "");
        actions.appendChild(viewBtn);

        const retryBtn = document.createElement("button");
        retryBtn.type = "button";
        retryBtn.className = "icon-btn";
        retryBtn.title = "Retry";
        retryBtn.setAttribute("aria-label", "Retry");
        retryBtn.innerHTML = '<i class="fa-solid fa-rotate-right" aria-hidden="true"></i>';
        retryBtn.dataset.processAction = "retry";
        retryBtn.dataset.processId = String(process.id || "");
        actions.appendChild(retryBtn);

        if (isProcessRunning(process.status)) {
            const killBtn = document.createElement("button");
            killBtn.type = "button";
            killBtn.className = "icon-btn icon-btn-danger";
            killBtn.title = "Kill";
            killBtn.setAttribute("aria-label", "Kill");
            killBtn.innerHTML = '<i class="fa-solid fa-stop" aria-hidden="true"></i>';
            killBtn.dataset.processAction = "kill";
            killBtn.dataset.processId = String(process.id || "");
            actions.appendChild(killBtn);
        }

        const hideBtn = document.createElement("button");
        hideBtn.type = "button";
        hideBtn.className = "icon-btn";
        hideBtn.title = "Hide";
        hideBtn.setAttribute("aria-label", "Hide");
        hideBtn.innerHTML = '<i class="fa-solid fa-eye-slash" aria-hidden="true"></i>';
        hideBtn.dataset.processAction = "close";
        hideBtn.dataset.processId = String(process.id || "");
        actions.appendChild(hideBtn);

        tr.appendChild(actions);
        body.appendChild(tr);
    });
    setText("process-count", (processes || []).length);
}

function setProcessOutputMeta(text) {
    setText("process-output-meta", text || "");
}

function setProcessOutputText(text) {
    processOutputState.text = String(text || "");
    renderAnsiOutput("process-output-text", processOutputState.text);
}

function setProcessOutputCommand(text) {
    setText("process-output-command", text || "");
}

function setScriptOutputMeta(text) {
    setText("script-output-meta", text || "");
}

function setScriptOutputText(text) {
    scriptOutputState.output = String(text || "");
    renderAnsiOutput("script-output-text", scriptOutputState.output);
}

function setScriptOutputCommand(text) {
    setText("script-output-command", text || "");
}

function getStartupProjectAction() {
    const node = document.querySelector("input[name='startup-project-action']:checked");
    return node ? String(node.value || "new") : "new";
}

function syncStartupSchedulerFromMain() {
    setValue("startup-scheduler-mode", getValue("scheduler-mode-select") || "deterministic");
    setValue("startup-scheduler-goal", getValue("scheduler-goal-select") || "internal_asset_discovery");
    setValue("startup-scheduler-provider", getValue("scheduler-provider-select") || "none");
}

function updateStartupSummary() {
    const summaryNode = document.getElementById("startup-summary");
    if (!summaryNode) {
        return;
    }
    const lines = [
        `Project: ${startupWizardState.summary.project || "not configured"}`,
        `Imports: ${startupWizardState.summary.imports || "none"}`,
        `Scheduler: ${startupWizardState.summary.scheduler || "not configured"}`,
    ];
    summaryNode.textContent = lines.join("\n");
}

function setStartupWizardOpen(open) {
    const overlay = document.getElementById("startup-wizard-overlay");
    if (!overlay) {
        return;
    }
    startupWizardState.open = Boolean(open);
    overlay.classList.toggle("is-open", Boolean(open));
    overlay.setAttribute("aria-hidden", open ? "false" : "true");
    updateBodyModalState();
}

function setStartupWizardStep(step) {
    const nextStep = Math.max(1, Math.min(4, parseInt(step, 10) || 1));
    startupWizardState.step = nextStep;

    [1, 2, 3, 4].forEach((index) => {
        const section = document.getElementById(`startup-step-${index}`);
        if (section) {
            section.classList.toggle("is-active", index === nextStep);
        }
    });

    setText("startup-wizard-meta", `Step ${nextStep} of 4`);
    const back = document.getElementById("startup-wizard-back");
    const next = document.getElementById("startup-wizard-next");
    if (back) {
        back.disabled = nextStep <= 1 || startupWizardState.busy;
    }
    if (next) {
        next.disabled = startupWizardState.busy;
        next.textContent = nextStep === 4 ? "Go to Workspace" : "Continue";
    }
    if (nextStep === 4) {
        updateStartupSummary();
    }
}

function setStartupWizardBusy(busy) {
    startupWizardState.busy = Boolean(busy);
    const back = document.getElementById("startup-wizard-back");
    const next = document.getElementById("startup-wizard-next");
    const skip = document.getElementById("startup-wizard-skip");
    if (back) {
        back.disabled = Boolean(busy) || startupWizardState.step <= 1;
    }
    if (next) {
        next.disabled = Boolean(busy);
    }
    if (skip) {
        skip.disabled = Boolean(busy);
    }
}

function markStartupWizardDone() {
    try {
        window.sessionStorage.setItem(STARTUP_WIZARD_SESSION_KEY, "1");
    } catch (_err) {
    }
}

function shouldShowStartupWizard() {
    try {
        return window.sessionStorage.getItem(STARTUP_WIZARD_SESSION_KEY) !== "1";
    } catch (_err) {
        return true;
    }
}

function focusRunNmapScan() {
    setNmapScanModalOpen(true);
    resetNmapScanWizardState({scrollIntoView: false, focusTargets: true});
}

function resetNmapScanWizardState({scrollIntoView = false, focusTargets = false} = {}) {
    const block = document.getElementById("nmap-scan-block");
    if (scrollIntoView && block) {
        block.scrollIntoView({behavior: "smooth", block: "start"});
    }

    nmapWizardState.postSubmitLock = true;
    nmapWizardState.lastMode = "";
    setValue("nmap-targets", "");
    setChecked("nmap-run-actions", true);

    const easyMode = document.querySelector("input[name='nmap-scan-mode'][value='easy']");
    if (easyMode) {
        easyMode.checked = true;
    }

    applyNmapModeTargetDefaults("easy");
    setNmapWizardStep(1);
    refreshNmapModeOptions();
    refreshNmapScanButtonState();

    if (focusTargets) {
        const targetInput = document.getElementById("nmap-targets");
        if (targetInput) {
            window.setTimeout(() => {
                targetInput.focus();
            }, 220);
        }
    }
}

async function applyStartupProjectStep() {
    const action = getStartupProjectAction();
    if (action === "open") {
        const path = getValue("startup-project-open-path").trim();
        if (!path) {
            throw new Error("Existing project path is required.");
        }
        const body = await postJson("/api/project/open", {path});
        resetWorkspaceDisplayForProjectSwitch({clearProjectPaths: false});
        setValue("project-save-path", "");
        renderProject(body?.project || {});
        setValue("project-open-path", path);
        startupWizardState.summary.project = `opened ${path}`;
    } else {
        const body = await postJson("/api/project/new-temp", {});
        resetWorkspaceDisplayForProjectSwitch({clearProjectPaths: true});
        renderProject(body?.project || {});
        startupWizardState.summary.project = "created new temporary project";
    }
    await Promise.all([pollSnapshot(), refreshWorkspace(), loadApprovals()]);
}

async function applyStartupImportsStep() {
    const importActions = [];

    if (getChecked("startup-import-targets-enabled")) {
        const targetsPath = getValue("startup-import-targets-path").trim();
        if (!targetsPath) {
            throw new Error("Targets file path is required when targets import is enabled.");
        }
        const body = await postJson("/api/targets/import-file", {path: targetsPath});
        setValue("targets-file-path", targetsPath);
        const jobId = body?.job?.id;
        importActions.push(`targets file (${jobId ? `job ${jobId}` : "queued"})`);
    }

    if (getChecked("startup-import-xml-enabled")) {
        const xmlPath = getValue("startup-import-xml-path").trim();
        if (!xmlPath) {
            throw new Error("Nmap XML path is required when XML import is enabled.");
        }
        const runActions = getChecked("startup-import-xml-run-actions");
        const body = await postJson("/api/nmap/import-xml", {path: xmlPath, run_actions: runActions});
        setValue("nmap-xml-path", xmlPath);
        setChecked("nmap-xml-run-actions", runActions);
        const jobId = body?.job?.id;
        importActions.push(`nmap xml (${jobId ? `job ${jobId}` : "queued"})`);
    }

    startupWizardState.summary.imports = importActions.length ? importActions.join(", ") : "none";
    await pollSnapshot();
}

async function applyStartupSchedulerStep() {
    const mode = getValue("startup-scheduler-mode") || "deterministic";
    const goalProfile = getValue("startup-scheduler-goal") || "internal_asset_discovery";
    const provider = getValue("startup-scheduler-provider") || "none";
    const updates = {
        mode,
        goal_profile: goalProfile,
        provider,
    };

    if (provider === "lm_studio") {
        const baseUrl = getValue("provider-lmstudio-baseurl").trim() || "http://127.0.0.1:1234/v1";
        const model = getValue("provider-lmstudio-model").trim() || "o3-7b";
        updates.providers = {
            lm_studio: {
                enabled: true,
                base_url: baseUrl,
                model,
            },
        };
    } else if (provider === "openai") {
        updates.providers = {
            openai: {
                enabled: true,
                base_url: getValue("provider-openai-baseurl").trim() || "https://api.openai.com/v1",
                model: getValue("provider-openai-model").trim(),
            },
        };
    } else if (provider === "claude") {
        updates.providers = {
            claude: {
                enabled: true,
                base_url: getValue("provider-claude-baseurl").trim() || "https://api.anthropic.com",
                model: getValue("provider-claude-model").trim(),
            },
        };
    }

    await postJson("/api/scheduler/preferences", updates);

    setValue("scheduler-mode-select", mode);
    setValue("scheduler-goal-select", goalProfile);
    setValue("scheduler-provider-select", provider);
    startupWizardState.summary.scheduler = `${mode} / ${goalProfile} / provider=${provider}`;
    await loadSchedulerPreferences();
}

async function startupWizardNextAction() {
    if (startupWizardState.busy) {
        return;
    }
    setStartupWizardStatus("", false);

    if (startupWizardState.step === 4) {
        markStartupWizardDone();
        setStartupWizardOpen(false);
        setActionStatus("Setup complete. Opened Scans > Add Scan.");
        focusRunNmapScan();
        return;
    }

    try {
        setStartupWizardBusy(true);
        if (startupWizardState.step === 1) {
            setStartupWizardStatus("Applying project setup...");
            await applyStartupProjectStep();
            setStartupWizardStatus("Project step complete.");
        } else if (startupWizardState.step === 2) {
            setStartupWizardStatus("Applying import setup...");
            await applyStartupImportsStep();
            setStartupWizardStatus("Import step complete.");
        } else if (startupWizardState.step === 3) {
            setStartupWizardStatus("Applying scheduler setup...");
            await applyStartupSchedulerStep();
            setStartupWizardStatus("Scheduler step complete.");
        }
        setStartupWizardStep(startupWizardState.step + 1);
    } catch (err) {
        setStartupWizardStatus(`Setup error: ${err.message}`, true);
    } finally {
        setStartupWizardBusy(false);
    }
}

function startupWizardBackAction() {
    if (startupWizardState.busy) {
        return;
    }
    setStartupWizardStep(startupWizardState.step - 1);
    setStartupWizardStatus("", false);
}

function startupWizardSkipAction() {
    markStartupWizardDone();
    setStartupWizardOpen(false);
    setActionStatus("Setup wizard skipped. Opened Scans > Add Scan.");
    focusRunNmapScan();
}

function initializeStartupWizard() {
    syncStartupSchedulerFromMain();
    startupWizardState.summary = {
        project: "",
        imports: "",
        scheduler: "",
    };
    setStartupWizardStatus("", false);
    setStartupWizardStep(1);
    if (shouldShowStartupWizard()) {
        setStartupWizardOpen(true);
    } else {
        setStartupWizardOpen(false);
    }
}

function setNmapScanModalOpen(open) {
    const overlay = document.getElementById("nmap-scan-modal");
    if (!overlay) {
        return;
    }
    uiModalState.nmapScanOpen = Boolean(open);
    overlay.classList.toggle("is-open", Boolean(open));
    overlay.setAttribute("aria-hidden", open ? "false" : "true");
    updateBodyModalState();
}

function setManualScanModalOpen(open) {
    const overlay = document.getElementById("manual-scan-modal");
    if (!overlay) {
        return;
    }
    uiModalState.manualScanOpen = Boolean(open);
    overlay.classList.toggle("is-open", Boolean(open));
    overlay.setAttribute("aria-hidden", open ? "false" : "true");
    updateBodyModalState();
}

function setHostSelectionModalOpen(open) {
    const overlay = document.getElementById("host-selection-modal");
    if (!overlay) {
        return;
    }
    uiModalState.hostSelectionOpen = Boolean(open);
    overlay.classList.toggle("is-open", Boolean(open));
    overlay.setAttribute("aria-hidden", open ? "false" : "true");
    updateBodyModalState();
}

function setScriptCveModalOpen(open) {
    const overlay = document.getElementById("script-cve-modal");
    if (!overlay) {
        return;
    }
    uiModalState.scriptCveOpen = Boolean(open);
    overlay.classList.toggle("is-open", Boolean(open));
    overlay.setAttribute("aria-hidden", open ? "false" : "true");
    updateBodyModalState();
}

function setProviderLogsModalOpen(open) {
    const overlay = document.getElementById("provider-logs-modal");
    if (!overlay) {
        return;
    }
    uiModalState.providerLogsOpen = Boolean(open);
    providerLogsState.modalOpen = Boolean(open);
    overlay.classList.toggle("is-open", Boolean(open));
    overlay.setAttribute("aria-hidden", open ? "false" : "true");
    updateBodyModalState();
}

function setJobsModalOpen(open) {
    const overlay = document.getElementById("jobs-modal");
    if (!overlay) {
        return;
    }
    uiModalState.jobsOpen = Boolean(open);
    overlay.classList.toggle("is-open", Boolean(open));
    overlay.setAttribute("aria-hidden", open ? "false" : "true");
    updateBodyModalState();
}

function setSubmittedScansModalOpen(open) {
    const overlay = document.getElementById("submitted-scans-modal");
    if (!overlay) {
        return;
    }
    uiModalState.submittedScansOpen = Boolean(open);
    overlay.classList.toggle("is-open", Boolean(open));
    overlay.setAttribute("aria-hidden", open ? "false" : "true");
    updateBodyModalState();
}

function setSchedulerDecisionsModalOpen(open) {
    const overlay = document.getElementById("scheduler-decisions-modal");
    if (!overlay) {
        return;
    }
    uiModalState.schedulerDecisionsOpen = Boolean(open);
    overlay.classList.toggle("is-open", Boolean(open));
    overlay.setAttribute("aria-hidden", open ? "false" : "true");
    updateBodyModalState();
}

function setHostRemoveModalOpen(open) {
    const overlay = document.getElementById("host-remove-modal");
    if (!overlay) {
        return;
    }
    uiModalState.hostRemoveOpen = Boolean(open);
    hostRemoveState.modalOpen = Boolean(open);
    overlay.classList.toggle("is-open", Boolean(open));
    overlay.setAttribute("aria-hidden", open ? "false" : "true");
    updateBodyModalState();
}

function setGraphNoteModalOpen(open) {
    const overlay = document.getElementById("graph-note-modal");
    if (!overlay) {
        return;
    }
    uiModalState.graphNoteOpen = Boolean(open);
    overlay.classList.toggle("is-open", Boolean(open));
    overlay.setAttribute("aria-hidden", open ? "false" : "true");
    updateBodyModalState();
    if (open) {
        window.requestAnimationFrame(() => {
            const input = document.getElementById("graph-note-input");
            if (input) {
                input.focus();
                input.setSelectionRange(input.value.length, input.value.length);
            }
        });
    }
}

function closeNmapScanModalAction() {
    setNmapScanModalOpen(false);
}

function closeManualScanModalAction() {
    setManualScanModalOpen(false);
}

function closeHostSelectionModalAction() {
    setHostSelectionModalOpen(false);
}

function closeScriptCveModalAction() {
    setScriptCveModalOpen(false);
}

function closeProviderLogsModalAction() {
    setProviderLogsModalOpen(false);
}

function closeJobsModalAction() {
    setJobsModalOpen(false);
}

function closeSubmittedScansModalAction() {
    setSubmittedScansModalOpen(false);
}

function closeSchedulerDecisionsModalAction() {
    setSchedulerDecisionsModalOpen(false);
}

function closeHostRemoveModalAction(clearSelection = true) {
    setHostRemoveModalOpen(false);
    if (clearSelection) {
        hostRemoveState.hostId = null;
        hostRemoveState.hostIp = "";
        hostRemoveState.hostName = "";
        setText("host-remove-modal-target", "");
    }
}

function closeGraphNoteModalAction(clearInput = false) {
    setGraphNoteModalOpen(false);
    if (clearInput) {
        setValue("graph-note-input", "");
    }
}

function prefillManualScanFromSelection() {
    const current = getValue("workspace-tool-host-ip").trim();
    if (current) {
        return;
    }
    const host = workspaceState.hosts.find((item) => String(item.id) === String(workspaceState.selectedHostId));
    if (host?.ip) {
        setValue("workspace-tool-host-ip", host.ip);
    }
}

function openAddScanAction() {
    closeRibbonMenus();
    setNmapScanModalOpen(true);
    resetNmapScanWizardState({scrollIntoView: false, focusTargets: true});
}

function openManualScanAction() {
    closeRibbonMenus();
    setManualScanModalOpen(true);
    prefillManualScanFromSelection();
}

function openHostSelectionAction() {
    closeRibbonMenus();
    setHostSelectionModalOpen(true);
}

function openScriptCveAction() {
    closeRibbonMenus();
    setScriptCveModalOpen(true);
}

async function openProviderLogsAction() {
    closeRibbonMenus();
    setProviderLogsModalOpen(true);
    await loadProviderLogsAction();
}

async function openJobsAction() {
    closeRibbonMenus();
    setJobsModalOpen(true);
    await pollSnapshot();
}

async function openSubmittedScansAction() {
    closeRibbonMenus();
    setSubmittedScansModalOpen(true);
    await pollSnapshot();
}

async function openSchedulerDecisionsAction() {
    closeRibbonMenus();
    setSchedulerDecisionsModalOpen(true);
    await pollSnapshot();
}

function requestHostRemoveAction(hostId) {
    const id = parseInt(hostId, 10);
    if (!id) {
        return;
    }
    const host = workspaceState.hosts.find((item) => parseInt(item.id, 10) === id);
    hostRemoveState.hostId = id;
    hostRemoveState.hostIp = String(host?.ip || "");
    hostRemoveState.hostName = String(host?.hostname || "");
    const hostLabel = hostRemoveState.hostName
        ? `${hostRemoveState.hostIp} (${hostRemoveState.hostName})`
        : hostRemoveState.hostIp;
    setText("host-remove-modal-target", hostLabel || `Host ID ${id}`);
    setHostRemoveModalOpen(true);
}

function setSchedulerModalOpen(open) {
    const overlay = document.getElementById("scheduler-settings-modal");
    if (!overlay) {
        return;
    }
    uiModalState.schedulerOpen = Boolean(open);
    overlay.classList.toggle("is-open", Boolean(open));
    overlay.setAttribute("aria-hidden", open ? "false" : "true");
    updateBodyModalState();
}

function setReportProviderModalOpen(open) {
    const overlay = document.getElementById("report-provider-modal");
    if (!overlay) {
        return;
    }
    uiModalState.reportProviderOpen = Boolean(open);
    overlay.classList.toggle("is-open", Boolean(open));
    overlay.setAttribute("aria-hidden", open ? "false" : "true");
    updateBodyModalState();
}

function setAppSettingsModalOpen(open) {
    const overlay = document.getElementById("app-settings-modal");
    if (!overlay) {
        return;
    }
    uiModalState.settingsOpen = Boolean(open);
    overlay.classList.toggle("is-open", Boolean(open));
    overlay.setAttribute("aria-hidden", open ? "false" : "true");
    updateBodyModalState();
}

function setConfigSettingsStatus(text, isError = false) {
    const node = document.getElementById("settings-config-status");
    if (!node) {
        return;
    }
    node.textContent = text || "";
    node.style.color = isError ? "#ff9b9b" : "";
}

function setToolAuditStatus(text, isError = false) {
    const node = document.getElementById("settings-tool-audit-status");
    if (!node) {
        return;
    }
    node.textContent = text || "";
    node.style.color = isError ? "#ff9b9b" : "";
}

function renderToolAuditRows(rows) {
    const tbody = document.getElementById("settings-tool-audit-body");
    if (!tbody) {
        return;
    }
    const items = Array.isArray(rows) ? rows : [];
    if (!items.length) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty-cell">No tool audit data.</td></tr>';
        return;
    }
    tbody.innerHTML = items.map((row) => {
        const status = String(row?.status || "unknown");
        const resolved = row?.resolved_path || row?.configured_value || "-";
        const statusClass = status === "installed"
            ? "tool-audit-status-ok"
            : (status === "configured-missing" ? "tool-audit-status-warn" : "tool-audit-status-missing");
        return `
            <tr>
                <td>
                    <strong>${escapeHtml(row?.label || row?.key || "tool")}</strong>
                    <div class="meta-note">${escapeHtml(row?.purpose || "")}</div>
                    ${row?.notes ? `<div class="meta-note">${escapeHtml(row.notes)}</div>` : ""}
                </td>
                <td>${escapeHtml(row?.category || "")}</td>
                <td><span class="${statusClass}">${escapeHtml(status)}</span></td>
                <td><code>${escapeHtml(resolved)}</code></td>
                <td><code>${escapeHtml(row?.kali_install || "-")}</code></td>
                <td><code>${escapeHtml(row?.ubuntu_install || "-")}</code></td>
            </tr>
        `;
    }).join("");
}

async function refreshToolAuditAction() {
    setToolAuditStatus("Checking tools...");
    try {
        const body = await fetchJson("/api/settings/tool-audit");
        renderToolAuditRows(body?.tools || []);
        const summary = body?.summary || {};
        setToolAuditStatus(
            `Installed ${summary.installed || 0}/${summary.total || 0}; missing ${summary.missing || 0}; configured missing ${summary.configured_missing || 0}`
        );
    } catch (err) {
        renderToolAuditRows([]);
        setToolAuditStatus(`Tool audit failed: ${err.message}`, true);
    }
}

function launchStartupWizardAction() {
    syncStartupSchedulerFromMain();
    setStartupWizardStatus("", false);
    setStartupWizardStep(1);
    setStartupWizardOpen(true);
}

function setRibbonMenuOpen(menuId, open) {
    const nextOpen = Boolean(open) ? String(menuId || "").trim() : "";
    ribbonMenuState.openMenuId = nextOpen || null;
    const menus = document.querySelectorAll(".ribbon-menu[data-ribbon-menu]");
    menus.forEach((menu) => {
        const currentId = String(menu.dataset.ribbonMenu || "");
        const isOpen = nextOpen && currentId === nextOpen;
        menu.classList.toggle("is-open", Boolean(isOpen));
        const trigger = menu.querySelector("[data-ribbon-menu-toggle]");
        if (trigger) {
            trigger.setAttribute("aria-expanded", isOpen ? "true" : "false");
        }
    });
}

function closeRibbonMenus() {
    setRibbonMenuOpen("", false);
}

function toggleRibbonMenu(menuId) {
    const nextId = String(menuId || "").trim();
    if (!nextId) {
        closeRibbonMenus();
        return;
    }
    const isOpen = ribbonMenuState.openMenuId === nextId;
    setRibbonMenuOpen(nextId, !isOpen);
}

async function openWorkspaceFromRibbonAction() {
    closeRibbonMenus();
    let path = getValue("project-open-path").trim();
    if (!path) {
        const prompted = window.prompt("Enter existing project path (.legion):", "");
        path = String(prompted || "").trim();
        if (!path) {
            return;
        }
        setValue("project-open-path", path);
    }
    await openProject();
}

async function saveWorkspaceFromRibbonAction(forcePrompt = false) {
    closeRibbonMenus();
    let path = getValue("project-save-path").trim();
    if (forcePrompt || !path) {
        const suggested = String(getValue("project-name") || "").trim();
        const prompted = window.prompt("Enter destination path (.legion):", suggested);
        path = String(prompted || "").trim();
        if (!path) {
            return;
        }
        setValue("project-save-path", path);
    }
    await saveProjectAs();
}

async function saveWorkspaceAction() {
    closeRibbonMenus();
    const path = getValue("project-save-path").trim();
    if (!path) {
        setActionStatus("Save failed: no destination path is set. Use Save As.", true);
        return;
    }
    await saveProjectAs();
}

async function saveWorkspaceAsAction() {
    await saveWorkspaceFromRibbonAction(true);
}

function downloadWorkspaceBundleAction() {
    closeRibbonMenus();
    window.location.assign(`/api/project/download-zip?t=${Date.now()}`);
}

function restoreWorkspaceBundleAction() {
    closeRibbonMenus();
    const input = document.getElementById("project-restore-zip-file");
    if (!input) {
        setActionStatus("Restore failed: ZIP input control missing.", true);
        return;
    }
    input.value = "";
    input.click();
}

async function restoreWorkspaceBundleSelectedAction(event) {
    const input = event?.target;
    const file = input?.files && input.files.length ? input.files[0] : null;
    if (!file) {
        return;
    }

    setActionStatus(`Uploading restore bundle (${file.name})...`);
    try {
        const formData = new FormData();
        formData.append("bundle", file, file.name || "workspace.zip");
        const response = await fetch("/api/project/restore-zip", {
            method: "POST",
            body: formData,
        });
        let body = {};
        try {
            body = await response.json();
        } catch (_err) {
        }
        if (!response.ok) {
            const message = body.error || `Request failed (${response.status})`;
            throw new Error(message);
        }

        const jobId = Number(body?.job?.id || 0);
        if (jobId > 0) {
            setActionStatus(`Restore queued (job ${jobId})...`);
            const completed = await waitForJobCompletion(jobId, 20 * 60 * 1000, 1500);
            const restoredPath = String(completed?.result?.project?.name || "").trim();
            if (restoredPath) {
                setValue("project-save-path", restoredPath);
                setValue("project-open-path", restoredPath);
            }
        }

        setActionStatus("Workspace restored");
        resetWorkspaceDisplayForProjectSwitch({clearProjectPaths: false});
        await refreshWorkspace();
        await Promise.all([pollSnapshot(), loadApprovals()]);
    } catch (err) {
        setActionStatus(`Restore failed: ${err.message}`, true);
    } finally {
        if (input) {
            input.value = "";
        }
    }
}

async function importNmapXmlFromRibbonAction() {
    closeRibbonMenus();
    let path = getValue("nmap-xml-path").trim();
    if (!path) {
        const prompted = window.prompt("Enter Nmap XML path:", "");
        path = String(prompted || "").trim();
        if (!path) {
            return;
        }
        setValue("nmap-xml-path", path);
    }
    const runActions = window.confirm("Run scripted actions after XML import?");
    setChecked("nmap-xml-run-actions", runActions);
    await importNmapXml();
}

async function importTargetsFromRibbonAction() {
    closeRibbonMenus();
    let path = getValue("targets-file-path").trim();
    if (!path) {
        const prompted = window.prompt("Enter targets text file path:", "");
        path = String(prompted || "").trim();
        if (!path) {
            return;
        }
        setValue("targets-file-path", path);
    }
    await importTargetsFile();
}

function exportWorkspaceJsonAction() {
    closeRibbonMenus();
    window.location.assign(`/api/export/json?t=${Date.now()}`);
}

function exportWorkspaceCsvAction() {
    closeRibbonMenus();
    window.location.assign(`/api/export/csv?t=${Date.now()}`);
}

function currentHostFilterQuery() {
    const params = new URLSearchParams();
    const filter = String(workspaceState.hostFilter || "hide_down").trim().toLowerCase() === "show_all"
        ? "show_all"
        : "hide_down";
    params.set("filter", filter);
    const service = String(workspaceState.hostServiceFilter || "").trim();
    if (service) {
        params.set("service", service);
    }
    return params.toString();
}

function exportHostsJsonAction() {
    closeRibbonMenus();
    window.location.assign(`/api/export/hosts-json?${currentHostFilterQuery()}&t=${Date.now()}`);
}

function exportHostsCsvAction() {
    closeRibbonMenus();
    window.location.assign(`/api/export/hosts-csv?${currentHostFilterQuery()}&t=${Date.now()}`);
}

function syncHostFilterControls() {
    const showAll = document.getElementById("hosts-filter-show-all-button");
    const hideDown = document.getElementById("hosts-filter-hide-down-button");
    const resetButton = document.getElementById("hosts-reset-filter-button");
    const filter = String(workspaceState.hostFilter || "hide_down").trim().toLowerCase();
    const service = String(workspaceState.hostServiceFilter || "").trim();
    if (showAll) {
        showAll.classList.toggle("is-active", filter === "show_all");
    }
    if (hideDown) {
        hideDown.classList.toggle("is-active", filter !== "show_all");
    }
    if (resetButton) {
        const atDefault = filter === "hide_down" && !service;
        resetButton.disabled = atDefault;
        resetButton.classList.toggle("is-active", !atDefault);
        const label = service
            ? `Reset host filters (show only up hosts, clear service filter: ${service})`
            : "Reset host filters (show only up hosts)";
        resetButton.setAttribute("title", label);
        resetButton.setAttribute("aria-label", label);
    }
}

async function setHostFilterAction(filter) {
    workspaceState.hostFilter = String(filter || "hide_down").trim().toLowerCase() === "show_all"
        ? "show_all"
        : "hide_down";
    syncHostFilterControls();
    closeRibbonMenus();
    await loadWorkspaceHosts();
    await graphLoadSnapshot({background: false}).catch(() => {});
}

async function setHostServiceFilterAction(service) {
    workspaceState.hostServiceFilter = String(service || "").trim();
    syncHostFilterControls();
    renderServices(workspaceState.services);
    await loadWorkspaceHosts();
}

async function resetHostFiltersAction() {
    workspaceState.hostFilter = "hide_down";
    workspaceState.hostServiceFilter = "";
    syncHostFilterControls();
    renderServices(workspaceState.services);
    closeRibbonMenus();
    await loadWorkspaceHosts();
    await graphLoadSnapshot({background: false}).catch(() => {});
}

function exportProjectAiReportAction(format = "json") {
    closeRibbonMenus();
    const normalized = String(format || "json").toLowerCase() === "md" ? "md" : "json";
    window.location.assign(`/api/workspace/project-ai-report?format=${normalized}&t=${Date.now()}`);
}

function exportAllHostAiReportsZipAction() {
    closeRibbonMenus();
    window.location.assign(`/api/workspace/ai-reports/download-zip?t=${Date.now()}`);
}

function exportSelectedHostAiReportAction(format = "json") {
    const hostId = Number(workspaceState.selectedHostId || 0);
    if (!Number.isFinite(hostId) || hostId <= 0) {
        setWorkspaceStatus("Select a host first to export report.", true);
        return;
    }
    const normalized = String(format || "json").toLowerCase() === "md" ? "md" : "json";
    window.location.assign(`/api/workspace/hosts/${hostId}/ai-report?format=${normalized}&t=${Date.now()}`);
}

async function pushProjectAiReportAction(event) {
    if (event) {
        event.preventDefault();
    }
    closeRibbonMenus();

    let delivery;
    try {
        delivery = collectProjectReportDeliveryFromForm();
    } catch (err) {
        const message = `Project report settings error: ${err.message}`;
        setActionStatus(message, true);
        setText("report-provider-save-status", message);
        return;
    }

    setActionStatus("Pushing project report...");
    setText("report-provider-save-status", "Pushing project report...");
    try {
        const result = await postJson("/api/workspace/project-ai-report/push", {
            project_report_delivery: delivery,
        });
        const summary = result?.status_code
            ? `Project report pushed (${result.status_code})`
            : "Project report pushed";
        setActionStatus(summary, false);
        setText("report-provider-save-status", summary);
    } catch (err) {
        const message = `Project report push failed: ${err.message}`;
        setActionStatus(message, true);
        setText("report-provider-save-status", message);
    }
}

function openSchedulerSettingsAction() {
    setSchedulerModalOpen(true);
}

function closeSchedulerSettingsAction() {
    setSchedulerModalOpen(false);
}

function openReportProviderAction() {
    closeRibbonMenus();
    setReportProviderModalOpen(true);
}

function closeReportProviderModalAction() {
    setReportProviderModalOpen(false);
}

async function refreshAppSettingsConfigAction() {
    setConfigSettingsStatus("Loading config...");
    try {
        const body = await fetchJson("/api/settings/legion-conf");
        setText("settings-config-path", body.path || "legion.conf");
        setValue("settings-config-text", body.text || "");
        setConfigSettingsStatus("Config loaded");
    } catch (err) {
        setConfigSettingsStatus(`Load failed: ${err.message}`, true);
    }
}

async function saveAppSettingsConfigAction() {
    const text = getValue("settings-config-text");
    setConfigSettingsStatus("Saving config...");
    try {
        const body = await postJson("/api/settings/legion-conf", {text});
        setText("settings-config-path", body.path || "legion.conf");
        setConfigSettingsStatus("Config saved");
    } catch (err) {
        setConfigSettingsStatus(`Save failed: ${err.message}`, true);
    }
}

async function openAppSettingsAction() {
    setAppSettingsModalOpen(true);
    await Promise.allSettled([
        refreshAppSettingsConfigAction(),
        refreshToolAuditAction(),
    ]);
}

function closeAppSettingsAction() {
    setAppSettingsModalOpen(false);
}

function setProcessOutputModalOpen(open) {
    const modal = document.getElementById("process-output-modal");
    if (!modal) {
        return;
    }
    processOutputState.modalOpen = Boolean(open);
    modal.classList.toggle("is-open", Boolean(open));
    modal.setAttribute("aria-hidden", open ? "false" : "true");
    updateBodyModalState();
}

function setScriptOutputModalOpen(open) {
    const modal = document.getElementById("script-output-modal");
    if (!modal) {
        return;
    }
    scriptOutputState.modalOpen = Boolean(open);
    modal.classList.toggle("is-open", Boolean(open));
    modal.setAttribute("aria-hidden", open ? "false" : "true");
    updateBodyModalState();
}

function setScreenshotModalOpen(open) {
    const modal = document.getElementById("screenshot-modal");
    if (!modal) {
        return;
    }
    screenshotModalState.modalOpen = Boolean(open);
    modal.classList.toggle("is-open", Boolean(open));
    modal.setAttribute("aria-hidden", open ? "false" : "true");
    updateBodyModalState();
}

function stopProcessOutputAutoRefresh() {
    if (processOutputState.refreshTimer) {
        window.clearInterval(processOutputState.refreshTimer);
        processOutputState.refreshTimer = null;
    }
}

function startProcessOutputAutoRefresh() {
    stopProcessOutputAutoRefresh();
    processOutputState.refreshTimer = window.setInterval(() => {
        if (!processOutputState.modalOpen) {
            return;
        }
        refreshProcessOutputAction(false, false).catch(() => {});
    }, PROCESS_OUTPUT_REFRESH_MS);
}

function closeProcessOutputModal(resetSelection = true) {
    stopProcessOutputAutoRefresh();
    processOutputState.refreshInFlight = false;
    setProcessOutputModalOpen(false);
    if (resetSelection) {
        processOutputState.processId = null;
        processOutputState.offset = 0;
        processOutputState.complete = true;
        processOutputState.status = "";
        processOutputState.text = "";
        setProcessOutputMeta("No process selected");
        setProcessOutputCommand("");
        setProcessOutputText("");
    }
}

function closeScriptOutputModal(resetSelection = true) {
    setScriptOutputModalOpen(false);
    if (resetSelection) {
        scriptOutputState.scriptDbId = null;
        scriptOutputState.processId = 0;
        scriptOutputState.scriptId = "";
        scriptOutputState.source = "";
        scriptOutputState.output = "";
        scriptOutputState.command = "";
        scriptOutputState.status = "";
        scriptOutputState.downloadName = "";
        setText("script-output-modal-title", "Script Output");
        setScriptOutputMeta("No script selected");
        setScriptOutputCommand("");
        setScriptOutputText("");
    }
}

function closeScreenshotModal(resetSelection = true) {
    setScreenshotModalOpen(false);
    if (resetSelection) {
        screenshotModalState.url = "";
        screenshotModalState.filename = "";
        screenshotModalState.port = "";
        const image = document.getElementById("screenshot-modal-image");
        if (image) {
            image.removeAttribute("src");
        }
        setText("screenshot-modal-meta", "No screenshot selected");
    }
}

async function openProcessOutputModal(processId) {
    const pid = parseInt(processId, 10);
    if (!pid) {
        return;
    }
    setProcessOutputModalOpen(true);
    setProcessOutputMeta(`Process ${pid} | loading...`);
    setProcessOutputCommand("");
    setProcessOutputText("");
    processOutputState.processId = pid;
    processOutputState.offset = 0;
    processOutputState.complete = false;
    processOutputState.status = "";
    startProcessOutputAutoRefresh();
    try {
        await refreshProcessOutputAction(true, true);
    } catch (err) {
        setProcessOutputMeta(`Process ${pid} | load failed`);
        setProcessOutputText(`Failed to load process output: ${err.message || err}`);
    }
}

async function openScriptOutputModal(scriptDbId) {
    const sid = parseInt(scriptDbId, 10);
    if (!sid) {
        return;
    }
    setScriptOutputModalOpen(true);
    setText("script-output-modal-title", "Script Output");
    setScriptOutputMeta(`Script ${sid} | loading...`);
    setScriptOutputCommand("");
    setScriptOutputText("");
    scriptOutputState.scriptDbId = sid;
    scriptOutputState.processId = 0;
    scriptOutputState.scriptId = "";
    scriptOutputState.source = "";
    scriptOutputState.output = "";
    scriptOutputState.command = "";
    scriptOutputState.status = "";
    scriptOutputState.downloadName = "";
    try {
        const payload = await fetchJson(`/api/workspace/scripts/${sid}/output?max_chars=50000`);
        const outputText = String(payload.output || payload.output_chunk || "");
        const sourceLabel = payload.source === "process"
            ? `Process ${payload.process_id || "?"}`
            : "Script row output";
        scriptOutputState.processId = parseInt(payload.process_id, 10) || 0;
        scriptOutputState.scriptId = String(payload.script_id || "");
        scriptOutputState.source = String(payload.source || "");
        scriptOutputState.output = outputText;
        scriptOutputState.command = String(payload.command || "");
        scriptOutputState.status = String(payload.status || "");
        scriptOutputState.downloadName = "";
        setScriptOutputCommand(payload.command || "(no associated process command)");
        setScriptOutputText(outputText);
        setScriptOutputMeta(
            `${payload.script_id || `Script ${sid}`} | ${sourceLabel} | bytes ${payload.output_length || outputText.length}`
        );
    } catch (err) {
        setScriptOutputMeta(`Script ${sid} | load failed`);
        setScriptOutputText(`Failed to load script output: ${err.message || err}`);
    }
}

function openTextPreviewModal({title = "Artifact Preview", meta = "", command = "", output = "", downloadName = ""} = {}) {
    setScriptOutputModalOpen(true);
    scriptOutputState.scriptDbId = null;
    scriptOutputState.processId = 0;
    scriptOutputState.scriptId = "";
    scriptOutputState.source = "graph";
    scriptOutputState.output = String(output || "");
    scriptOutputState.command = String(command || "");
    scriptOutputState.status = "";
    scriptOutputState.downloadName = String(downloadName || "");
    setText("script-output-modal-title", title || "Artifact Preview");
    setScriptOutputMeta(String(meta || "Artifact preview"));
    setScriptOutputCommand(command || "(no associated command)");
    setScriptOutputText(output || "");
}

function openScreenshotModal(url, filename, port = "") {
    const resolvedUrl = String(url || "").trim();
    if (!resolvedUrl) {
        setWorkspaceStatus("Screenshot URL is missing", true);
        return;
    }
    screenshotModalState.url = resolvedUrl;
    screenshotModalState.filename = String(filename || "").trim() || "screenshot.png";
    screenshotModalState.port = String(port || "").trim();
    const image = document.getElementById("screenshot-modal-image");
    if (image) {
        image.src = `${resolvedUrl}${resolvedUrl.includes("?") ? "&" : "?"}t=${Date.now()}`;
        image.alt = screenshotModalState.filename || "Screenshot preview";
    }
    const portSuffix = screenshotModalState.port ? ` (${screenshotModalState.port})` : "";
    setText("screenshot-modal-meta", `${screenshotModalState.filename}${portSuffix}`);
    setScreenshotModalOpen(true);
}

async function refreshProcessOutputAction(force = false, reset = false) {
    const pid = parseInt(processOutputState.processId, 10);
    if (!pid) {
        return;
    }
    if (!force && processOutputState.complete) {
        return;
    }
    if (processOutputState.refreshInFlight) {
        return;
    }

    processOutputState.refreshInFlight = true;
    try {
        await loadProcessOutput(pid, Boolean(reset));
    } finally {
        processOutputState.refreshInFlight = false;
    }
}

async function copyProcessOutputAction() {
    const text = processOutputState.text || "";
    await copyTextToClipboard(text, "Process output copied to clipboard", "No process output to copy");
}

async function copyProcessCommandAction() {
    const node = document.getElementById("process-output-command");
    const text = node ? String(node.textContent || "") : "";
    await copyTextToClipboard(text, "Command copied to clipboard", "No command to copy");
}

async function copyScriptOutputAction() {
    const text = scriptOutputState.output || "";
    await copyTextToClipboard(text, "Script output copied to clipboard", "No script output to copy");
}

async function copyScriptCommandAction() {
    const node = document.getElementById("script-output-command");
    const text = node ? String(node.textContent || "") : "";
    await copyTextToClipboard(text, "Command copied to clipboard", "No command to copy");
}

async function copyScreenshotAction() {
    const url = String(screenshotModalState.url || "").trim();
    if (!url) {
        setWorkspaceStatus("No screenshot to copy", true);
        return;
    }
    if (!(navigator.clipboard && window.ClipboardItem && navigator.clipboard.write)) {
        await copyTextToClipboard(url, "Screenshot URL copied to clipboard", "No screenshot to copy");
        return;
    }
    try {
        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        const blob = await response.blob();
        const type = blob.type || "image/png";
        const item = new ClipboardItem({[type]: blob});
        await navigator.clipboard.write([item]);
        setWorkspaceStatus("Screenshot copied to clipboard");
    } catch (err) {
        setWorkspaceStatus(`Screenshot copy failed: ${err.message}`, true);
    }
}

async function copyTextToClipboard(text, successMessage, emptyMessage) {
    const value = String(text || "");
    if (!value) {
        setWorkspaceStatus(emptyMessage || "Nothing to copy", true);
        return;
    }
    try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(value);
        } else {
            const temp = document.createElement("textarea");
            temp.value = value;
            temp.setAttribute("readonly", "readonly");
            temp.style.position = "absolute";
            temp.style.left = "-9999px";
            document.body.appendChild(temp);
            temp.select();
            document.execCommand("copy");
            document.body.removeChild(temp);
        }
        setWorkspaceStatus(successMessage || "Copied to clipboard");
    } catch (err) {
        setWorkspaceStatus(`Copy failed: ${err.message}`, true);
    }
}

function downloadProcessOutputAction() {
    const text = processOutputState.text || "";
    if (!text) {
        setWorkspaceStatus("No process output to download", true);
        return;
    }
    const processId = parseInt(processOutputState.processId, 10) || "unknown";
    const blob = new Blob([text], {type: "text/plain;charset=utf-8"});
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `process-${processId}-output.txt`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    setWorkspaceStatus(`Process ${processId} output downloaded`);
}

function downloadScriptOutputAction() {
    const text = scriptOutputState.output || "";
    if (!text) {
        setWorkspaceStatus("No script output to download", true);
        return;
    }
    if (scriptOutputState.downloadName) {
        const blob = new Blob([text], {type: "text/plain;charset=utf-8"});
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = scriptOutputState.downloadName;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
        setWorkspaceStatus(`${scriptOutputState.downloadName} downloaded`);
        return;
    }
    const scriptDbId = parseInt(scriptOutputState.scriptDbId, 10) || "unknown";
    const scriptId = String(scriptOutputState.scriptId || "").trim() || `script-${scriptDbId}`;
    const safeName = scriptId.replace(/[^a-zA-Z0-9._-]+/g, "-");
    const blob = new Blob([text], {type: "text/plain;charset=utf-8"});
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${safeName}-${scriptDbId}-output.txt`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    setWorkspaceStatus(`Script ${scriptDbId} output downloaded`);
}

async function downloadScreenshotAction() {
    const url = String(screenshotModalState.url || "").trim();
    if (!url) {
        setWorkspaceStatus("No screenshot to download", true);
        return;
    }
    try {
        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        const blob = await response.blob();
        const downloadName = String(screenshotModalState.filename || "screenshot.png").replace(/[^a-zA-Z0-9._-]+/g, "-");
        const objectUrl = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = objectUrl;
        a.download = downloadName || "screenshot.png";
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(objectUrl);
        setWorkspaceStatus(`Downloaded ${downloadName}`);
    } catch (err) {
        setWorkspaceStatus(`Screenshot download failed: ${err.message}`, true);
    }
}

async function loadProviderLogsAction() {
    setText("provider-logs-meta", "Loading logs...");
    try {
        const payload = await fetchJson("/api/scheduler/provider/logs?limit=400");
        providerLogsState.text = String(payload.text || "");
        providerLogsState.count = Array.isArray(payload.logs) ? payload.logs.length : 0;
        renderAnsiOutput("provider-logs-text", providerLogsState.text);
        setText(
            "provider-logs-meta",
            `Entries ${providerLogsState.count} | bytes ${providerLogsState.text.length}`
        );
    } catch (err) {
        const message = `Failed to load provider logs: ${err.message}`;
        providerLogsState.text = message;
        renderAnsiOutput("provider-logs-text", message);
        setText("provider-logs-meta", "Load failed");
        setWorkspaceStatus(message, true);
    }
}

async function copyProviderLogsAction() {
    const text = providerLogsState.text || "";
    await copyTextToClipboard(text, "Provider logs copied to clipboard", "No provider logs to copy");
}

function downloadProviderLogsAction() {
    const text = providerLogsState.text || "";
    if (!text) {
        setWorkspaceStatus("No provider logs to download", true);
        return;
    }
    const blob = new Blob([text], {type: "text/plain;charset=utf-8"});
    const url = URL.createObjectURL(blob);
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const a = document.createElement("a");
    a.href = url;
    a.download = `provider-logs-${stamp}.txt`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    setWorkspaceStatus("Provider logs downloaded");
}

async function rescanHostAction(hostId) {
    const id = parseInt(hostId, 10);
    if (!id) {
        return;
    }
    try {
        const body = await postJson(`/api/workspace/hosts/${id}/rescan`, {});
        setWorkspaceStatus(`Rescan queued (job ${body?.job?.id || "?"})`);
        await pollSnapshot();
    } catch (err) {
        setWorkspaceStatus(`Rescan failed: ${err.message}`, true);
    }
}

async function rescanSubnetAction(subnet) {
    const value = String(subnet || "").trim();
    if (!value) {
        return;
    }
    try {
        const body = await postJson("/api/workspace/subnets/rescan", {subnet: value});
        const jobId = Number(body?.job?.id || 0);
        if (body?.job?.existing) {
            setWorkspaceStatus(`Subnet rescan already queued/running (job ${jobId || "?"})`);
        } else {
            setWorkspaceStatus(`Subnet rescan queued (job ${jobId || "?"})`);
        }
        await pollSnapshot();
    } catch (err) {
        setWorkspaceStatus(`Subnet rescan failed: ${err.message}`, true);
    }
}

async function digDeeperHostAction(hostId) {
    const id = parseInt(hostId, 10);
    if (!id) {
        return;
    }
    try {
        const body = await postJson(`/api/workspace/hosts/${id}/dig-deeper`, {});
        if (body?.job?.existing) {
            setWorkspaceStatus(`Dig deeper already queued/running (job ${body?.job?.id || "?"})`);
        } else {
            setWorkspaceStatus(`Dig deeper queued (job ${body?.job?.id || "?"})`);
        }
        await pollSnapshot();
    } catch (err) {
        setWorkspaceStatus(`Dig deeper failed: ${err.message}`, true);
    }
}

async function refreshHostScreenshotsAction(hostId) {
    const id = parseInt(hostId, 10);
    if (!id) {
        return;
    }
    try {
        const body = await postJson(`/api/workspace/hosts/${id}/refresh-screenshots`, {});
        const jobId = Number(body?.job?.id || 0);
        if (body?.job?.existing) {
            setWorkspaceStatus(`Screenshot refresh already queued/running (job ${jobId || "?"})`);
            await pollSnapshot();
            return;
        }
        setWorkspaceStatus(`Screenshot refresh queued (job ${jobId || "?"})`);
        await pollSnapshot();
        if (jobId > 0) {
            waitForJobCompletion(jobId, 300000, 1500).then(async (job) => {
                const result = job?.result || {};
                const completed = Number(result.completed || 0);
                const targetCount = Number(result.target_count || 0);
                if (String(workspaceState.selectedHostId || "") === String(id)) {
                    await loadHostDetail(id);
                }
                await pollSnapshot();
                setWorkspaceStatus(
                    targetCount > 0
                        ? `Screenshot refresh completed (${completed}/${targetCount})`
                        : "Screenshot refresh completed",
                );
            }).catch(async (err) => {
                if (String(workspaceState.selectedHostId || "") === String(id)) {
                    await loadHostDetail(id).catch(() => {});
                }
                await pollSnapshot();
                setWorkspaceStatus(`Screenshot refresh failed: ${err.message}`, true);
            });
        }
    } catch (err) {
        setWorkspaceStatus(`Screenshot refresh failed: ${err.message}`, true);
    }
}

async function refreshGraphScreenshotAction(payload) {
    const hostId = parseInt(payload?.hostId, 10);
    const port = String(payload?.port || "").trim();
    const protocol = String(payload?.protocol || "tcp").trim().toLowerCase() || "tcp";
    if (!hostId || !port) {
        return;
    }
    try {
        const body = await postJson("/api/workspace/screenshots/refresh", {
            host_id: hostId,
            port,
            protocol,
        });
        const jobId = Number(body?.job?.id || 0);
        if (body?.job?.existing) {
            setWorkspaceStatus(`Screenshot refresh already queued/running (job ${jobId || "?"})`);
        } else {
            setWorkspaceStatus(`Screenshot refresh queued (job ${jobId || "?"})`);
        }
        await pollSnapshot();
    } catch (err) {
        setWorkspaceStatus(`Screenshot refresh failed: ${err.message}`, true);
    }
}

async function deleteGraphScreenshotAction(payload) {
    const hostId = parseInt(payload?.hostId, 10);
    const port = String(payload?.port || "").trim();
    const protocol = String(payload?.protocol || "tcp").trim().toLowerCase() || "tcp";
    const artifactRef = String(payload?.artifactRef || "").trim();
    const filename = String(payload?.filename || "").trim();
    if (!hostId || (!artifactRef && !filename)) {
        return;
    }
    const targetLabel = filename || artifactRef || "this screenshot";
    if (!window.confirm(`Delete ${targetLabel}?`)) {
        return;
    }
    try {
        await postJson("/api/workspace/screenshots/delete", {
            host_id: hostId,
            port,
            protocol,
            artifact_ref: artifactRef,
            filename,
        });
        setWorkspaceStatus(`Deleted screenshot ${targetLabel}`);
        await pollSnapshot();
    } catch (err) {
        setWorkspaceStatus(`Delete screenshot failed: ${err.message}`, true);
    }
}

async function confirmHostRemoveAction() {
    const hostId = parseInt(hostRemoveState.hostId, 10);
    if (!hostId) {
        closeHostRemoveModalAction(true);
        return;
    }
    try {
        const response = await fetch(`/api/workspace/hosts/${hostId}`, {method: "DELETE"});
        let body = {};
        try {
            body = await response.json();
        } catch (_err) {
        }
        if (!response.ok) {
            const message = body.error || `Request failed (${response.status})`;
            throw new Error(message);
        }
        const removedIp = String(body.host_ip || hostRemoveState.hostIp || "");
        closeHostRemoveModalAction(true);
        if (workspaceState.selectedHostId === hostId) {
            workspaceState.selectedHostId = null;
            workspaceState.hostDetail = null;
            renderHostDetail({host: {}, note: "", ports: [], cves: [], screenshots: []});
        }
        setWorkspaceStatus(`Removed host ${removedIp || hostId}`);
        await Promise.all([refreshWorkspace(), pollSnapshot(), loadApprovals()]);
    } catch (err) {
        setWorkspaceStatus(`Remove host failed: ${err.message}`, true);
    }
}

async function loadProcessOutput(processId, reset = true) {
    const pid = parseInt(processId, 10);
    if (!pid) {
        return;
    }
    if (reset || processOutputState.processId !== pid) {
        processOutputState.processId = pid;
        processOutputState.offset = 0;
        processOutputState.complete = false;
        processOutputState.status = "";
        setProcessOutputText("");
    }

    const query = new URLSearchParams({
        offset: String(processOutputState.offset || 0),
        max_chars: "24000",
    });
    const payload = await fetchJson(`/api/processes/${pid}/output?${query.toString()}`);
    setProcessOutputCommand(payload.command || "");
    const chunk = payload.output_chunk || "";
    const nextOffset = Number(payload.next_offset || 0);
    const current = processOutputState.text || "";
    if (chunk) {
        setProcessOutputText(`${current}${chunk}`);
    } else if (reset && payload.output) {
        setProcessOutputText(payload.output || "");
    }
    processOutputState.offset = nextOffset;
    processOutputState.complete = Boolean(payload.completed);
    processOutputState.status = String(payload.status || "");
    setProcessOutputMeta(
        `Process ${payload.id} | ${payload.status || ""} | bytes ${processOutputState.offset}/${payload.output_length || 0}`
    );
}

async function killProcessAction(processId) {
    try {
        await postJson(`/api/processes/${processId}/kill`, {});
        setWorkspaceStatus(`Process ${processId} kill requested`);
        await pollSnapshot();
        if (processOutputState.modalOpen && parseInt(processOutputState.processId, 10) === parseInt(processId, 10)) {
            await loadProcessOutput(processId, false);
        }
    } catch (err) {
        setWorkspaceStatus(`Kill failed: ${err.message}`, true);
    }
}

async function retryProcessAction(processId) {
    try {
        const body = await postJson(`/api/processes/${processId}/retry`, {});
        setWorkspaceStatus(`Retry queued for process ${processId} (job ${body?.job?.id || "?"})`);
        await pollSnapshot();
    } catch (err) {
        setWorkspaceStatus(`Retry failed: ${err.message}`, true);
    }
}

async function closeProcessAction(processId) {
    try {
        await postJson(`/api/processes/${processId}/close`, {});
        setWorkspaceStatus(`Process ${processId} hidden`);
        await pollSnapshot();
    } catch (err) {
        setWorkspaceStatus(`Hide failed: ${err.message}`, true);
    }
}

async function clearProcessesAction(resetAll) {
    try {
        await postJson("/api/processes/clear", {reset_all: Boolean(resetAll)});
        setWorkspaceStatus(resetAll ? "Hidden all non-running processes" : "Hidden finished/issues processes");
        await pollSnapshot();
    } catch (err) {
        setWorkspaceStatus(`Clear failed: ${err.message}`, true);
    }
}

async function stopJobAction(jobId) {
    const id = Number(jobId);
    if (!Number.isFinite(id) || id <= 0) {
        setWorkspaceStatus("Invalid job id.", true);
        return;
    }
    try {
        const body = await postJson(`/api/jobs/${id}/stop`, {});
        if (body?.stopped) {
            const killedCount = Array.isArray(body?.killed_process_ids) ? body.killed_process_ids.length : 0;
            if (killedCount > 0) {
                setWorkspaceStatus(`Stop requested for job ${id} (terminated ${killedCount} process${killedCount === 1 ? "" : "es"})`);
            } else {
                setWorkspaceStatus(`Stop requested for job ${id}`);
            }
        } else {
            setWorkspaceStatus(`Job ${id} is already finished`);
        }
        await pollSnapshot();
    } catch (err) {
        setWorkspaceStatus(`Stop job failed: ${err.message}`, true);
    }
}

function renderSummary(summary) {
    setText("stat-hosts", summary.hosts);
    setText("stat-open-ports", summary.open_ports);
    setText("stat-services", summary.services);
    setText("stat-cves", summary.cves);
    setText("stat-running", summary.running_processes);
    setText("stat-finished", summary.finished_processes);
}

function renderDecisions(decisions) {
    const body = document.getElementById("decisions-body");
    if (!body) {
        return;
    }
    body.innerHTML = "";
    (decisions || []).forEach((decision) => {
        const tr = document.createElement("tr");
        const target = formatTargetLabel(decision.host_ip, decision.port, decision.protocol);
        tr.appendChild(makeCell(decision.timestamp || ""));
        tr.appendChild(makeCell(target));
        tr.appendChild(makeCell(decision.tool_id || decision.label || ""));
        tr.appendChild(makeCell(decision.scheduler_mode || ""));
        tr.appendChild(makeCell(decision.approved || ""));
        tr.appendChild(makeCell(decision.executed || ""));
        tr.appendChild(makeCell(decision.reason || ""));
        tr.appendChild(makeCell(decision.command_family_id || ""));
        body.appendChild(tr);
    });
    setText("decision-count", (decisions || []).length);
}

function renderApprovals(approvals) {
    const body = document.getElementById("approvals-body");
    if (!body) {
        return;
    }
    body.innerHTML = "";
    (approvals || []).forEach((item) => {
        const tr = document.createElement("tr");
        tr.dataset.approvalId = String(item.id || "");

        const addDetailLine = (container, label, value) => {
            const text = String(value || "").trim();
            if (!text) {
                return;
            }
            const line = document.createElement("div");
            line.textContent = `${label}: ${text}`;
            container.appendChild(line);
        };

        const actionCell = document.createElement("td");
        addDetailLine(actionCell, "tool", item.label || item.tool_id || "");
        addDetailLine(actionCell, "id", item.tool_id || "");
        addDetailLine(actionCell, "command", item.command_template || "");
        addDetailLine(actionCell, "status", item.status || "");

        const riskCell = document.createElement("td");
        addDetailLine(riskCell, "risk tags", item.risk_tags || item.danger_categories || "");
        addDetailLine(riskCell, "decision", item.policy_decision || "");
        addDetailLine(riskCell, "why risky", item.risk_summary || "");
        addDetailLine(riskCell, "policy", item.policy_reason || "");
        addDetailLine(riskCell, "safer alternative", item.safer_alternative || "");
        addDetailLine(riskCell, "family policy", item.family_policy_state || "");

        const rationaleCell = document.createElement("td");
        addDetailLine(rationaleCell, "planner rationale", item.rationale || "");
        addDetailLine(rationaleCell, "evidence", item.evidence_refs || "");

        const actionsCell = document.createElement("td");
        const approveBtn = document.createElement("button");
        approveBtn.type = "button";
        approveBtn.textContent = "Approve+Run";
        approveBtn.dataset.action = "approve";
        approveBtn.dataset.approvalId = String(item.id || "");

        const rejectBtn = document.createElement("button");
        rejectBtn.type = "button";
        rejectBtn.textContent = "Reject";
        rejectBtn.dataset.action = "reject";
        rejectBtn.dataset.approvalId = String(item.id || "");

        const allowFamilyBtn = document.createElement("button");
        allowFamilyBtn.type = "button";
        allowFamilyBtn.textContent = "Allow Family";
        allowFamilyBtn.dataset.action = "allow-family";
        allowFamilyBtn.dataset.approvalId = String(item.id || "");

        const suppressFamilyBtn = document.createElement("button");
        suppressFamilyBtn.type = "button";
        suppressFamilyBtn.textContent = "Suppress Family";
        suppressFamilyBtn.dataset.action = "suppress-family";
        suppressFamilyBtn.dataset.approvalId = String(item.id || "");

        actionsCell.className = "approval-action-buttons";
        actionsCell.appendChild(approveBtn);
        actionsCell.appendChild(rejectBtn);
        actionsCell.appendChild(allowFamilyBtn);
        actionsCell.appendChild(suppressFamilyBtn);

        const target = formatTargetLabel(item.host_ip, item.port, item.protocol);
        tr.appendChild(makeCell(item.id || ""));
        tr.appendChild(makeCell(target));
        tr.appendChild(actionCell);
        tr.appendChild(riskCell);
        tr.appendChild(rationaleCell);
        tr.appendChild(actionsCell);
        body.appendChild(tr);
    });
    setText("approval-count", (approvals || []).length);
}

function renderJobs(jobs) {
    const body = document.getElementById("jobs-body");
    if (!body) {
        return;
    }
    body.innerHTML = "";
    (jobs || []).forEach((job) => {
        const tr = document.createElement("tr");
        tr.appendChild(makeCell(job.id || ""));
        tr.appendChild(makeCell(job.type || ""));
        tr.appendChild(makeCell(job.status || ""));
        tr.appendChild(makeCell(job.created_at || ""));
        tr.appendChild(makeCell(job.started_at || ""));
        tr.appendChild(makeCell(job.finished_at || ""));
        const warnings = Array.isArray(job?.result?.warnings) ? job.result.warnings.filter(Boolean) : [];
        const errorText = String(job?.error || "");
        const diagnostic = errorText || (warnings.length ? warnings.join(" | ") : "");
        tr.appendChild(makeCell(diagnostic));
        const actionsCell = document.createElement("td");
        const status = String(job?.status || "").trim().toLowerCase();
        if (status === "running" || status === "queued") {
            const stopBtn = document.createElement("button");
            stopBtn.type = "button";
            stopBtn.textContent = "Stop";
            stopBtn.dataset.jobAction = "stop";
            stopBtn.dataset.jobId = String(job.id || "");
            actionsCell.appendChild(stopBtn);
        }
        tr.appendChild(actionsCell);
        body.appendChild(tr);
    });
    setText("job-count", (jobs || []).length);
}

function renderScanHistory(scans) {
    const body = document.getElementById("scan-history-body");
    if (!body) {
        return;
    }
    body.innerHTML = "";
    (scans || []).forEach((scan) => {
        const tr = document.createElement("tr");
        tr.appendChild(makeCell(scan.id || ""));
        tr.appendChild(makeCell(scan.submission_kind || ""));
        tr.appendChild(makeCell(scan.status || ""));
        tr.appendChild(makeCell(scan.target_summary || ""));
        tr.appendChild(makeCell(scan.scope_summary || ""));
        tr.appendChild(makeCell(scan.scan_mode || ""));
        tr.appendChild(makeCell(scan.created_at || ""));
        tr.appendChild(makeCell(scan.result_summary || ""));
        body.appendChild(tr);
    });
    setText("scan-history-count", (scans || []).length);
}

function renderHostDetail(payload) {
    workspaceState.hostDetail = payload || null;
    const host = payload?.host || {};
    const ports = payload?.ports || [];
    const cves = payload?.cves || [];
    const screenshots = payload?.screenshots || [];
    const aiAnalysis = payload?.ai_analysis || {};
    const targetState = payload?.target_state || {};
    const aiTechnologies = Array.isArray(aiAnalysis?.technologies) ? aiAnalysis.technologies : [];
    const aiFindings = Array.isArray(aiAnalysis?.findings) ? aiAnalysis.findings : [];
    const aiManualTests = Array.isArray(aiAnalysis?.manual_tests) ? aiAnalysis.manual_tests : [];
    const aiHostUpdates = aiAnalysis?.host_updates || {};
    const stateAttemptedActions = Array.isArray(targetState?.attempted_actions) ? targetState.attempted_actions : [];
    const stateCoverageGaps = Array.isArray(targetState?.coverage_gaps) ? targetState.coverage_gaps : [];
    const stateUrls = Array.isArray(targetState?.urls) ? targetState.urls : [];
    const stateCredentials = Array.isArray(targetState?.credentials) ? targetState.credentials : [];
    const stateSessions = Array.isArray(targetState?.sessions) ? targetState.sessions : [];

    setText("host-detail-name", host.ip ? `${host.ip} (${host.hostname || "no-hostname"})` : "");
    setValue("workspace-note", payload?.note || "");
    setValue("workspace-tool-host-ip", host.ip || "");

    const portsBody = document.getElementById("host-detail-ports");
    if (portsBody) {
        portsBody.innerHTML = "";
        const screenshotsByPort = new Map();
        screenshots.forEach((shot) => {
            const key = String(shot?.port || "");
            if (!key) {
                return;
            }
            if (!screenshotsByPort.has(key)) {
                screenshotsByPort.set(key, []);
            }
            screenshotsByPort.get(key).push(shot);
        });
        ports.forEach((row) => {
            const tr = document.createElement("tr");
            tr.appendChild(makeCell(row.port || ""));
            tr.appendChild(makeCell(row.protocol || ""));
            tr.appendChild(makeCell(row.state || ""));
            tr.appendChild(makeCell(row.service?.name || ""));
            tr.appendChild(makeCell(`${row.service?.product || ""} ${row.service?.version || ""}`.trim()));
            tr.appendChild(makeCell(extractBannerForPort(row)));
            const screenshotCell = document.createElement("td");
            const byPort = screenshotsByPort.get(String(row.port || "")) || [];
            if (byPort.length > 0) {
                const first = byPort[0];
                const shotButton = document.createElement("button");
                shotButton.type = "button";
                shotButton.className = "host-screenshot-trigger";
                shotButton.textContent = String(first.filename || "screenshot.png");
                shotButton.dataset.screenshotUrl = String(first.url || "");
                shotButton.dataset.screenshotName = String(first.filename || "");
                shotButton.dataset.screenshotPort = String(first.port || row.port || "");
                screenshotCell.appendChild(shotButton);
                if (byPort.length > 1) {
                    const extra = document.createElement("span");
                    extra.className = "text-muted";
                    extra.textContent = ` (+${byPort.length - 1})`;
                    screenshotCell.appendChild(extra);
                }
            }
            tr.appendChild(screenshotCell);
            portsBody.appendChild(tr);
        });
    }

    const scriptsBody = document.getElementById("host-detail-scripts");
    if (scriptsBody) {
        scriptsBody.innerHTML = "";
        ports.forEach((portRow) => {
            (portRow.scripts || []).forEach((scriptRow) => {
                const tr = document.createElement("tr");
                tr.appendChild(makeCell(scriptRow.id || ""));
                tr.appendChild(makeCell(scriptRow.script_id || ""));
                tr.appendChild(makeCell(scriptRow.display_output || (scriptRow.output || "").slice(0, 140)));
                const actions = document.createElement("td");
                const view = document.createElement("button");
                view.type = "button";
                view.textContent = "View";
                view.dataset.scriptViewId = String(scriptRow.id || "");
                actions.appendChild(view);
                const del = document.createElement("button");
                del.type = "button";
                del.textContent = "Delete";
                del.dataset.scriptDeleteId = String(scriptRow.id || "");
                actions.appendChild(del);
                tr.appendChild(actions);
                scriptsBody.appendChild(tr);
            });
        });
    }

    const cvesBody = document.getElementById("host-detail-cves");
    if (cvesBody) {
        cvesBody.innerHTML = "";
        cves.forEach((item) => {
            const tr = document.createElement("tr");
            tr.appendChild(makeCell(item.id || ""));
            tr.appendChild(makeCell(item.name || ""));
            tr.appendChild(makeCell(item.severity || ""));
            tr.appendChild(makeCell(item.product || ""));
            tr.appendChild(makeCell(item.url || ""));
            const actions = document.createElement("td");
            const del = document.createElement("button");
            del.type = "button";
            del.textContent = "Delete";
            del.dataset.cveDeleteId = String(item.id || "");
            actions.appendChild(del);
            tr.appendChild(actions);
            cvesBody.appendChild(tr);
        });
    }

    const aiTechBody = document.getElementById("host-detail-ai-technologies");
    if (aiTechBody) {
        aiTechBody.innerHTML = "";
        aiTechnologies.forEach((item) => {
            const tr = document.createElement("tr");
            tr.appendChild(makeCell(item.name || ""));
            tr.appendChild(makeCell(item.version || ""));
            tr.appendChild(makeCell(item.cpe || ""));
            tr.appendChild(makeCell(item.evidence || ""));
            aiTechBody.appendChild(tr);
        });
    }

    const aiFindingsBody = document.getElementById("host-detail-ai-findings");
    if (aiFindingsBody) {
        aiFindingsBody.innerHTML = "";
        aiFindings.forEach((item) => {
            const tr = document.createElement("tr");
            tr.appendChild(makeCell(item.severity || ""));
            tr.appendChild(makeCell(item.title || ""));
            tr.appendChild(makeCell(item.cve || ""));
            tr.appendChild(makeCell(item.cvss ?? ""));
            tr.appendChild(makeCell(item.evidence || ""));
            aiFindingsBody.appendChild(tr);
        });
    }

    const aiManualBody = document.getElementById("host-detail-ai-manual-tests");
    if (aiManualBody) {
        aiManualBody.innerHTML = "";
        aiManualTests.forEach((item) => {
            const tr = document.createElement("tr");
            tr.appendChild(makeCell(item.why || ""));
            tr.appendChild(makeCell(item.command || ""));
            tr.appendChild(makeCell(item.scope_note || ""));
            aiManualBody.appendChild(tr);
        });
    }

    const statusBits = [];
    if (aiAnalysis?.provider) {
        statusBits.push(`provider: ${aiAnalysis.provider}`);
    }
    if (aiAnalysis?.updated_at) {
        statusBits.push(`updated: ${aiAnalysis.updated_at}`);
    }
    if (aiAnalysis?.next_phase) {
        statusBits.push(`next phase: ${aiAnalysis.next_phase}`);
    }
    if (aiHostUpdates?.hostname) {
        statusBits.push(`hostname: ${aiHostUpdates.hostname}`);
    }
    if (aiHostUpdates?.os) {
        statusBits.push(`os: ${aiHostUpdates.os}`);
    }
    if (stateAttemptedActions.length > 0) {
        statusBits.push(`attempted: ${stateAttemptedActions.length}`);
    }
    if (stateCoverageGaps.length > 0) {
        statusBits.push(`coverage gaps: ${stateCoverageGaps.length}`);
    }
    if (stateUrls.length > 0) {
        statusBits.push(`urls: ${stateUrls.length}`);
    }
    if (stateCredentials.length > 0) {
        statusBits.push(`credentials: ${stateCredentials.length}`);
    }
    if (stateSessions.length > 0) {
        statusBits.push(`sessions: ${stateSessions.length}`);
    }
    setText("host-ai-analysis-status", statusBits.join(" | "));
    setText("host-ai-tech-count", aiTechnologies.length);
    setText("host-ai-finding-count", aiFindings.length);
    setText("host-ai-manual-count", aiManualTests.length);

    const shotsNode = document.getElementById("host-detail-screenshots");
    if (shotsNode) {
        shotsNode.innerHTML = "";
        screenshots.forEach((shot) => {
            const a = document.createElement("a");
            a.href = shot.url || "#";
            a.target = "_blank";
            a.rel = "noopener noreferrer";
            a.textContent = `${shot.filename || "screenshot"} ${shot.port ? `(${shot.port})` : ""}`;
            shotsNode.appendChild(a);
        });
    }
    setText("host-screenshot-count", screenshots.length);
}

function applySchedulerPreferences(prefs) {
    if (!prefs) {
        return;
    }
    const featureFlags = normalizeSchedulerFeatureFlags(prefs.feature_flags);
    const policy = normalizeEngagementPolicyPayload(
        prefs.engagement_policy,
        prefs.goal_profile || "internal_asset_discovery",
    );
    setText("scheduler-mode", prefs.mode || "");
    setText("scheduler-goal", policy.preset_label || policy.preset || prefs.goal_profile || "");
    setText("scheduler-families", prefs.preapproved_families_count || 0);

    setValue("scheduler-mode-select", prefs.mode || "deterministic");
    setValue("scheduler-goal-select", policy.preset || "internal_recon");
    setValue("engagement-scope-select", policy.scope || "internal");
    setValue("engagement-intent-select", policy.intent || "recon");
    setChecked("engagement-allow-exploitation", Boolean(policy.allow_exploitation));
    setChecked("engagement-allow-lateral", Boolean(policy.allow_lateral_movement));
    setValue("engagement-credential-mode", policy.credential_attack_mode || "blocked");
    setValue("engagement-lockout-mode", policy.lockout_risk_mode || "blocked");
    setValue("engagement-stability-mode", policy.stability_risk_mode || "approval");
    setValue("engagement-detection-mode", policy.detection_risk_mode || "low");
    setValue("engagement-approval-mode", policy.approval_mode || "risky");
    applySchedulerRolloutFlags(featureFlags, policy.runner_preference || "local");
    setValue("engagement-noise-budget", policy.noise_budget || "low");
    setValue("scheduler-provider-select", prefs.provider || "none");
    setValue("scheduler-concurrency-input", String(prefs.max_concurrency || 1));
    setValue("scheduler-max-jobs-input", String(prefs.max_jobs || 200));

    const providers = prefs.providers || {};
    const lmStudio = providers.lm_studio || {};
    const openai = providers.openai || {};
    const claude = providers.claude || {};
    const projectDelivery = prefs.project_report_delivery || {};
    const projectDeliveryMtls = projectDelivery.mtls || {};

    setValue("provider-lmstudio-baseurl", lmStudio.base_url || "");
    setValue("provider-lmstudio-model", lmStudio.model || "");
    setValue("provider-lmstudio-apikey", "");

    setValue("provider-openai-baseurl", openai.base_url || "");
    setValue("provider-openai-model", openai.model || "");
    setValue("provider-openai-apikey", "");

    setValue("provider-claude-baseurl", claude.base_url || "");
    setValue("provider-claude-model", claude.model || "");
    setValue("provider-claude-apikey", "");

    setValue("project-report-provider-name", projectDelivery.provider_name || "");
    setValue("project-report-endpoint", projectDelivery.endpoint || "");
    setValue("project-report-method", projectDelivery.method || "POST");
    setValue("project-report-format", projectDelivery.format || "json");
    setValue("project-report-timeout", String(projectDelivery.timeout_seconds || 30));
    setChecked("project-report-mtls-enabled", projectDeliveryMtls.enabled);
    setValue("project-report-mtls-cert", projectDeliveryMtls.client_cert_path || "");
    setValue("project-report-mtls-key", projectDeliveryMtls.client_key_path || "");
    setValue("project-report-mtls-ca", projectDeliveryMtls.ca_cert_path || "");
    setValue(
        "project-report-headers",
        JSON.stringify(projectDelivery.headers || {}, null, 2),
    );

    const activeDanger = new Set(prefs.dangerous_categories || []);
    [
        "exploit_execution",
        "credential_bruteforce",
        "network_flooding",
        "destructive_write_actions",
    ].forEach((category) => {
        setChecked(`danger-${category}`, activeDanger.has(category));
    });

    setSchedulerProviderFieldVisibility(prefs.provider || "none");
}

function normalizeSchedulerFeatureFlags(flags) {
    const provided = flags && typeof flags === "object" ? flags : {};
    return {
        graph_workspace: provided.graph_workspace !== false,
        optional_runners: provided.optional_runners !== false,
    };
}

function applySchedulerRolloutFlags(featureFlags, requestedRunnerPreference) {
    const flags = normalizeSchedulerFeatureFlags(featureFlags);
    const select = document.getElementById("engagement-runner-preference");
    const disabledRunnerPreferences = new Set(flags.optional_runners ? [] : ["container", "browser"]);
    if (!select) {
        return;
    }
    Array.from(select.options).forEach((option) => {
        const value = String(option?.value || "").trim().toLowerCase();
        option.disabled = disabledRunnerPreferences.has(value);
        if (option.disabled) {
            option.textContent = `${value} (disabled)`;
        } else {
            option.textContent = value;
        }
    });
    const preferred = String(requestedRunnerPreference || "local").trim().toLowerCase();
    if (disabledRunnerPreferences.has(preferred)) {
        setValue("engagement-runner-preference", "local");
        return;
    }
    setValue("engagement-runner-preference", preferred || "local");
}

function defaultEngagementPolicyForPreset(preset) {
    const normalizedPreset = String(preset || "").trim().toLowerCase();
    const defaults = {
        external_recon: {
            preset: "external_recon",
            preset_label: "External Recon",
            scope: "external",
            intent: "recon",
            allow_exploitation: false,
            allow_lateral_movement: false,
            credential_attack_mode: "blocked",
            lockout_risk_mode: "blocked",
            stability_risk_mode: "approval",
            detection_risk_mode: "low",
            approval_mode: "risky",
            runner_preference: "local",
            noise_budget: "low",
            custom_overrides: {},
            legacy_goal_profile: "external_pentest",
        },
        external_pentest: {
            preset: "external_pentest",
            preset_label: "External Pentest",
            scope: "external",
            intent: "pentest",
            allow_exploitation: true,
            allow_lateral_movement: false,
            credential_attack_mode: "approval",
            lockout_risk_mode: "approval",
            stability_risk_mode: "approval",
            detection_risk_mode: "medium",
            approval_mode: "risky",
            runner_preference: "local",
            noise_budget: "medium",
            custom_overrides: {},
            legacy_goal_profile: "external_pentest",
        },
        internal_recon: {
            preset: "internal_recon",
            preset_label: "Internal Recon",
            scope: "internal",
            intent: "recon",
            allow_exploitation: false,
            allow_lateral_movement: false,
            credential_attack_mode: "blocked",
            lockout_risk_mode: "blocked",
            stability_risk_mode: "approval",
            detection_risk_mode: "low",
            approval_mode: "risky",
            runner_preference: "local",
            noise_budget: "low",
            custom_overrides: {},
            legacy_goal_profile: "internal_asset_discovery",
        },
        internal_pentest: {
            preset: "internal_pentest",
            preset_label: "Internal Pentest",
            scope: "internal",
            intent: "pentest",
            allow_exploitation: true,
            allow_lateral_movement: true,
            credential_attack_mode: "approval",
            lockout_risk_mode: "approval",
            stability_risk_mode: "approval",
            detection_risk_mode: "medium",
            approval_mode: "risky",
            runner_preference: "local",
            noise_budget: "medium",
            custom_overrides: {},
            legacy_goal_profile: "internal_asset_discovery",
        },
    };
    return defaults[normalizedPreset] || {
        ...defaults.internal_recon,
        preset: normalizedPreset || "custom",
        preset_label: normalizedPreset ? normalizedPreset.replace(/_/g, " ") : "Custom",
    };
}

function presetFromLegacyGoalProfile(goalProfile) {
    const normalized = String(goalProfile || "").trim().toLowerCase();
    if (normalized === "external_pentest") {
        return "external_pentest";
    }
    if (normalized === "internal_pentest") {
        return "internal_pentest";
    }
    if (normalized === "external_recon") {
        return "external_recon";
    }
    return "internal_recon";
}

function legacyGoalProfileFromEngagementPolicy(policy) {
    const preset = String(policy?.preset || "").trim().toLowerCase();
    if (preset === "external_recon" || preset === "external_pentest") {
        return "external_pentest";
    }
    return "internal_asset_discovery";
}

function normalizeEngagementPolicyPayload(policy, fallbackGoalProfile) {
    const fallbackPreset = presetFromLegacyGoalProfile(fallbackGoalProfile);
    const provided = policy && typeof policy === "object" ? policy : {};
    const base = defaultEngagementPolicyForPreset(provided.preset || fallbackPreset);
    return {
        ...base,
        ...provided,
        custom_overrides: provided.custom_overrides && typeof provided.custom_overrides === "object"
            ? provided.custom_overrides
            : {},
        legacy_goal_profile: provided.legacy_goal_profile || legacyGoalProfileFromEngagementPolicy({
            ...base,
            ...provided,
        }),
    };
}

function setSchedulerProviderFieldVisibility(providerName) {
    const selectedProvider = String(providerName || "none").trim().toLowerCase();
    const providerFields = document.querySelectorAll(".scheduler-provider-field[data-scheduler-provider]");
    providerFields.forEach((fieldNode) => {
        const fieldProvider = String(fieldNode.getAttribute("data-scheduler-provider") || "").trim().toLowerCase();
        fieldNode.classList.toggle("is-active", fieldProvider === selectedProvider);
    });
}

function collectSchedulerPreferencesFromForm() {
    const mode = getValue("scheduler-mode-select");
    const selectedProvider = getValue("scheduler-provider-select");
    const rawConcurrency = parseInt(getValue("scheduler-concurrency-input"), 10);
    const maxConcurrency = Number.isFinite(rawConcurrency)
        ? Math.max(1, Math.min(16, rawConcurrency))
        : 1;
    const rawMaxJobs = parseInt(getValue("scheduler-max-jobs-input"), 10);
    const maxJobs = Number.isFinite(rawMaxJobs)
        ? Math.max(20, Math.min(2000, rawMaxJobs))
        : 200;
    const dangerousCategories = [
        "exploit_execution",
        "credential_bruteforce",
        "network_flooding",
        "destructive_write_actions",
    ].filter((category) => getChecked(`danger-${category}`));

    const providers = {
        lm_studio: {
            enabled: selectedProvider === "lm_studio",
            base_url: getValue("provider-lmstudio-baseurl"),
            model: getValue("provider-lmstudio-model"),
        },
        openai: {
            enabled: selectedProvider === "openai",
            base_url: getValue("provider-openai-baseurl"),
            model: getValue("provider-openai-model"),
        },
        claude: {
            enabled: selectedProvider === "claude",
            base_url: getValue("provider-claude-baseurl"),
            model: getValue("provider-claude-model"),
        },
    };

    if (selectedProvider === "lm_studio") {
        providers.lm_studio.base_url = providers.lm_studio.base_url || "http://127.0.0.1:1234/v1";
        providers.lm_studio.model = providers.lm_studio.model || "o3-7b";
    } else if (selectedProvider === "openai") {
        providers.openai.base_url = providers.openai.base_url || "https://api.openai.com/v1";
        providers.openai.model = providers.openai.model || "gpt-4.1-mini";
    }

    const lmApiKey = getValue("provider-lmstudio-apikey").trim();
    const openaiApiKey = getValue("provider-openai-apikey").trim();
    const claudeApiKey = getValue("provider-claude-apikey").trim();
    if (lmApiKey) {
        providers.lm_studio.api_key = lmApiKey;
    }
    if (openaiApiKey) {
        providers.openai.api_key = openaiApiKey;
    }
    if (claudeApiKey) {
        providers.claude.api_key = claudeApiKey;
    }

    const engagementPolicy = normalizeEngagementPolicyPayload(
        {
            preset: getValue("scheduler-goal-select"),
            scope: getValue("engagement-scope-select"),
            intent: getValue("engagement-intent-select"),
            allow_exploitation: getChecked("engagement-allow-exploitation"),
            allow_lateral_movement: getChecked("engagement-allow-lateral"),
            credential_attack_mode: getValue("engagement-credential-mode"),
            lockout_risk_mode: getValue("engagement-lockout-mode"),
            stability_risk_mode: getValue("engagement-stability-mode"),
            detection_risk_mode: getValue("engagement-detection-mode"),
            approval_mode: getValue("engagement-approval-mode"),
            runner_preference: getValue("engagement-runner-preference"),
            noise_budget: getValue("engagement-noise-budget"),
            custom_overrides: {},
        },
        getValue("scheduler-goal-select"),
    );

    return {
        mode,
        goal_profile: legacyGoalProfileFromEngagementPolicy(engagementPolicy),
        engagement_policy: engagementPolicy,
        provider: selectedProvider,
        max_concurrency: maxConcurrency,
        max_jobs: maxJobs,
        dangerous_categories: dangerousCategories,
        providers,
    };
}

function collectProjectReportDeliveryFromForm() {
    const projectReportMethod = String(getValue("project-report-method") || "POST").toUpperCase();
    const projectReportFormatRaw = String(getValue("project-report-format") || "json").toLowerCase();
    const projectReportFormat = projectReportFormatRaw === "md" ? "md" : "json";
    const rawProjectReportTimeout = parseInt(getValue("project-report-timeout"), 10);
    const projectReportTimeout = Number.isFinite(rawProjectReportTimeout)
        ? Math.max(5, Math.min(300, rawProjectReportTimeout))
        : 30;
    let projectReportHeaders = {};
    const projectReportHeadersText = String(getValue("project-report-headers") || "").trim();
    if (projectReportHeadersText) {
        let parsedHeaders;
        try {
            parsedHeaders = JSON.parse(projectReportHeadersText);
        } catch (_err) {
            throw new Error("Project report headers must be valid JSON.");
        }
        if (typeof parsedHeaders !== "object" || parsedHeaders === null || Array.isArray(parsedHeaders)) {
            throw new Error("Project report headers must be a JSON object.");
        }
        projectReportHeaders = Object.fromEntries(
            Object.entries(parsedHeaders)
                .map(([key, value]) => [String(key || "").trim(), String(value ?? "")])
                .filter(([key]) => key.length > 0)
        );
    }

    return {
        provider_name: getValue("project-report-provider-name"),
        endpoint: getValue("project-report-endpoint"),
        method: ["POST", "PUT", "PATCH"].includes(projectReportMethod) ? projectReportMethod : "POST",
        format: projectReportFormat,
        headers: projectReportHeaders,
        timeout_seconds: projectReportTimeout,
        mtls: {
            enabled: getChecked("project-report-mtls-enabled"),
            client_cert_path: getValue("project-report-mtls-cert"),
            client_key_path: getValue("project-report-mtls-key"),
            ca_cert_path: getValue("project-report-mtls-ca"),
        },
    };
}

async function postJson(url, payload) {
    const response = await fetch(url, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(payload || {}),
    });
    let body = {};
    try {
        body = await response.json();
    } catch (_err) {
    }
    if (!response.ok) {
        const message = body.error || `Request failed (${response.status})`;
        throw new Error(message);
    }
    return body;
}

async function fetchJson(url) {
    const response = await fetch(url);
    if (!response.ok) {
        throw new Error(`Request failed (${response.status})`);
    }
    return response.json();
}

function graphWorkspaceEnabled() {
    return Boolean(document.getElementById("graph-workspace-canvas"));
}

function getGraphWorkspacePanel() {
    const canvas = document.getElementById("graph-workspace-canvas");
    return canvas ? canvas.closest(".graph-panel") : null;
}

function getGraphWorkspaceShell() {
    return document.getElementById("graph-workspace-shell");
}

function getGraphWorkspaceSection() {
    const shell = getGraphWorkspaceShell();
    return shell ? shell.closest(".graph-panel") : null;
}

function getGraphCanvasPanel() {
    return document.querySelector(".graph-canvas-panel");
}

function getGraphCanvasScrollNode() {
    return document.querySelector(".graph-canvas-scroll");
}

function graphHasActiveSelection() {
    return Boolean(graphWorkspaceState.selectedKind && graphWorkspaceState.selectedRef);
}

function graphSelectedNodeEntity({allowRetainedSummary = true} = {}) {
    if (graphWorkspaceState.selectedKind !== "node" || !graphWorkspaceState.selectedRef) {
        return null;
    }
    const liveEntity = graphFindEntity("node", graphWorkspaceState.selectedRef);
    if (liveEntity) {
        return liveEntity;
    }
    if (!allowRetainedSummary) {
        return null;
    }
    const retained = graphWorkspaceState.selectedPayload;
    const selectedRef = String(graphWorkspaceState.selectedRef || "");
    const retainedId = String(retained?.node_id || "");
    if (!retained || retainedId !== selectedRef) {
        return null;
    }
    if (!graphPropertyValue(retained, "summary_kind")) {
        return null;
    }
    if (!graphWorkspaceState.expandedSummaryIds[retainedId]) {
        return null;
    }
    return retained;
}

function normalizeGraphWorkspaceHeight(value) {
    const parsed = Number.parseInt(String(value || ""), 10);
    if (!Number.isFinite(parsed)) {
        return GRAPH_WORKSPACE_DEFAULT_HEIGHT;
    }
    return Math.max(GRAPH_WORKSPACE_MIN_HEIGHT, Math.min(GRAPH_WORKSPACE_MAX_HEIGHT, parsed));
}

function applyGraphWorkspaceHeight(height, {persist = true} = {}) {
    const panel = getGraphWorkspacePanel();
    if (!panel) {
        return;
    }
    const normalized = normalizeGraphWorkspaceHeight(height);
    panel.style.setProperty("--graph-workspace-height", `${normalized}px`);
    if (persist) {
        try {
            window.localStorage.setItem(GRAPH_WORKSPACE_HEIGHT_STORAGE_KEY, String(normalized));
        } catch (_err) {
            // ignore storage failures
        }
    }
    graphSyncDetailPresentation();
}

function restoreGraphWorkspaceHeight() {
    try {
        const stored = window.localStorage.getItem(GRAPH_WORKSPACE_HEIGHT_STORAGE_KEY);
        if (stored) {
            applyGraphWorkspaceHeight(stored, {persist: false});
            return;
        }
    } catch (_err) {
        // ignore storage failures
    }
    applyGraphWorkspaceHeight(GRAPH_WORKSPACE_DEFAULT_HEIGHT, {persist: false});
}

function stopGraphWorkspaceResize() {
    if (!graphWorkspaceResizeState) {
        return;
    }
    const handle = graphWorkspaceResizeState.handle;
    const pointerId = graphWorkspaceResizeState.pointerId;
    document.body.classList.remove("graph-workspace-resizing");
    window.removeEventListener("pointermove", handleGraphWorkspaceResizeMove);
    window.removeEventListener("pointerup", stopGraphWorkspaceResize);
    window.removeEventListener("pointercancel", stopGraphWorkspaceResize);
    window.removeEventListener("blur", stopGraphWorkspaceResize);
    if (handle && typeof handle.releasePointerCapture === "function" && pointerId !== null && pointerId !== undefined) {
        try {
            if (handle.hasPointerCapture && handle.hasPointerCapture(pointerId)) {
                handle.releasePointerCapture(pointerId);
            }
        } catch (_err) {
            // ignore release failures
        }
    }
    applyGraphWorkspaceHeight(graphWorkspaceResizeState.currentHeight || graphWorkspaceResizeState.startHeight);
    graphWorkspaceResizeState = null;
}

function handleGraphWorkspaceResizeMove(event) {
    if (!graphWorkspaceResizeState) {
        return;
    }
    const delta = Number(event.clientY || 0) - graphWorkspaceResizeState.startY;
    const nextHeight = graphWorkspaceResizeState.startHeight + delta;
    graphWorkspaceResizeState.currentHeight = normalizeGraphWorkspaceHeight(nextHeight);
    applyGraphWorkspaceHeight(graphWorkspaceResizeState.currentHeight, {persist: false});
}

function startGraphWorkspaceResize(event) {
    if (!graphWorkspaceEnabled()) {
        return;
    }
    const scrollNode = document.querySelector(".graph-canvas-scroll");
    if (!scrollNode) {
        return;
    }
    event.preventDefault();
    const handle = event.currentTarget || document.getElementById("graph-resize-handle");
    const pointerId = event.pointerId;
    graphWorkspaceResizeState = {
        startY: Number(event.clientY || 0),
        startHeight: Math.max(
            GRAPH_WORKSPACE_MIN_HEIGHT,
            Math.round(scrollNode.getBoundingClientRect().height || GRAPH_WORKSPACE_DEFAULT_HEIGHT),
        ),
        currentHeight: 0,
        handle,
        pointerId,
    };
    if (handle && typeof handle.setPointerCapture === "function" && pointerId !== null && pointerId !== undefined) {
        try {
            handle.setPointerCapture(pointerId);
        } catch (_err) {
            // ignore capture failures
        }
    }
    document.body.classList.add("graph-workspace-resizing");
    window.addEventListener("pointermove", handleGraphWorkspaceResizeMove);
    window.addEventListener("pointerup", stopGraphWorkspaceResize);
    window.addEventListener("pointercancel", stopGraphWorkspaceResize);
    window.addEventListener("blur", stopGraphWorkspaceResize);
}

function resetGraphWorkspaceHeight() {
    applyGraphWorkspaceHeight(GRAPH_WORKSPACE_DEFAULT_HEIGHT);
}

function setGraphStatus(text, isError = false) {
    const node = document.getElementById("graph-workspace-status");
    if (!node) {
        return;
    }
    node.textContent = text || "";
    node.style.color = isError ? "#ff9b9b" : "";
}

function graphFriendlyLabel(value) {
    return String(value || "")
        .replace(/_/g, " ")
        .replace(/\s+/g, " ")
        .trim();
}

function graphSubnetForIp(ip) {
    const token = String(ip || "").trim();
    const match = token.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}$/);
    if (!match) {
        return token || "other";
    }
    return `${match[1]}.${match[2]}.${match[3]}.0/24`;
}

function graphHashToken(value) {
    const input = String(value || "");
    let hash = 5381;
    for (let index = 0; index < input.length; index += 1) {
        hash = ((hash << 5) + hash) + input.charCodeAt(index);
        hash &= 0x7fffffff;
    }
    return Math.abs(hash).toString(36);
}

function graphHostnameSuffix(hostname) {
    const parts = String(hostname || "").trim().toLowerCase().split(".").filter(Boolean);
    if (parts.length <= 2) {
        return parts.join(".") || "";
    }
    const tld = parts.slice(-2).join(".");
    if (["co.uk", "com.au", "co.jp"].includes(tld) && parts.length >= 3) {
        return parts.slice(-3).join(".");
    }
    return parts.slice(-2).join(".");
}

function graphUrlHost(value) {
    const raw = String(value || "").trim();
    if (!raw) {
        return "";
    }
    try {
        return new URL(raw).host || "";
    } catch (err) {
        const match = raw.match(/^[a-z]+:\/\/([^/?#]+)/i);
        return match ? String(match[1] || "").trim() : "";
    }
}

function graphPropertyValue(entity, key) {
    if (!entity || typeof entity !== "object") {
        return "";
    }
    const props = entity.properties && typeof entity.properties === "object" ? entity.properties : {};
    return props[key];
}

function graphPackValues(entity) {
    const props = entity?.properties && typeof entity.properties === "object" ? entity.properties : {};
    const packs = [];
    ["pack_id", "pack", "strategy_pack"].forEach((key) => {
        const token = String(props[key] || "").trim();
        if (token) {
            packs.push(token);
        }
    });
    const tagValues = Array.isArray(props.pack_tags) ? props.pack_tags : [];
    tagValues.forEach((tag) => {
        const token = String(tag || "").trim();
        if (token) {
            packs.push(token);
        }
    });
    return Array.from(new Set(packs));
}

function graphTimestampValue(entity) {
    const lastSeen = String(entity?.last_seen || "").trim();
    const firstSeen = String(entity?.first_seen || "").trim();
    return lastSeen || firstSeen || "";
}

function graphTimeWindowCutoff(windowId) {
    const normalized = String(windowId || "all").trim().toLowerCase();
    const hoursByWindow = {
        "24h": 24,
        "7d": 24 * 7,
        "30d": 24 * 30,
        "90d": 24 * 90,
    };
    const hours = hoursByWindow[normalized];
    if (!hours) {
        return 0;
    }
    return Date.now() - (hours * 60 * 60 * 1000);
}

function graphEntityMatchesTimeWindow(entity, cutoffMs) {
    if (!cutoffMs) {
        return true;
    }
    const timestamp = Date.parse(graphTimestampValue(entity));
    if (!Number.isFinite(timestamp)) {
        return true;
    }
    return timestamp >= cutoffMs;
}

function graphEntityMatchesSeverity(entity, severity) {
    const normalized = String(severity || "").trim().toLowerCase();
    if (!normalized) {
        return true;
    }
    return String(graphPropertyValue(entity, "severity") || "").trim().toLowerCase() === normalized;
}

function graphEntityMatchesPack(entity, pack) {
    const normalized = String(pack || "").trim().toLowerCase();
    if (!normalized) {
        return true;
    }
    return graphPackValues(entity).some((value) => String(value || "").trim().toLowerCase() === normalized);
}

function graphUpdateConfidenceLabel() {
    const value = getValue("graph-min-confidence") || "0";
    setText("graph-min-confidence-value", value);
}

function graphUpdateZoomLabel() {
    const value = Math.max(10, Math.min(200, parseInt(getValue("graph-zoom-slider"), 10) || graphWorkspaceState.zoomPercent || 70));
    graphWorkspaceState.zoomPercent = value;
    setText("graph-zoom-value", `${value}%`);
}

function graphCurrentViewConfig() {
    const viewId = String(getValue("graph-view-select") || graphWorkspaceState.viewId || "attack_surface").trim();
    return GRAPH_VIEW_PRESETS[viewId] || GRAPH_VIEW_PRESETS.attack_surface;
}

function graphUpdateSelectOptions(selectOrId, values, defaultLabel) {
    const node = typeof selectOrId === "string" ? document.getElementById(selectOrId) : selectOrId;
    if (!node) {
        return;
    }
    const previous = String(node.value || "");
    const optionValues = Array.from(new Set((values || []).map((value) => String(value || "").trim()).filter(Boolean))).sort();
    node.innerHTML = "";
    const defaultOption = document.createElement("option");
    defaultOption.value = "";
    defaultOption.textContent = defaultLabel;
    node.appendChild(defaultOption);
    optionValues.forEach((value) => {
        const option = document.createElement("option");
        option.value = value;
        option.textContent = graphFriendlyLabel(value);
        node.appendChild(option);
    });
    if (optionValues.includes(previous)) {
        node.value = previous;
    }
}

function graphRenderLayoutOptions() {
    const select = document.getElementById("graph-layout-select");
    if (!select) {
        return;
    }
    const currentViewId = String(getValue("graph-view-select") || graphWorkspaceState.viewId || "attack_surface").trim();
    const currentValue = String(graphWorkspaceState.activeLayoutId || select.value || "");
    const layouts = (graphWorkspaceState.layouts || []).filter((item) => String(item?.view_id || "").trim() === currentViewId);
    select.innerHTML = "";
    const defaultOption = document.createElement("option");
    defaultOption.value = "";
    defaultOption.textContent = "auto layout";
    select.appendChild(defaultOption);
    layouts.forEach((layout) => {
        const option = document.createElement("option");
        option.value = String(layout.layout_id || "");
        option.textContent = `${layout.name || "layout"}${layout.updated_at ? ` (${layout.updated_at})` : ""}`;
        select.appendChild(option);
    });
    if (layouts.some((layout) => String(layout.layout_id || "") === currentValue)) {
        select.value = currentValue;
    } else {
        select.value = "";
    }
}

function graphUpdateHostFilterOptions() {
    const select = document.getElementById("graph-host-filter");
    if (!select) {
        return;
    }
    const previous = String(select.value || "");
    select.innerHTML = "";
    const defaultOption = document.createElement("option");
    defaultOption.value = "";
    defaultOption.textContent = "all hosts";
    select.appendChild(defaultOption);
    (workspaceState.hosts || []).forEach((host) => {
        const option = document.createElement("option");
        option.value = String(host.id || "");
        option.textContent = `${host.ip || ""}${host.hostname ? ` (${host.hostname})` : ""}`;
        select.appendChild(option);
    });
    if ((workspaceState.hosts || []).some((host) => String(host.id || "") === previous)) {
        select.value = previous;
    }
}

function graphPopulateDynamicFilters() {
    const snapshot = graphWorkspaceState.data || {};
    const nodes = Array.isArray(snapshot.nodes) ? snapshot.nodes : [];
    const edges = Array.isArray(snapshot.edges) ? snapshot.edges : [];
    graphUpdateSelectOptions(
        "graph-node-type-filter",
        nodes.map((item) => String(item?.type || "").trim().toLowerCase()),
        "all node types",
    );
    graphUpdateSelectOptions(
        "graph-edge-type-filter",
        edges.map((item) => String(item?.type || "").trim().toLowerCase()),
        "all edge types",
    );
    graphUpdateSelectOptions(
        "graph-source-kind-filter",
        nodes.concat(edges).map((item) => String(item?.source_kind || "").trim().toLowerCase()),
        "all provenance",
    );
    graphUpdateSelectOptions(
        "graph-severity-filter",
        nodes.concat(edges).map((item) => String(graphPropertyValue(item, "severity") || "").trim().toLowerCase()),
        "all severities",
    );
    graphUpdateSelectOptions(
        "graph-pack-filter",
        nodes.concat(edges).flatMap((item) => graphPackValues(item).map((value) => String(value || "").trim().toLowerCase())),
        "all packs",
    );
}

function graphCollectServerQuery() {
    graphWorkspaceState.viewId = String(getValue("graph-view-select") || graphWorkspaceState.viewId || "attack_surface").trim();
    graphWorkspaceState.groupBy = String(getValue("graph-group-select") || graphWorkspaceState.groupBy || graphCurrentViewConfig().defaultGroup || "subnet").trim();
    graphWorkspaceState.renderMode = String(getValue("graph-render-mode-select") || graphWorkspaceState.renderMode || "auto").trim().toLowerCase();
    graphWorkspaceState.focusDepth = Math.max(1, Math.min(3, parseInt(getValue("graph-focus-depth-select"), 10) || graphWorkspaceState.focusDepth || 1));
    const hostId = parseInt(getValue("graph-host-filter"), 10);
    const minConfidence = Math.max(0, Math.min(100, parseInt(getValue("graph-min-confidence"), 10) || 0));
    return {
        viewId: graphWorkspaceState.viewId,
        groupBy: graphWorkspaceState.groupBy,
        renderMode: graphWorkspaceState.renderMode,
        focusDepth: graphWorkspaceState.focusDepth,
        hostId: Number.isFinite(hostId) && hostId > 0 ? hostId : 0,
        hostFilter: String(workspaceState.hostFilter || "hide_down").trim().toLowerCase() === "show_all"
            ? "show_all"
            : "hide_down",
        nodeType: String(getValue("graph-node-type-filter") || "").trim().toLowerCase(),
        edgeType: String(getValue("graph-edge-type-filter") || "").trim().toLowerCase(),
        sourceKind: String(getValue("graph-source-kind-filter") || "").trim().toLowerCase(),
        severity: String(getValue("graph-severity-filter") || "").trim().toLowerCase(),
        pack: String(getValue("graph-pack-filter") || "").trim().toLowerCase(),
        timeWindow: String(getValue("graph-time-window-filter") || "all").trim().toLowerCase(),
        search: String(getValue("graph-search-input") || "").trim(),
        minConfidence,
        hideAiSuggested: getChecked("graph-hide-ai-suggested"),
        hideNmapXmlArtifacts: getChecked("graph-hide-nmap-xml-artifacts"),
    };
}

function graphBuildHostMaps(nodes) {
    const hostById = new Map();
    const hostLabelById = new Map();
    const subnetByHostId = new Map();
    const domainByHostId = new Map();
    (nodes || []).forEach((node) => {
        const hostId = parseInt(graphPropertyValue(node, "host_id"), 10);
        if (!Number.isFinite(hostId) || hostId <= 0) {
            return;
        }
        if (String(node.type || "") === "host") {
            hostById.set(hostId, node);
            hostLabelById.set(hostId, String(node.label || graphPropertyValue(node, "ip") || `host-${hostId}`));
            const hostname = String(graphPropertyValue(node, "hostname") || "").trim();
            if (hostname) {
                domainByHostId.set(hostId, hostname);
            }
            const ip = String(graphPropertyValue(node, "ip") || "").trim();
            if (ip) {
                subnetByHostId.set(hostId, graphSubnetForIp(ip));
            }
        }
    });
    return {
        hostById,
        hostLabelById,
        subnetByHostId,
        domainByHostId,
    };
}

function graphGroupKeyForNode(node, groupBy, hostMaps) {
    const summaryGroupKey = String(graphPropertyValue(node, "summary_group_key") || "").trim();
    if (summaryGroupKey) {
        return summaryGroupKey;
    }
    const type = String(node?.type || "").trim().toLowerCase();
    const hostId = parseInt(graphPropertyValue(node, "host_id"), 10);
    const hostname = String(graphPropertyValue(node, "hostname") || "").trim();
    const serviceName = String(
        graphPropertyValue(node, "service")
        || graphPropertyValue(node, "name")
        || graphPropertyValue(node, "product")
        || ""
    ).trim();
    if (groupBy === "host") {
        if (type === "host") {
            return String(node.label || "host");
        }
        return hostMaps.hostLabelById.get(hostId) || "unassigned host";
    }
    if (groupBy === "domain") {
        if (type === "fqdn") {
            return String(node.label || "domain");
        }
        return hostname || hostMaps.domainByHostId.get(hostId) || "undisclosed domain";
    }
    if (groupBy === "service") {
        if (type === "service") {
            return serviceName || String(node.label || "service");
        }
        if (type === "port") {
            return `${graphPropertyValue(node, "port") || ""}/${graphPropertyValue(node, "protocol") || ""}`.replace(/\/$/, "") || "port";
        }
        return serviceName || graphFriendlyLabel(type) || "other service";
    }
    if (groupBy === "finding") {
        if (type === "finding") {
            return String(graphPropertyValue(node, "title") || node.label || "finding");
        }
        return String(graphPropertyValue(node, "cve") || graphPropertyValue(node, "title") || graphPropertyValue(node, "severity") || graphFriendlyLabel(type) || "other");
    }
    if (type === "subnet") {
        return String(node.label || "subnet");
    }
    const ip = String(graphPropertyValue(node, "ip") || "").trim();
    if (ip) {
        return graphSubnetForIp(ip);
    }
    return hostMaps.subnetByHostId.get(hostId) || "other subnet";
}

function graphSortNodes(left, right) {
    const leftType = String(left?.type || "").trim().toLowerCase();
    const rightType = String(right?.type || "").trim().toLowerCase();
    const leftIndex = GRAPH_TYPE_ORDER.indexOf(leftType);
    const rightIndex = GRAPH_TYPE_ORDER.indexOf(rightType);
    if (leftIndex !== rightIndex) {
        return (leftIndex === -1 ? GRAPH_TYPE_ORDER.length : leftIndex) - (rightIndex === -1 ? GRAPH_TYPE_ORDER.length : rightIndex);
    }
    return String(left?.label || "").localeCompare(String(right?.label || ""));
}

function graphSeverityRank(entity) {
    const severity = String(graphPropertyValue(entity, "severity") || "").trim().toLowerCase();
    if (!severity) {
        return 99;
    }
    return Object.prototype.hasOwnProperty.call(GRAPH_SEVERITY_ORDER, severity)
        ? GRAPH_SEVERITY_ORDER[severity]
        : 80;
}

function graphGroupTypePriority(nodeType, groupBy) {
    const type = String(nodeType || "").trim().toLowerCase();
    if (groupBy === "finding") {
        if (type === "finding") {
            return 0;
        }
        if (type === "cve" || type === "exploit_reference") {
            return 1;
        }
        if (["credential", "identity", "session"].includes(type)) {
            return 2;
        }
        if (["service", "url"].includes(type)) {
            return 3;
        }
        if (type === "technology" || type === "cpe") {
            return 4;
        }
        if (type === "screenshot") {
            return 5;
        }
        if (["host", "fqdn", "port", "subnet", "scope"].includes(type)) {
            return 6;
        }
        return 7;
    }
    if (groupBy === "service") {
        if (["service", "url"].includes(type)) {
            return 0;
        }
        if (type === "technology" || type === "cpe") {
            return 1;
        }
        if (["finding", "cve", "exploit_reference"].includes(type)) {
            return 2;
        }
        if (type === "screenshot") {
            return 3;
        }
        if (["host", "fqdn", "port"].includes(type)) {
            return 4;
        }
        return 5;
    }
    if (groupBy === "host" || groupBy === "domain" || groupBy === "subnet") {
        if (["host", "fqdn", "subnet", "scope"].includes(type)) {
            return 0;
        }
        if (["service", "url", "port"].includes(type)) {
            return 1;
        }
        if (["finding", "cve", "exploit_reference"].includes(type)) {
            return 2;
        }
        if (["credential", "identity", "session"].includes(type)) {
            return 3;
        }
        if (type === "screenshot") {
            return 4;
        }
        return 5;
    }
    return 9;
}

function graphNaturalCompare(left, right) {
    return String(left || "").localeCompare(String(right || ""), undefined, {
        numeric: true,
        sensitivity: "base",
    });
}

function graphSortGroups(groupsMap, groupBy) {
    return Array.from(groupsMap.entries()).sort((left, right) => {
        const [leftKey, leftNodes] = left;
        const [rightKey, rightNodes] = right;
        const leftPriority = Math.min(...leftNodes.map((item) => graphGroupTypePriority(item?.type, groupBy)), 9);
        const rightPriority = Math.min(...rightNodes.map((item) => graphGroupTypePriority(item?.type, groupBy)), 9);
        if (leftPriority !== rightPriority) {
            return leftPriority - rightPriority;
        }
        const leftSeverity = Math.min(...leftNodes.map((item) => graphSeverityRank(item)), 99);
        const rightSeverity = Math.min(...rightNodes.map((item) => graphSeverityRank(item)), 99);
        if (leftSeverity !== rightSeverity) {
            return leftSeverity - rightSeverity;
        }
        const leftFindings = leftNodes.filter((item) => ["finding", "cve", "exploit_reference"].includes(String(item?.type || "").trim().toLowerCase())).length;
        const rightFindings = rightNodes.filter((item) => ["finding", "cve", "exploit_reference"].includes(String(item?.type || "").trim().toLowerCase())).length;
        if (leftFindings !== rightFindings) {
            return rightFindings - leftFindings;
        }
        return graphNaturalCompare(leftKey, rightKey);
    });
}

function graphBuildNeighborMaps(edges) {
    const neighborMap = new Map();
    const degreeMap = new Map();
    (edges || []).forEach((edge) => {
        const fromId = String(edge?.from_node_id || "");
        const toId = String(edge?.to_node_id || "");
        if (!fromId || !toId) {
            return;
        }
        if (!neighborMap.has(fromId)) {
            neighborMap.set(fromId, new Set());
        }
        if (!neighborMap.has(toId)) {
            neighborMap.set(toId, new Set());
        }
        neighborMap.get(fromId).add(toId);
        neighborMap.get(toId).add(fromId);
    });
    neighborMap.forEach((neighbors, nodeId) => {
        degreeMap.set(String(nodeId || ""), neighbors.size);
    });
    return {neighborMap, degreeMap};
}

function graphEstimateGroupGrid(nodeCount, totalNodes) {
    const count = Math.max(1, Number(nodeCount || 0));
    if (count <= 4) {
        return {columns: 1, rows: count};
    }
    const denseGraph = totalNodes >= 5000;
    const veryLargeGroup = count >= 240;
    const denseFactor = denseGraph ? 0.62 : totalNodes >= 2500 ? 0.56 : 0.48;
    const maxRows = denseGraph ? 24 : totalNodes >= 2500 ? 20 : veryLargeGroup ? 18 : 14;
    const minRows = count >= 80 ? 7 : count >= 20 ? 4 : 2;
    let columns = Math.max(1, Math.ceil(Math.sqrt(count * denseFactor)));
    let rows = Math.max(1, Math.ceil(count / columns));
    if (rows > maxRows) {
        rows = maxRows;
        columns = Math.max(1, Math.ceil(count / rows));
    } else if (rows < minRows && count > minRows) {
        rows = minRows;
        columns = Math.max(1, Math.ceil(count / rows));
    }
    return {columns, rows};
}

function graphViewLanePriority(nodeType, viewId, groupBy) {
    const type = String(nodeType || "").trim().toLowerCase();
    const view = String(viewId || graphWorkspaceState.viewId || "attack_surface").trim().toLowerCase();
    if (view === "attack_surface") {
        if (type === "scope" || type === "subnet") {
            return 0;
        }
        if (type === "host" || type === "fqdn") {
            return 1;
        }
        if (type === "port" || type === "service") {
            return 2;
        }
        if (type === "url" || type === "screenshot") {
            return 3;
        }
        if (type === "technology" || type === "cpe") {
            return 4;
        }
        if (type === "finding" || type === "cve" || type === "exploit_reference") {
            return 5;
        }
        if (["credential", "identity", "session", "action", "artifact", "evidence_record"].includes(type)) {
            return 6;
        }
        return 7;
    }
    if (view === "host_service_topology") {
        if (type === "host" || type === "fqdn" || type === "subnet") {
            return 0;
        }
        if (type === "port" || type === "service") {
            return 1;
        }
        if (type === "url" || type === "screenshot") {
            return 2;
        }
        if (type === "technology" || type === "cpe") {
            return 3;
        }
        if (type === "finding" || type === "cve" || type === "exploit_reference") {
            return 4;
        }
        return 5;
    }
    if (view === "web_application_map") {
        if (type === "host" || type === "fqdn" || type === "service") {
            return 0;
        }
        if (type === "url" || type === "screenshot") {
            return 1;
        }
        if (type === "technology" || type === "cpe") {
            return 2;
        }
        if (type === "finding" || type === "cve" || type === "exploit_reference") {
            return 3;
        }
        return 4;
    }
    if (view === "credential_identity_session") {
        if (type === "host") {
            return 0;
        }
        if (type === "credential" || type === "identity" || type === "session") {
            return 1;
        }
        if (type === "action" || type === "artifact" || type === "evidence_record") {
            return 2;
        }
        return 3;
    }
    if (view === "exploitation_chain") {
        if (type === "host") {
            return 0;
        }
        if (type === "finding" || type === "cve" || type === "exploit_reference") {
            return 1;
        }
        if (type === "credential" || type === "identity" || type === "session") {
            return 2;
        }
        if (type === "action" || type === "artifact" || type === "screenshot" || type === "evidence_record") {
            return 3;
        }
        return 4;
    }
    return graphGroupTypePriority(type, groupBy);
}

function graphEstimateLayoutTargetHeight(totalArea, totalNodes, laneCount) {
    const base = Math.sqrt(Math.max(totalArea, 1)) * (totalNodes >= 5000 ? 1.08 : 1.16);
    return Math.max(1100, Math.min(totalNodes >= 5000 ? 5600 : 4200, Math.round(base + (laneCount * 120))));
}

function graphPackGroupsIntoLanes(groupInfos, targetHeight, groupGapX, groupGapY, outerPad) {
    const lanes = new Map();
    groupInfos.forEach((group) => {
        const laneKey = Number(group?.lane ?? 0);
        if (!lanes.has(laneKey)) {
            lanes.set(laneKey, []);
        }
        lanes.get(laneKey).push(group);
    });

    const orderedLanes = Array.from(lanes.entries()).sort((left, right) => Number(left[0]) - Number(right[0]));
    let globalX = outerPad;
    let maxHeight = 0;

    orderedLanes.forEach(([, laneGroups]) => {
        let localX = 0;
        let localY = outerPad;
        let currentColumnWidth = 0;
        let laneWidth = 0;
        let laneHeight = 0;
        laneGroups.forEach((group) => {
            if (localY > outerPad && (localY + group.height) > targetHeight) {
                localX += currentColumnWidth + groupGapX;
                localY = outerPad;
                currentColumnWidth = 0;
            }
            group.x = globalX + localX;
            group.y = localY;
            localY += group.height + groupGapY;
            currentColumnWidth = Math.max(currentColumnWidth, group.width);
            laneWidth = Math.max(laneWidth, localX + currentColumnWidth);
            laneHeight = Math.max(laneHeight, group.y + group.height);
        });
        globalX += laneWidth + (groupGapX * 2);
        maxHeight = Math.max(maxHeight, laneHeight + outerPad);
    });

    return {
        width: globalX,
        height: Math.max(maxHeight, 760),
    };
}

function graphComputeCompactLayout(nodes, edges, groupsMap, groupBy, persistedPositions = {}) {
    const totalNodes = Array.isArray(nodes) ? nodes.length : 0;
    const nodeGapX = totalNodes >= 5000 ? 10 : totalNodes >= 2500 ? 12 : 16;
    const nodeGapY = totalNodes >= 5000 ? 8 : totalNodes >= 2500 ? 10 : 14;
    const groupGapX = totalNodes >= 5000 ? 20 : 26;
    const groupGapY = totalNodes >= 5000 ? 20 : 28;
    const groupPadX = totalNodes >= 5000 ? 14 : 18;
    const groupTopPad = 42;
    const groupBottomPad = totalNodes >= 5000 ? 12 : 18;
    const groupHeaderPad = 16;
    const outerPad = 20;
    const viewId = String(graphWorkspaceState.viewId || "attack_surface").trim();

    const nodeById = new Map((nodes || []).map((node) => [String(node?.node_id || ""), node]));
    const {neighborMap, degreeMap} = graphBuildNeighborMaps(edges);
    const groupEntries = graphSortGroups(groupsMap, groupBy);
    const nodeToGroup = new Map();
    groupEntries.forEach(([groupKey, groupNodes]) => {
        (groupNodes || []).forEach((node) => {
            nodeToGroup.set(String(node?.node_id || ""), String(groupKey || ""));
        });
    });

    const groupAdjacency = new Map();
    const groupDegree = new Map();
    (edges || []).forEach((edge) => {
        const fromId = String(edge?.from_node_id || "");
        const toId = String(edge?.to_node_id || "");
        const fromGroup = nodeToGroup.get(fromId);
        const toGroup = nodeToGroup.get(toId);
        if (!fromGroup || !toGroup || fromGroup === toGroup) {
            return;
        }
        const forwardKey = `${fromGroup}::${toGroup}`;
        const reverseKey = `${toGroup}::${fromGroup}`;
        groupAdjacency.set(forwardKey, Number(groupAdjacency.get(forwardKey) || 0) + 1);
        groupAdjacency.set(reverseKey, Number(groupAdjacency.get(reverseKey) || 0) + 1);
        groupDegree.set(fromGroup, Number(groupDegree.get(fromGroup) || 0) + 1);
        groupDegree.set(toGroup, Number(groupDegree.get(toGroup) || 0) + 1);
    });

    const groupInfos = groupEntries.map(([groupKey, groupNodes]) => {
        const key = String(groupKey || "");
        const orderedNodes = (groupNodes || []).slice().sort((left, right) => {
            const typeDelta = graphGroupTypePriority(left?.type, groupBy) - graphGroupTypePriority(right?.type, groupBy);
            if (typeDelta !== 0) {
                return typeDelta;
            }
            const severityDelta = graphSeverityRank(left) - graphSeverityRank(right);
            if (severityDelta !== 0) {
                return severityDelta;
            }
            const degreeDelta = Number(degreeMap.get(String(right?.node_id || "")) || 0) - Number(degreeMap.get(String(left?.node_id || "")) || 0);
            if (degreeDelta !== 0) {
                return degreeDelta;
            }
            const neighborDelta = Number((neighborMap.get(String(right?.node_id || "")) || new Set()).size) - Number((neighborMap.get(String(left?.node_id || "")) || new Set()).size);
            if (neighborDelta !== 0) {
                return neighborDelta;
            }
            return graphNaturalCompare(left?.label || "", right?.label || "");
        });
        const priority = Math.min(...orderedNodes.map((item) => graphGroupTypePriority(item?.type, groupBy)), 9);
        const severity = Math.min(...orderedNodes.map((item) => graphSeverityRank(item)), 99);
        const findings = orderedNodes.filter((item) => ["finding", "cve", "exploit_reference"].includes(String(item?.type || "").trim().toLowerCase())).length;
        const {columns, rows} = graphEstimateGroupGrid(orderedNodes.length, totalNodes);
        const width = Math.max(
            220,
            Math.round((groupPadX * 2) + (columns * GRAPH_NODE_SIZE.width) + (Math.max(0, columns - 1) * nodeGapX)),
        );
        const height = Math.max(
            132,
            Math.round(groupHeaderPad + groupTopPad + (rows * GRAPH_NODE_SIZE.height) + (Math.max(0, rows - 1) * nodeGapY) + groupBottomPad),
        );
        return {
            key,
            label: key,
            nodes: orderedNodes,
            nodeIds: orderedNodes.map((item) => String(item?.node_id || "")).filter(Boolean),
            priority,
            severity,
            findings,
            degree: Number(groupDegree.get(key) || 0),
            lane: Math.min(...orderedNodes.map((item) => graphViewLanePriority(item?.type, viewId, groupBy)), 99),
            columns,
            rows,
            width,
            height,
            area: width * height,
            x: outerPad,
            y: outerPad,
        };
    });

    groupInfos.sort((left, right) => {
        if (left.lane !== right.lane) {
            return left.lane - right.lane;
        }
        if (left.priority !== right.priority) {
            return left.priority - right.priority;
        }
        if (left.severity !== right.severity) {
            return left.severity - right.severity;
        }
        if (left.findings !== right.findings) {
            return right.findings - left.findings;
        }
        if (left.degree !== right.degree) {
            return right.degree - left.degree;
        }
        if (left.area !== right.area) {
            return right.area - left.area;
        }
        return graphNaturalCompare(left.key, right.key);
    });

    const totalArea = groupInfos.reduce((sum, item) => sum + Number(item.area || 0), 0);
    const laneCount = new Set(groupInfos.map((item) => Number(item?.lane ?? 0))).size || 1;
    const targetHeight = graphEstimateLayoutTargetHeight(totalArea, totalNodes, laneCount);
    const packedGroups = graphPackGroupsIntoLanes(
        groupInfos,
        targetHeight,
        groupGapX,
        groupGapY,
        outerPad,
    );

    const positions = {};
    groupInfos.forEach((group) => {
        const rows = Math.max(1, Number(group.rows || 1));
        (group.nodes || []).forEach((node, index) => {
            const nodeId = String(node?.node_id || "");
            const column = Math.floor(index / rows);
            const row = index % rows;
            positions[nodeId] = {
                x: Math.round(group.x + groupPadX + (column * (GRAPH_NODE_SIZE.width + nodeGapX))),
                y: Math.round(group.y + groupTopPad + (row * (GRAPH_NODE_SIZE.height + nodeGapY))),
            };
        });
    });

    const livePositions = persistedPositions && typeof persistedPositions === "object" ? persistedPositions : {};
    Object.keys(livePositions).forEach((nodeId) => {
        if (!nodeById.has(String(nodeId || ""))) {
            return;
        }
        positions[nodeId] = {
            x: Math.max(outerPad, Math.round(Number(livePositions[nodeId]?.x) || 0)),
            y: Math.max(outerPad, Math.round(Number(livePositions[nodeId]?.y) || 0)),
        };
    });

    const renderedGroups = groupInfos.map((group) => {
        const groupNodeIds = Array.isArray(group.nodeIds) ? group.nodeIds : [];
        let minX = Number.POSITIVE_INFINITY;
        let minY = Number.POSITIVE_INFINITY;
        let maxX = 0;
        let maxY = 0;
        groupNodeIds.forEach((nodeId) => {
            const point = positions[String(nodeId || "")];
            if (!point) {
                return;
            }
            minX = Math.min(minX, Number(point.x) || 0);
            minY = Math.min(minY, Number(point.y) || 0);
            maxX = Math.max(maxX, (Number(point.x) || 0) + GRAPH_NODE_SIZE.width);
            maxY = Math.max(maxY, (Number(point.y) || 0) + GRAPH_NODE_SIZE.height);
        });
        if (!Number.isFinite(minX) || !Number.isFinite(minY)) {
            return {
                key: group.key,
                label: group.label,
                x: group.x,
                y: group.y,
                width: group.width,
                height: group.height,
                nodeIds: groupNodeIds,
            };
        }
        return {
            key: group.key,
            label: group.label,
            x: Math.max(12, Math.round(minX - groupPadX)),
            y: Math.max(12, Math.round(minY - groupTopPad + 12)),
            width: Math.max(220, Math.round((maxX - minX) + (groupPadX * 2))),
            height: Math.max(132, Math.round((maxY - minY) + groupTopPad + groupBottomPad + 12)),
            nodeIds: groupNodeIds,
        };
    });

    let width = Math.max(Math.round(packedGroups.width || 1200), 1200);
    let height = Math.max(Math.round(packedGroups.height || 760), 760);
    Object.values(positions).forEach((point) => {
        width = Math.max(width, (Number(point?.x) || 0) + GRAPH_NODE_SIZE.width + 80);
        height = Math.max(height, (Number(point?.y) || 0) + GRAPH_NODE_SIZE.height + 120);
    });
    renderedGroups.forEach((group) => {
        width = Math.max(width, (Number(group?.x) || 0) + (Number(group?.width) || 0) + 48);
        height = Math.max(height, (Number(group?.y) || 0) + (Number(group?.height) || 0) + 48);
    });

    return {
        positions,
        groups: renderedGroups,
        width: Math.round(width),
        height: Math.round(height),
    };
}

function graphEntityUnderlyingNodeIds(entity) {
    if (!entity || typeof entity !== "object") {
        return [];
    }
    const memberNodeIds = Array.isArray(graphPropertyValue(entity, "member_node_ids"))
        ? graphPropertyValue(entity, "member_node_ids")
        : [];
    if (memberNodeIds.length) {
        return memberNodeIds.map((item) => String(item || "")).filter(Boolean);
    }
    const nodeId = String(entity.node_id || "");
    return nodeId ? [nodeId] : [];
}

function graphSelectedUnderlyingNodeIds() {
    if (graphWorkspaceState.selectedKind !== "node" || !graphWorkspaceState.selectedRef) {
        return [];
    }
    return graphEntityUnderlyingNodeIds(graphFindEntity("node", graphWorkspaceState.selectedRef));
}

function graphShouldUseSummaryMode(nodeCount, edgeCount, renderMode) {
    const mode = String(renderMode || graphWorkspaceState.renderMode || "auto").trim().toLowerCase();
    if (mode === "graph") {
        return false;
    }
    if (mode === "summary") {
        return true;
    }
    if (mode === "matrix") {
        return true;
    }
    return nodeCount >= GRAPH_LARGE_NODE_THRESHOLD || edgeCount >= GRAPH_LARGE_EDGE_THRESHOLD;
}

function graphShouldUseMatrixMode(nodeCount, edgeCount, renderMode) {
    const mode = String(renderMode || graphWorkspaceState.renderMode || "auto").trim().toLowerCase();
    if (mode === "matrix") {
        return true;
    }
    if (mode === "graph" || mode === "summary") {
        return false;
    }
    return nodeCount >= GRAPH_MATRIX_NODE_THRESHOLD || edgeCount >= GRAPH_MATRIX_EDGE_THRESHOLD;
}

function graphDominantSourceKind(items) {
    const scores = new Map();
    const priority = {
        observed: 4,
        user_entered: 3,
        inferred: 2,
        ai_suggested: 1,
    };
    (items || []).forEach((item) => {
        const key = String(item?.source_kind || "observed").trim().toLowerCase() || "observed";
        const base = Number(scores.get(key) || 0);
        scores.set(key, base + 10 + Number(priority[key] || 0));
    });
    return Array.from(scores.entries()).sort((left, right) => right[1] - left[1])[0]?.[0] || "observed";
}

function graphRepresentativeSeverity(items) {
    let best = "";
    let bestRank = Number.POSITIVE_INFINITY;
    (items || []).forEach((item) => {
        const severity = String(graphPropertyValue(item, "severity") || "").trim().toLowerCase();
        if (!severity) {
            return;
        }
        const rank = Object.prototype.hasOwnProperty.call(GRAPH_SEVERITY_ORDER, severity)
            ? GRAPH_SEVERITY_ORDER[severity]
            : 80;
        if (rank < bestRank) {
            bestRank = rank;
            best = severity;
        }
    });
    return best;
}

function graphLargeClusterCollapseThreshold(nodeType, totalNodes) {
    const type = String(nodeType || "").trim().toLowerCase();
    if (type === "scope" || type === "subnet") {
        return Number.POSITIVE_INFINITY;
    }
    if (type === "finding" || type === "cve" || type === "exploit_reference") {
        return totalNodes >= 5000 ? 5 : 7;
    }
    if (type === "host" || type === "fqdn") {
        return totalNodes >= 5000 ? 3 : 5;
    }
    if (type === "service" || type === "port" || type === "url" || type === "screenshot") {
        return totalNodes >= 5000 ? 2 : 4;
    }
    if (type === "technology" || type === "cpe") {
        return totalNodes >= 5000 ? 2 : 3;
    }
    return totalNodes >= 5000 ? 2 : 4;
}

function graphLargeClusterDescriptor(node, hostMaps) {
    const type = String(node?.type || "").trim().toLowerCase();
    const label = String(node?.label || "").trim();
    const hostId = parseInt(graphPropertyValue(node, "host_id"), 10);
    const hostname = String(graphPropertyValue(node, "hostname") || "").trim();
    const ip = String(graphPropertyValue(node, "ip") || "").trim();
    const serviceName = String(graphPropertyValue(node, "service") || graphPropertyValue(node, "name") || label || "").trim().toLowerCase();
    const urlHost = graphUrlHost(label).toLowerCase();
    if (type === "host") {
        return {
            type,
            bucket: graphSubnetForIp(ip) || hostMaps.subnetByHostId.get(hostId) || graphHostnameSuffix(hostname) || "hosts",
        };
    }
    if (type === "fqdn") {
        return {
            type,
            bucket: graphHostnameSuffix(label || hostname) || hostMaps.domainByHostId.get(hostId) || "domains",
        };
    }
    if (type === "port") {
        return {
            type,
            bucket: `${graphPropertyValue(node, "port") || label}/${graphPropertyValue(node, "protocol") || "tcp"}`.replace(/\/$/, ""),
        };
    }
    if (type === "service") {
        return {
            type,
            bucket: serviceName || "service",
        };
    }
    if (type === "url") {
        return {
            type,
            bucket: urlHost || graphHostnameSuffix(hostname) || "urls",
        };
    }
    if (type === "technology" || type === "cpe" || type === "credential" || type === "identity" || type === "session") {
        return {
            type,
            bucket: String(label || graphPropertyValue(node, "name") || type).trim().toLowerCase() || type,
        };
    }
    if (type === "screenshot" || type === "artifact" || type === "action" || type === "evidence_record") {
        return {
            type,
            bucket: hostname || hostMaps.hostLabelById.get(hostId) || graphSubnetForIp(ip) || type,
        };
    }
    if (type === "finding" || type === "cve" || type === "exploit_reference") {
        return {
            type,
            bucket: String(label || graphPropertyValue(node, "title") || graphPropertyValue(node, "cve") || graphPropertyValue(node, "severity") || type)
                .trim()
                .toLowerCase() || type,
        };
    }
    return {
        type,
        bucket: String(label || type).trim().toLowerCase() || type,
    };
}

function graphLargeClusterLabel(type, bucket, memberNodes) {
    const count = Array.isArray(memberNodes) ? memberNodes.length : 0;
    const cleanedBucket = graphFriendlyLabel(String(bucket || "").replace(/^.+?:/, "")) || graphFriendlyLabel(type) || "summary";
    const plural = count === 1 ? "" : "s";
    if (type === "host") {
        return `${cleanedBucket} ${count} host${plural}`;
    }
    if (type === "fqdn") {
        return `${cleanedBucket} ${count} fqdn${plural}`;
    }
    if (type === "service" || type === "port" || type === "technology" || type === "cpe") {
        return `${cleanedBucket} ${count}`;
    }
    if (type === "url") {
        return `${cleanedBucket} ${count} url${plural}`;
    }
    if (type === "screenshot") {
        return `${cleanedBucket} ${count} screenshot${plural}`;
    }
    return `${cleanedBucket} ${count}`;
}

function graphCreateSummaryNode(summaryId, groupKey, descriptor, memberNodes) {
    const severity = graphRepresentativeSeverity(memberNodes);
    const sampleLabels = (memberNodes || []).map((item) => String(item?.label || "").trim()).filter(Boolean).slice(0, 3);
    return {
        node_id: summaryId,
        type: descriptor.type,
        label: graphLargeClusterLabel(descriptor.type, descriptor.bucket, memberNodes),
        confidence: Math.max(...(memberNodes || []).map((item) => Number(item?.confidence || 0) || 0), 0),
        source_kind: graphDominantSourceKind(memberNodes),
        properties: {
            summary_kind: true,
            summary_group_key: groupKey,
            member_count: memberNodes.length,
            member_node_ids: memberNodes.map((item) => String(item?.node_id || "")).filter(Boolean),
            member_types: Array.from(new Set(memberNodes.map((item) => String(item?.type || "").trim().toLowerCase()).filter(Boolean))),
            sample_labels: sampleLabels,
            collapsed_type: descriptor.type,
            severity,
        },
        evidence_refs: [],
    };
}

function graphLimitAggregateEdges(edges, summaryNodeIds, selectedVisibleId, focusActive) {
    const sorted = (edges || []).slice().sort((left, right) => {
        const leftCount = Number(graphPropertyValue(left, "aggregate_count") || 1);
        const rightCount = Number(graphPropertyValue(right, "aggregate_count") || 1);
        if (leftCount !== rightCount) {
            return rightCount - leftCount;
        }
        return graphNaturalCompare(left?.edge_id || "", right?.edge_id || "");
    });
    if (focusActive) {
        return sorted;
    }
    const perNode = new Map();
    const kept = [];
    sorted.forEach((edge) => {
        const fromId = String(edge?.from_node_id || "");
        const toId = String(edge?.to_node_id || "");
        const count = Number(graphPropertyValue(edge, "aggregate_count") || 1);
        const fromSummary = summaryNodeIds.has(fromId);
        const toSummary = summaryNodeIds.has(toId);
        if (selectedVisibleId && (fromId === selectedVisibleId || toId === selectedVisibleId)) {
            kept.push(edge);
            return;
        }
        if (fromSummary || toSummary || count >= 3) {
            kept.push(edge);
            return;
        }
        const fromSeen = Number(perNode.get(fromId) || 0);
        const toSeen = Number(perNode.get(toId) || 0);
        if (fromSeen >= 6 && toSeen >= 6) {
            return;
        }
        perNode.set(fromId, fromSeen + 1);
        perNode.set(toId, toSeen + 1);
        kept.push(edge);
    });
    return kept;
}

function graphBuildLargeGraphProjection(nodes, edges, hostMaps, groupBy) {
    const totalNodes = Array.isArray(nodes) ? nodes.length : 0;
    const groupsMap = new Map();
    (nodes || []).forEach((node) => {
        const groupKey = graphGroupKeyForNode(node, groupBy, hostMaps) || "other";
        if (!groupsMap.has(groupKey)) {
            groupsMap.set(groupKey, []);
        }
        groupsMap.get(groupKey).push(node);
    });

    const visibleNodes = [];
    const visibleNodeIdsByGroup = new Map();
    const memberToVisible = new Map();
    const summaryNodeIds = new Set();
    const visibleNodeMap = new Map();

    groupsMap.forEach((groupNodes, groupKey) => {
        const clusters = new Map();
        (groupNodes || []).forEach((node) => {
            const descriptor = graphLargeClusterDescriptor(node, hostMaps);
            const clusterKey = `${descriptor.type}|${descriptor.bucket}`;
            if (!clusters.has(clusterKey)) {
                clusters.set(clusterKey, {
                    descriptor,
                    nodes: [],
                });
            }
            clusters.get(clusterKey).nodes.push(node);
        });
        visibleNodeIdsByGroup.set(groupKey, new Set());
        clusters.forEach((cluster, clusterKey) => {
            const type = String(cluster.descriptor?.type || "").trim().toLowerCase();
            const threshold = graphLargeClusterCollapseThreshold(type, totalNodes);
            const summaryId = `graph-summary-${graphHashToken(`${groupKey}|${clusterKey}`)}`;
            const expanded = Boolean(graphWorkspaceState.expandedSummaryIds[summaryId]);
            const shouldCollapse = cluster.nodes.length > threshold && !expanded;
            if (shouldCollapse) {
                const summaryNode = graphCreateSummaryNode(summaryId, groupKey, cluster.descriptor, cluster.nodes);
                visibleNodes.push(summaryNode);
                visibleNodeMap.set(summaryId, summaryNode);
                visibleNodeIdsByGroup.get(groupKey).add(summaryId);
                summaryNodeIds.add(summaryId);
                cluster.nodes.forEach((node) => {
                    memberToVisible.set(String(node?.node_id || ""), summaryId);
                });
                return;
            }
            cluster.nodes.forEach((node) => {
                const nodeId = String(node?.node_id || "");
                visibleNodes.push(node);
                visibleNodeMap.set(nodeId, node);
                visibleNodeIdsByGroup.get(groupKey).add(nodeId);
                memberToVisible.set(nodeId, nodeId);
            });
        });
    });

    const edgeMap = new Map();
    (edges || []).forEach((edge) => {
        const fromVisibleId = memberToVisible.get(String(edge?.from_node_id || ""));
        const toVisibleId = memberToVisible.get(String(edge?.to_node_id || ""));
        if (!fromVisibleId || !toVisibleId || fromVisibleId === toVisibleId) {
            return;
        }
        const edgeType = String(edge?.type || "").trim().toLowerCase() || "related";
        const key = `${fromVisibleId}|${toVisibleId}|${edgeType}`;
        if (!edgeMap.has(key)) {
            edgeMap.set(key, {
                edge_id: `graph-edge-summary-${graphHashToken(key)}`,
                type: edgeType,
                from_node_id: fromVisibleId,
                to_node_id: toVisibleId,
                source_kind: "observed",
                confidence: 0,
                members: [],
                properties: {
                    aggregate_kind: true,
                    aggregate_count: 0,
                    edge_types: [],
                },
            });
        }
        const record = edgeMap.get(key);
        record.members.push(edge);
        record.properties.aggregate_count += Number(graphPropertyValue(edge, "aggregate_count") || 1);
        record.properties.edge_types.push(edgeType);
        record.confidence = Math.max(Number(record.confidence || 0), Number(edge?.confidence || 0) || 0);
        record.source_kind = graphDominantSourceKind(record.members);
    });

    const selectedVisibleId = String(graphWorkspaceState.selectedRef || "");
    const focusActive = Array.isArray(graphWorkspaceState.focusSeedNodeIds) && graphWorkspaceState.focusSeedNodeIds.length > 0;
    const projectedEdges = graphLimitAggregateEdges(
        Array.from(edgeMap.values()).map((edge) => ({
            edge_id: edge.edge_id,
            type: edge.type,
            from_node_id: edge.from_node_id,
            to_node_id: edge.to_node_id,
            source_kind: edge.source_kind,
            confidence: edge.confidence,
            properties: {
                ...edge.properties,
                edge_types: Array.from(new Set(edge.properties.edge_types)),
            },
        })),
        summaryNodeIds,
        selectedVisibleId,
        focusActive,
    );

    const projectedGroups = new Map();
    visibleNodeIdsByGroup.forEach((nodeIdSet, groupKey) => {
        const visibleGroupNodes = Array.from(nodeIdSet)
            .map((nodeId) => visibleNodeMap.get(String(nodeId || "")))
            .filter(Boolean);
        if (visibleGroupNodes.length) {
            projectedGroups.set(groupKey, visibleGroupNodes);
        }
    });

    return {
        nodes: visibleNodes,
        edges: projectedEdges,
        groupsMap: projectedGroups,
        usedSummary: summaryNodeIds.size > 0,
        summaryNodeIds,
    };
}

function graphComputeFocusedSubgraph(nodes, edges, seedNodeIds, depth) {
    const requestedSeeds = Array.isArray(seedNodeIds) ? seedNodeIds.map((item) => String(item || "")).filter(Boolean) : [];
    if (!requestedSeeds.length) {
        return {
            nodes,
            edges,
            active: false,
        };
    }
    const nodeById = new Map((nodes || []).map((node) => [String(node?.node_id || ""), node]));
    const seeds = requestedSeeds.filter((nodeId) => nodeById.has(nodeId));
    if (!seeds.length) {
        return {
            nodes,
            edges,
            active: false,
        };
    }
    const neighborMap = new Map();
    (edges || []).forEach((edge) => {
        const fromId = String(edge?.from_node_id || "");
        const toId = String(edge?.to_node_id || "");
        if (!fromId || !toId) {
            return;
        }
        if (!neighborMap.has(fromId)) {
            neighborMap.set(fromId, new Set());
        }
        if (!neighborMap.has(toId)) {
            neighborMap.set(toId, new Set());
        }
        neighborMap.get(fromId).add(toId);
        neighborMap.get(toId).add(fromId);
    });

    const visited = new Set(seeds);
    let frontier = seeds.slice();
    const maxDepth = Math.max(1, Math.min(3, Number(depth || 1)));
    for (let step = 0; step < maxDepth; step += 1) {
        const next = [];
        frontier.forEach((nodeId) => {
            const neighbors = Array.from(neighborMap.get(nodeId) || []);
            neighbors.forEach((neighborId) => {
                if (visited.has(neighborId)) {
                    return;
                }
                visited.add(neighborId);
                next.push(neighborId);
            });
        });
        frontier = next;
        if (!frontier.length) {
            break;
        }
    }
    return {
        nodes: (nodes || []).filter((node) => visited.has(String(node?.node_id || ""))),
        edges: (edges || []).filter((edge) => visited.has(String(edge?.from_node_id || "")) && visited.has(String(edge?.to_node_id || ""))),
        active: true,
    };
}

function graphComputeMatrixView(nodes, edges, groups) {
    const nodeToGroup = new Map();
    (groups || []).forEach((group) => {
        (group.nodeIds || []).forEach((nodeId) => {
            nodeToGroup.set(String(nodeId || ""), String(group.key || ""));
        });
    });

    const activity = new Map();
    (edges || []).forEach((edge) => {
        const fromKey = nodeToGroup.get(String(edge?.from_node_id || ""));
        const toKey = nodeToGroup.get(String(edge?.to_node_id || ""));
        if (!fromKey || !toKey) {
            return;
        }
        const count = Number(graphPropertyValue(edge, "aggregate_count") || 1);
        activity.set(fromKey, Number(activity.get(fromKey) || 0) + count);
        activity.set(toKey, Number(activity.get(toKey) || 0) + count);
    });

    const orderedGroups = (groups || []).map((group) => ({
        key: String(group?.key || ""),
        label: String(group?.label || group?.key || ""),
        nodeCount: Array.isArray(group?.nodeIds) ? group.nodeIds.length : 0,
        activity: Number(activity.get(String(group?.key || "")) || 0),
    })).sort((left, right) => {
        if (left.activity !== right.activity) {
            return right.activity - left.activity;
        }
        if (left.nodeCount !== right.nodeCount) {
            return right.nodeCount - left.nodeCount;
        }
        return graphNaturalCompare(left.label, right.label);
    });

    const keptGroups = orderedGroups.slice(0, GRAPH_MATRIX_GROUP_LIMIT);
    const keptKeys = new Set(keptGroups.map((group) => group.key));
    const otherNeeded = orderedGroups.length > keptGroups.length;
    const indexByKey = new Map(keptGroups.map((group, index) => [group.key, index]));
    if (otherNeeded) {
        keptGroups.push({
            key: "__other__",
            label: "other",
            nodeCount: orderedGroups.slice(GRAPH_MATRIX_GROUP_LIMIT).reduce((sum, group) => sum + group.nodeCount, 0),
            activity: orderedGroups.slice(GRAPH_MATRIX_GROUP_LIMIT).reduce((sum, group) => sum + group.activity, 0),
        });
    }

    const size = keptGroups.length;
    const values = Array.from({length: size}, () => Array.from({length: size}, () => 0));
    let maxValue = 0;
    (edges || []).forEach((edge) => {
        let fromKey = nodeToGroup.get(String(edge?.from_node_id || ""));
        let toKey = nodeToGroup.get(String(edge?.to_node_id || ""));
        if (!fromKey || !toKey) {
            return;
        }
        if (!keptKeys.has(fromKey)) {
            fromKey = "__other__";
        }
        if (!keptKeys.has(toKey)) {
            toKey = "__other__";
        }
        const rowIndex = keptGroups.findIndex((group) => group.key === fromKey);
        const columnIndex = keptGroups.findIndex((group) => group.key === toKey);
        if (rowIndex < 0 || columnIndex < 0) {
            return;
        }
        const count = Number(graphPropertyValue(edge, "aggregate_count") || 1);
        values[rowIndex][columnIndex] += count;
        maxValue = Math.max(maxValue, values[rowIndex][columnIndex]);
    });

    return {
        groups: keptGroups,
        values,
        maxValue,
    };
}

function graphApplyLocalFilters(snapshot) {
    const viewConfig = graphCurrentViewConfig();
    const filters = graphCollectServerQuery();
    const sourceKind = filters.sourceKind;
    const nodeType = filters.nodeType;
    const edgeType = filters.edgeType;
    const severity = filters.severity;
    const pack = filters.pack;
    const cutoff = graphTimeWindowCutoff(filters.timeWindow);

    let nodes = Array.isArray(snapshot?.nodes) ? snapshot.nodes.slice() : [];
    let edges = Array.isArray(snapshot?.edges) ? snapshot.edges.slice() : [];

    if (Array.isArray(viewConfig.nodeTypes) && viewConfig.nodeTypes.length > 0) {
        const allowedNodeTypes = new Set(viewConfig.nodeTypes);
        nodes = nodes.filter((item) => allowedNodeTypes.has(String(item?.type || "").trim().toLowerCase()));
    }
    let nodeIds = new Set(nodes.map((item) => String(item?.node_id || "")));
    if (Array.isArray(viewConfig.edgeTypes) && viewConfig.edgeTypes.length > 0) {
        const allowedEdgeTypes = new Set(viewConfig.edgeTypes);
        edges = edges.filter((item) => allowedEdgeTypes.has(String(item?.type || "").trim().toLowerCase()));
    }
    edges = edges.filter((item) => nodeIds.has(String(item?.from_node_id || "")) && nodeIds.has(String(item?.to_node_id || "")));

    const nodeFocusActive = Boolean(sourceKind || nodeType || severity || pack || cutoff);
    const edgeFocusActive = Boolean(sourceKind || edgeType || severity || pack || cutoff);
    const nodePredicate = (item) => {
        const matchesSource = !sourceKind || String(item?.source_kind || "").trim().toLowerCase() === sourceKind;
        const matchesType = !nodeType || String(item?.type || "").trim().toLowerCase() === nodeType;
        return matchesSource
            && matchesType
            && graphEntityMatchesSeverity(item, severity)
            && graphEntityMatchesPack(item, pack)
            && graphEntityMatchesTimeWindow(item, cutoff);
    };
    const edgePredicate = (item) => {
        const matchesSource = !sourceKind || String(item?.source_kind || "").trim().toLowerCase() === sourceKind;
        const matchesType = !edgeType || String(item?.type || "").trim().toLowerCase() === edgeType;
        return matchesSource
            && matchesType
            && graphEntityMatchesSeverity(item, severity)
            && graphEntityMatchesPack(item, pack)
            && graphEntityMatchesTimeWindow(item, cutoff);
    };

    const keptNodeIds = new Set(
        nodeFocusActive
            ? nodes.filter(nodePredicate).map((item) => String(item?.node_id || ""))
            : nodes.map((item) => String(item?.node_id || ""))
    );
    const keptEdges = edgeFocusActive ? edges.filter(edgePredicate) : edges.slice();
    if (edgeFocusActive) {
        keptEdges.forEach((item) => {
            keptNodeIds.add(String(item?.from_node_id || ""));
            keptNodeIds.add(String(item?.to_node_id || ""));
        });
    }

    nodes = nodes.filter((item) => keptNodeIds.has(String(item?.node_id || "")));
    nodeIds = new Set(nodes.map((item) => String(item?.node_id || "")));
    edges = keptEdges.filter((item) => nodeIds.has(String(item?.from_node_id || "")) && nodeIds.has(String(item?.to_node_id || "")));

    const baseNodeCount = nodes.length;
    const baseEdgeCount = edges.length;
    const focused = graphComputeFocusedSubgraph(nodes, edges, graphWorkspaceState.focusSeedNodeIds, filters.focusDepth);
    nodes = focused.nodes;
    edges = focused.edges;

    const hostMaps = graphBuildHostMaps(nodes);
    let groupsMap = new Map();
    let largeGraphMode = graphShouldUseSummaryMode(nodes.length, edges.length, filters.renderMode);
    let summaryUsed = false;
    let summaryNodeIds = new Set();

    if (largeGraphMode) {
        const projection = graphBuildLargeGraphProjection(
            nodes,
            edges,
            hostMaps,
            filters.groupBy || viewConfig.defaultGroup || "subnet",
        );
        nodes = projection.nodes;
        edges = projection.edges;
        groupsMap = projection.groupsMap;
        summaryUsed = Boolean(projection.usedSummary);
        summaryNodeIds = projection.summaryNodeIds || new Set();
    } else {
        nodes.sort(graphSortNodes).forEach((item) => {
            const key = graphGroupKeyForNode(item, filters.groupBy || viewConfig.defaultGroup || "subnet", hostMaps) || "other";
            if (!groupsMap.has(key)) {
                groupsMap.set(key, []);
            }
            groupsMap.get(key).push(item);
        });
    }

    const layout = graphComputeCompactLayout(
        nodes,
        edges,
        groupsMap,
        filters.groupBy || viewConfig.defaultGroup || "subnet",
        graphWorkspaceState.positions,
    );

    const renderKind = graphShouldUseMatrixMode(nodes.length, edges.length, filters.renderMode) && (layout.groups || []).length > 2
        ? "matrix"
        : "graph";
    const matrix = renderKind === "matrix"
        ? graphComputeMatrixView(nodes, edges, layout.groups || [])
        : null;

    return {
        nodes,
        edges,
        groups: layout.groups,
        positions: layout.positions,
        width: layout.width,
        height: layout.height,
        renderKind,
        matrix,
        meta: {
            largeGraphMode,
            summaryUsed,
            focusActive: focused.active,
            focusDepth: filters.focusDepth,
            baseNodeCount,
            baseEdgeCount,
            summaryNodeCount: summaryNodeIds.size,
        },
    };
}

function graphNodeColor(node) {
    const token = String(node?.type || "").trim().toLowerCase();
    return GRAPH_NODE_COLORS[token] || "#b4bbdd";
}

function graphSourceStyle(entity) {
    const key = String(entity?.source_kind || "observed").trim().toLowerCase();
    return GRAPH_SOURCE_KIND_STYLES[key] || GRAPH_SOURCE_KIND_STYLES.observed;
}

function opaqueUiEnabled() {
    return Boolean(window.LEGION_OPAQUE_UI_ENABLED) || Boolean(document.body?.classList.contains("opaque-ui"));
}

function graphEdgeStrokeColor(entity) {
    const style = graphSourceStyle(entity);
    return String(style?.edgeStroke || style?.stroke || "#687691");
}

function graphNodeFillColor(entity) {
    const style = graphSourceStyle(entity);
    return opaqueUiEnabled() ? String(style?.fillOpaque || "#18182a") : String(style?.fill || "#18182a");
}

function graphSplitLabel(label) {
    const words = String(label || "").trim().split(/\s+/).filter(Boolean);
    if (!words.length) {
        return ["unknown"];
    }
    const lines = [];
    let current = "";
    words.forEach((word) => {
        const next = current ? `${current} ${word}` : word;
        if (next.length <= 18 || !current) {
            current = next;
            return;
        }
        lines.push(current);
        current = word;
    });
    if (current) {
        lines.push(current);
    }
    return lines.slice(0, 2);
}

function graphCreateSvgNode(tagName, attributes = {}, text = "") {
    const node = document.createElementNS("http://www.w3.org/2000/svg", tagName);
    Object.entries(attributes).forEach(([key, value]) => {
        if (value === undefined || value === null || value === "") {
            return;
        }
        node.setAttribute(key, String(value));
    });
    if (text) {
        node.textContent = text;
    }
    return node;
}

function graphSvgPoint(svg, event) {
    const rect = svg.getBoundingClientRect();
    const viewBox = svg.viewBox.baseVal;
    const scaleX = rect.width > 0 ? viewBox.width / rect.width : 1;
    const scaleY = rect.height > 0 ? viewBox.height / rect.height : 1;
    return {
        x: viewBox.x + ((event.clientX - rect.left) * scaleX),
        y: viewBox.y + ((event.clientY - rect.top) * scaleY),
    };
}

function graphFindEntity(kind, ref) {
    if (kind === "edge") {
        return (graphWorkspaceState.filtered.edges || []).find((item) => String(item?.edge_id || "") === String(ref || "")) || null;
    }
    return (graphWorkspaceState.filtered.nodes || []).find((item) => String(item?.node_id || "") === String(ref || "")) || null;
}

function graphFindGroup(groupKey) {
    return (graphWorkspaceState.filtered.groups || []).find((item) => String(item?.key || "") === String(groupKey || "")) || null;
}

function graphEntityHostId(entity) {
    if (!entity || graphPropertyValue(entity, "summary_kind")) {
        return 0;
    }
    const directHostId = parseInt(graphPropertyValue(entity, "host_id"), 10);
    if (Number.isFinite(directHostId) && directHostId > 0) {
        return directHostId;
    }

    const label = String(entity?.label || "").trim().toLowerCase();
    const hostname = String(graphPropertyValue(entity, "hostname") || "").trim().toLowerCase();
    const ip = String(graphPropertyValue(entity, "ip") || "").trim();
    const matchedHost = (workspaceState.hosts || []).find((host) => {
        return (
            (label && String(host?.hostname || "").trim().toLowerCase() === label)
            || (hostname && String(host?.hostname || "").trim().toLowerCase() === hostname)
            || (ip && String(host?.ip || "").trim() === ip)
        );
    });
    const matchedHostId = parseInt(matchedHost?.id, 10);
    return Number.isFinite(matchedHostId) && matchedHostId > 0 ? matchedHostId : 0;
}

function graphNodeMatchesSelectedHost(node) {
    const selectedHostId = parseInt(workspaceState.selectedHostId, 10);
    if (!Number.isFinite(selectedHostId) || selectedHostId <= 0) {
        return false;
    }
    if (String(node?.type || "").trim().toLowerCase() !== "host") {
        return false;
    }
    return graphEntityHostId(node) === selectedHostId;
}

function graphDismissSelection() {
    closeGraphNoteModalAction(false);
    graphWorkspaceState.selectedKind = "";
    graphWorkspaceState.selectedRef = "";
    graphWorkspaceState.selectedPayload = null;
    graphWorkspaceState.relatedContent = [];
    graphRenderWorkspace();
}

function graphSetFiltersExpanded(expanded) {
    const next = Boolean(expanded);
    graphWorkspaceState.filtersExpanded = next;
    const panel = document.getElementById("graph-filters-panel");
    const button = document.getElementById("graph-filters-toggle-button");
    if (panel) {
        panel.hidden = !next;
    }
    if (button) {
        const label = next ? "Hide Filters" : "Show Filters";
        button.setAttribute("title", label);
        button.setAttribute("aria-label", label);
        button.setAttribute("aria-expanded", next ? "true" : "false");
        button.classList.toggle("is-active", next);
    }
}

function graphSelectionAnchorPoint() {
    const canvasPanel = getGraphCanvasPanel();
    const svg = document.getElementById("graph-workspace-canvas");
    if (!canvasPanel || !svg || svg.hidden) {
        return null;
    }
    const viewBox = svg.viewBox?.baseVal;
    if (!viewBox || !Number(viewBox.width) || !Number(viewBox.height)) {
        return null;
    }
    const panelRect = canvasPanel.getBoundingClientRect();
    const svgRect = svg.getBoundingClientRect();
    const kind = String(graphWorkspaceState.selectedKind || "");
    const ref = String(graphWorkspaceState.selectedRef || "");
    if (!kind || !ref) {
        return null;
    }

    let anchorX = 0;
    let anchorY = 0;
    if (kind === "node") {
        const point = graphWorkspaceState.filtered.positions?.[ref] || graphWorkspaceState.positions?.[ref];
        if (!point) {
            return null;
        }
        anchorX = Number(point.x || 0) + GRAPH_NODE_SIZE.width;
        anchorY = Number(point.y || 0) + (GRAPH_NODE_SIZE.height / 2);
    } else if (kind === "edge") {
        const entity = graphFindEntity("edge", ref);
        if (!entity) {
            return null;
        }
        const sourcePoint = graphWorkspaceState.filtered.positions?.[String(entity.from_node_id || "")];
        const targetPoint = graphWorkspaceState.filtered.positions?.[String(entity.to_node_id || "")];
        if (!sourcePoint || !targetPoint) {
            return null;
        }
        const startX = Number(sourcePoint.x || 0) + GRAPH_NODE_SIZE.width;
        const startY = Number(sourcePoint.y || 0) + (GRAPH_NODE_SIZE.height / 2);
        const endX = Number(targetPoint.x || 0);
        const endY = Number(targetPoint.y || 0) + (GRAPH_NODE_SIZE.height / 2);
        anchorX = (startX + endX) / 2;
        anchorY = (startY + endY) / 2;
    } else {
        return null;
    }

    return {
        x: (svgRect.left - panelRect.left) + ((anchorX / Number(viewBox.width || 1)) * svgRect.width),
        y: (svgRect.top - panelRect.top) + ((anchorY / Number(viewBox.height || 1)) * svgRect.height),
    };
}

function graphSyncDetailPresentation() {
    const shell = getGraphWorkspaceShell();
    const sidebar = document.getElementById("graph-sidebar");
    const dockSlot = document.getElementById("graph-detail-dock-slot");
    const floatingLayer = document.getElementById("graph-detail-floating-layer");
    const detailPanel = document.getElementById("graph-detail-panel");
    const toggleButton = document.getElementById("graph-detail-dock-toggle-button");
    const closeButton = document.getElementById("graph-detail-close-button");
    if (!shell || !sidebar || !dockSlot || !floatingLayer || !detailPanel || !toggleButton || !closeButton) {
        return;
    }

    const floating = String(graphWorkspaceState.detailMode || "floating") !== "docked";
    const hasSelection = graphHasActiveSelection();

    shell.classList.toggle("graph-workspace-detail-floating", floating);
    shell.classList.toggle("graph-workspace-detail-docked", !floating);
    sidebar.hidden = floating;
    floatingLayer.hidden = !floating || !hasSelection;
    detailPanel.classList.toggle("is-floating", floating);
    toggleButton.setAttribute("title", floating ? "Dock Panel" : "Float Panel");
    toggleButton.setAttribute("aria-label", floating ? "Dock Panel" : "Float Panel");
    closeButton.hidden = !floating;

    if (floating) {
        if (detailPanel.parentElement !== floatingLayer) {
            floatingLayer.appendChild(detailPanel);
        }
    } else if (detailPanel.parentElement !== dockSlot) {
        dockSlot.appendChild(detailPanel);
    }

    detailPanel.hidden = floating ? !hasSelection : false;
    if (!floating || !hasSelection) {
        detailPanel.style.left = "";
        detailPanel.style.top = "";
        return;
    }

    window.requestAnimationFrame(() => {
        const canvasPanel = getGraphCanvasPanel();
        if (!canvasPanel || detailPanel.hidden) {
            return;
        }
        const anchor = graphSelectionAnchorPoint();
        const panelWidth = Math.min(detailPanel.offsetWidth || 430, Math.max(280, canvasPanel.clientWidth - 16));
        const panelHeight = detailPanel.offsetHeight || 420;
        const areaWidth = Math.max(320, canvasPanel.clientWidth);
        const areaHeight = Math.max(240, canvasPanel.clientHeight);
        let left = Math.max(8, areaWidth - panelWidth - 10);
        let top = 12;
        if (anchor) {
            left = anchor.x + 18;
            top = anchor.y + 12;
            if ((left + panelWidth) > (areaWidth - 8)) {
                left = Math.max(8, anchor.x - panelWidth - 18);
            }
            if ((top + panelHeight) > (areaHeight - 8)) {
                top = Math.max(8, areaHeight - panelHeight - 8);
            }
        }
        left = Math.max(8, Math.min(left, areaWidth - panelWidth - 8));
        top = Math.max(8, Math.min(top, areaHeight - Math.min(panelHeight, areaHeight - 8) - 8));
        detailPanel.style.left = `${Math.round(left)}px`;
        detailPanel.style.top = `${Math.round(top)}px`;
    });
}

function graphSetDetailMode(mode) {
    graphWorkspaceState.detailMode = String(mode || "floating").trim().toLowerCase() === "docked"
        ? "docked"
        : "floating";
    graphSyncDetailPresentation();
}

function graphToggleDetailModeAction() {
    graphSetDetailMode(graphWorkspaceState.detailMode === "docked" ? "floating" : "docked");
}

function graphRefreshSelectionActionButtons() {
    const focusButton = document.getElementById("graph-focus-selection-button");
    const clearFocusButton = document.getElementById("graph-clear-focus-button");
    const expandButton = document.getElementById("graph-expand-selection-button");
    const collapseButton = document.getElementById("graph-collapse-expanded-button");
    const selectedNode = graphSelectedNodeEntity();
    const selectedSummaryNode = selectedNode && graphPropertyValue(selectedNode, "summary_kind")
        ? selectedNode
        : null;
    const selectedSummaryId = String(selectedSummaryNode?.node_id || "");
    const selectedSummaryExpanded = Boolean(selectedSummaryId && graphWorkspaceState.expandedSummaryIds[selectedSummaryId]);

    if (focusButton) {
        const canFocus = Boolean(selectedNode);
        focusButton.disabled = !canFocus;
        const focusLabel = canFocus ? "Focus Selected" : "Select a node or summary to focus";
        focusButton.setAttribute("title", focusLabel);
        focusButton.setAttribute("aria-label", focusLabel);
    }

    if (clearFocusButton) {
        const hasFocus = Array.isArray(graphWorkspaceState.focusSeedNodeIds) && graphWorkspaceState.focusSeedNodeIds.length > 0;
        clearFocusButton.disabled = !hasFocus;
        const clearLabel = hasFocus ? "Clear Focus" : "No graph focus is active";
        clearFocusButton.setAttribute("title", clearLabel);
        clearFocusButton.setAttribute("aria-label", clearLabel);
    }

    if (expandButton) {
        const canExpand = Boolean(selectedSummaryNode) && !selectedSummaryExpanded;
        expandButton.hidden = !canExpand;
        expandButton.disabled = !canExpand;
        const expandLabel = canExpand ? "Expand Cluster" : "Select a collapsed summary cluster to expand";
        expandButton.setAttribute("title", expandLabel);
        expandButton.setAttribute("aria-label", expandLabel);
    }

    if (collapseButton) {
        const canCollapse = Boolean(selectedSummaryNode) && selectedSummaryExpanded;
        collapseButton.hidden = !canCollapse;
        collapseButton.disabled = !canCollapse;
        const collapseLabel = canCollapse ? "Collapse Cluster" : "Select an expanded summary cluster to collapse";
        collapseButton.setAttribute("title", collapseLabel);
        collapseButton.setAttribute("aria-label", collapseLabel);
    }
}

function graphRenderSelectionDetail() {
    const detailCaption = document.getElementById("graph-detail-caption");
    const badgesNode = document.getElementById("graph-selection-badges");
    const fieldsNode = document.getElementById("graph-detail-fields");
    const hostActionsBlock = document.getElementById("graph-host-actions-block");
    const hostActionsNode = document.getElementById("graph-host-actions");
    const portActionsBlock = document.getElementById("graph-port-actions-block");
    const portActionsNode = document.getElementById("graph-port-actions");
    const serviceActionsBlock = document.getElementById("graph-service-actions-block");
    const serviceActionsNode = document.getElementById("graph-service-actions");
    const subnetActionsBlock = document.getElementById("graph-subnet-actions-block");
    const subnetActionsNode = document.getElementById("graph-subnet-actions");
    const screenshotActionsBlock = document.getElementById("graph-screenshot-actions-block");
    const screenshotActionsNode = document.getElementById("graph-screenshot-actions");
    const evidenceNode = document.getElementById("graph-detail-evidence");
    const propertiesNode = document.getElementById("graph-detail-properties");
    const annotationsNode = document.getElementById("graph-annotations-list");
    const focusButton = document.getElementById("graph-focus-selection-button");
    const expandButton = document.getElementById("graph-expand-selection-button");
    const collapseButton = document.getElementById("graph-collapse-expanded-button");
    const pinButton = document.getElementById("graph-pin-toggle-button");
    const noteButton = document.getElementById("graph-note-open-button");
    if (!detailCaption || !badgesNode || !fieldsNode || !hostActionsBlock || !hostActionsNode || !portActionsBlock || !portActionsNode || !serviceActionsBlock || !serviceActionsNode || !subnetActionsBlock || !subnetActionsNode || !screenshotActionsBlock || !screenshotActionsNode || !evidenceNode || !propertiesNode || !annotationsNode || !focusButton || !expandButton || !collapseButton || !pinButton || !noteButton) {
        return;
    }

    const kind = String(graphWorkspaceState.selectedKind || "");
    const ref = String(graphWorkspaceState.selectedRef || "");
    const entity = kind === "node"
        ? graphSelectedNodeEntity()
        : graphFindEntity(kind, ref);
    graphWorkspaceState.selectedPayload = entity;

    badgesNode.innerHTML = "";
    fieldsNode.innerHTML = "";
    hostActionsNode.innerHTML = "";
    portActionsNode.innerHTML = "";
    serviceActionsNode.innerHTML = "";
    subnetActionsNode.innerHTML = "";
    screenshotActionsNode.innerHTML = "";
    hostActionsBlock.hidden = true;
    portActionsBlock.hidden = true;
    serviceActionsBlock.hidden = true;
    subnetActionsBlock.hidden = true;
    screenshotActionsBlock.hidden = true;
    evidenceNode.innerHTML = "";
    annotationsNode.innerHTML = "";

    if (!entity) {
        detailCaption.textContent = "Select a node or edge";
        propertiesNode.textContent = "No graph selection";
        focusButton.disabled = true;
        focusButton.setAttribute("title", "Select a node or summary to focus");
        focusButton.setAttribute("aria-label", "Select a node or summary to focus");
        noteButton.disabled = true;
        noteButton.setAttribute("title", "Select a node or edge to add a note");
        noteButton.setAttribute("aria-label", "Select a node or edge to add a note");
        pinButton.disabled = true;
        pinButton.classList.remove("is-active");
        pinButton.setAttribute("title", "Select a node to pin");
        pinButton.setAttribute("aria-label", "Select a node to pin");
        graphRenderRelatedContent("No related artifacts or screenshots.");
        graphRefreshSelectionActionButtons();
        graphSyncDetailPresentation();
        return;
    }

    const isSummaryNode = kind === "node" && Boolean(graphPropertyValue(entity, "summary_kind"));
    const isAggregateEdge = kind === "edge" && Boolean(graphPropertyValue(entity, "aggregate_kind"));
    const relatedHostId = kind === "node" ? graphEntityHostId(entity) : 0;
    const entityType = kind === "node" ? String(entity.type || "").trim().toLowerCase() : "";
    const fields = [];
    if (kind === "node") {
        detailCaption.textContent = `${graphFriendlyLabel(entity.type)}: ${entity.label || entity.node_id || ""}`;
        fields.push(["Node ID", entity.node_id || ""]);
        fields.push(["Type", graphFriendlyLabel(entity.type || "")]);
        if (isSummaryNode) {
            fields.push(["Summary", "collapsed cluster"]);
            fields.push(["Members", graphPropertyValue(entity, "member_count") || ""]);
            fields.push(["Examples", (graphPropertyValue(entity, "sample_labels") || []).join(", ")]);
            fields.push(["Expanded", graphWorkspaceState.expandedSummaryIds[String(entity.node_id || "")] ? "yes" : "no"]);
        }
    } else {
        const fromNode = graphFindEntity("node", entity.from_node_id);
        const toNode = graphFindEntity("node", entity.to_node_id);
        detailCaption.textContent = `${graphFriendlyLabel(entity.type)}: ${(fromNode?.label || entity.from_node_id || "")} -> ${(toNode?.label || entity.to_node_id || "")}`;
        fields.push(["Edge ID", entity.edge_id || ""]);
        fields.push(["Type", graphFriendlyLabel(entity.type || "")]);
        fields.push(["From", fromNode?.label || entity.from_node_id || ""]);
        fields.push(["To", toNode?.label || entity.to_node_id || ""]);
        if (isAggregateEdge) {
            fields.push(["Aggregate Count", graphPropertyValue(entity, "aggregate_count") || ""]);
            fields.push(["Edge Types", (graphPropertyValue(entity, "edge_types") || []).join(", ")]);
        }
    }
    fields.push(["Confidence", entity.confidence ?? ""]);
    fields.push(["Provenance", GRAPH_SOURCE_KIND_LABELS[String(entity.source_kind || "").trim().toLowerCase()] || graphFriendlyLabel(entity.source_kind || "")]);
    fields.push(["First Seen", entity.first_seen || ""]);
    fields.push(["Last Seen", entity.last_seen || ""]);
    fields.push(["Source Ref", entity.source_ref || ""]);

    fields.forEach(([label, value]) => {
        if (value === undefined || value === null || value === "") {
            return;
        }
        const dt = document.createElement("dt");
        dt.textContent = label;
        const dd = document.createElement("dd");
        dd.textContent = String(value);
        fieldsNode.appendChild(dt);
        fieldsNode.appendChild(dd);
    });

    [
        kind === "node" ? graphFriendlyLabel(entity.type || "") : graphFriendlyLabel(entity.type || ""),
        GRAPH_SOURCE_KIND_LABELS[String(entity.source_kind || "").trim().toLowerCase()] || graphFriendlyLabel(entity.source_kind || ""),
        `${Math.round(Number(entity.confidence || 0))}% confidence`,
    ].forEach((text) => {
        const badge = document.createElement("span");
        badge.className = "graph-badge";
        badge.textContent = text;
        badgesNode.appendChild(badge);
    });
    if (kind === "node" && graphWorkspaceState.pinnedNodeIds[String(entity.node_id || "")]) {
        const badge = document.createElement("span");
        badge.className = "graph-badge graph-badge-pinned";
        badge.textContent = "pinned";
        badgesNode.appendChild(badge);
    }
    if (isSummaryNode) {
        const badge = document.createElement("span");
        badge.className = "graph-badge";
        badge.textContent = "summary";
        badgesNode.appendChild(badge);
    }
    if (isAggregateEdge) {
        const badge = document.createElement("span");
        badge.className = "graph-badge";
        badge.textContent = `${graphPropertyValue(entity, "aggregate_count") || 0} merged edges`;
        badgesNode.appendChild(badge);
    }

    const evidence = Array.isArray(entity.evidence_refs) ? entity.evidence_refs : [];
    if (!evidence.length) {
        const li = document.createElement("li");
        li.textContent = "No explicit evidence refs";
        evidenceNode.appendChild(li);
    } else {
        evidence.forEach((value) => {
            const li = document.createElement("li");
            li.textContent = String(value || "");
            evidenceNode.appendChild(li);
        });
    }

    const displayProperties = entity.properties && typeof entity.properties === "object"
        ? JSON.parse(JSON.stringify(entity.properties))
        : {};
    if (Array.isArray(displayProperties.member_node_ids) && displayProperties.member_node_ids.length > 24) {
        displayProperties.member_node_ids = [`${displayProperties.member_node_ids.length} members hidden from inline view`];
    }
    propertiesNode.textContent = JSON.stringify(displayProperties, null, 2);

    const annotations = (graphWorkspaceState.annotations || []).filter((item) => {
        return String(item?.target_kind || "") === kind && String(item?.target_ref || "") === ref;
    });
    if (!annotations.length) {
        const empty = document.createElement("p");
        empty.className = "text-muted";
        empty.textContent = "No notes yet.";
        annotationsNode.appendChild(empty);
    } else {
        annotations.forEach((item) => {
            const card = document.createElement("article");
            card.className = "graph-annotation-card";
            const heading = document.createElement("div");
            heading.className = "graph-annotation-meta";
            heading.textContent = `${item.created_by || "operator"} | ${item.updated_at || item.created_at || ""}`;
            const body = document.createElement("div");
            body.className = "graph-annotation-body";
            body.textContent = item.body || "";
            card.appendChild(heading);
            card.appendChild(body);
            annotationsNode.appendChild(card);
        });
    }

    if (kind === "node" && entityType === "host" && relatedHostId > 0) {
        hostActionsBlock.hidden = false;
        ["rescan", "refresh-screenshots", "dig-deeper", "remove"].forEach((action) => {
            const button = buildHostActionButton(action, relatedHostId);
            button.addEventListener("click", async () => {
                await handleHostActionButtonAction(button);
            });
            hostActionsNode.appendChild(button);
        });
    }

    if (kind === "node" && entityType === "port") {
        const context = graphToolLaunchContextForEntity(entity);
        if (context) {
            portActionsBlock.hidden = false;
            const deleteButton = document.createElement("button");
            deleteButton.type = "button";
            deleteButton.className = "icon-btn icon-btn-danger";
            deleteButton.title = "Delete Port";
            deleteButton.setAttribute("aria-label", "Delete Port");
            deleteButton.innerHTML = '<i class="fa-solid fa-trash" aria-hidden="true"></i>';
            deleteButton.addEventListener("click", async () => {
                await deleteGraphPortAction(context);
            });
            portActionsNode.appendChild(deleteButton);
            portActionsNode.appendChild(buildGraphToolMenu(context));
        }
    }

    if (kind === "node" && entityType === "service") {
        const context = graphToolLaunchContextForEntity(entity);
        if (context) {
            serviceActionsBlock.hidden = false;
            const deleteButton = document.createElement("button");
            deleteButton.type = "button";
            deleteButton.className = "icon-btn icon-btn-danger";
            deleteButton.title = "Delete Service";
            deleteButton.setAttribute("aria-label", "Delete Service");
            deleteButton.innerHTML = '<i class="fa-solid fa-trash" aria-hidden="true"></i>';
            deleteButton.addEventListener("click", async () => {
                await deleteGraphServiceAction(context);
            });
            serviceActionsNode.appendChild(deleteButton);
            serviceActionsNode.appendChild(buildGraphToolMenu(context));
        }
    }

    if (kind === "node" && entityType === "subnet") {
        const subnetValue = String(graphPropertyValue(entity, "cidr") || entity.label || "").trim();
        if (subnetValue) {
            subnetActionsBlock.hidden = false;
            const button = buildSubnetActionButton("rescan", subnetValue);
            button.addEventListener("click", async () => {
                await handleSubnetActionButtonAction(button);
            });
            subnetActionsNode.appendChild(button);
        }
    }

    if (kind === "node" && entityType === "screenshot") {
        const screenshotPayload = {
            hostId: relatedHostId,
            port: String(graphPropertyValue(entity, "port") || "").trim(),
            protocol: String(graphPropertyValue(entity, "protocol") || "tcp").trim().toLowerCase() || "tcp",
            artifactRef: String(graphPropertyValue(entity, "artifact_ref") || "").trim(),
            filename: String(graphPropertyValue(entity, "filename") || entity.label || "").trim(),
        };
        if (screenshotPayload.hostId > 0) {
            screenshotActionsBlock.hidden = false;
            ["refresh", "delete"].forEach((action) => {
                const button = buildScreenshotActionButton(action, screenshotPayload);
                button.addEventListener("click", async () => {
                    await handleScreenshotActionButtonAction(button);
                });
                screenshotActionsNode.appendChild(button);
            });
        }
    }

    noteButton.disabled = false;
    noteButton.setAttribute("title", "Add Note");
    noteButton.setAttribute("aria-label", "Add Note");
    pinButton.disabled = kind !== "node" || isSummaryNode;
    const nodePinned = kind === "node" && Boolean(graphWorkspaceState.pinnedNodeIds[String(entity.node_id || "")]);
    pinButton.classList.toggle("is-active", nodePinned);
    if (kind !== "node") {
        pinButton.setAttribute("title", "Pinning is available for nodes only");
        pinButton.setAttribute("aria-label", "Pinning is available for nodes only");
    } else if (isSummaryNode) {
        pinButton.setAttribute("title", "Summary nodes cannot be pinned");
        pinButton.setAttribute("aria-label", "Summary nodes cannot be pinned");
    } else {
        pinButton.setAttribute("title", nodePinned ? "Unpin Node" : "Pin Node");
        pinButton.setAttribute("aria-label", nodePinned ? "Unpin Node" : "Pin Node");
    }
    if (isSummaryNode) {
        graphRenderRelatedContent("Summary nodes do not have direct related content. Expand or focus the cluster to inspect individual artifacts.");
    } else {
        graphRenderRelatedContent();
    }
    graphRefreshSelectionActionButtons();
    graphSyncDetailPresentation();
}

function graphRenderRelatedContent(statusMessage = "") {
    const listNode = document.getElementById("graph-detail-content-list");
    const statusNode = document.getElementById("graph-detail-content-status");
    if (!listNode || !statusNode) {
        return;
    }
    listNode.innerHTML = "";
    const entries = Array.isArray(graphWorkspaceState.relatedContent) ? graphWorkspaceState.relatedContent : [];
    const fallback = statusMessage || "No related artifacts or screenshots.";
    if (!entries.length) {
        statusNode.textContent = fallback;
        graphSyncDetailPresentation();
        return;
    }
    statusNode.textContent = `${entries.length} related item${entries.length === 1 ? "" : "s"}`;
    entries.forEach((entry) => {
        const card = document.createElement("article");
        card.className = "graph-content-card";

        const header = document.createElement("div");
        header.className = "graph-content-header";
        const title = document.createElement("strong");
        title.textContent = entry.label || entry.filename || entry.node_id || "artifact";
        header.appendChild(title);
        const kind = document.createElement("span");
        kind.className = "graph-content-kind";
        kind.textContent = graphFriendlyLabel(entry.kind || entry.node_type || "artifact");
        header.appendChild(kind);
        card.appendChild(header);

        const meta = document.createElement("div");
        meta.className = "graph-content-meta";
        meta.textContent = entry.ref || entry.filename || "";
        card.appendChild(meta);

        if (entry.kind === "image" && entry.preview_url) {
            const image = document.createElement("img");
            image.className = "graph-content-image";
            image.src = `${entry.preview_url}${entry.preview_url.includes("?") ? "&" : "?"}t=${Date.now()}`;
            image.alt = entry.filename || entry.label || "Graph artifact preview";
            image.addEventListener("click", () => {
                openScreenshotModal(entry.preview_url, entry.filename || entry.label || "screenshot.png", "");
            });
            card.appendChild(image);
        } else if (entry.kind === "text") {
            const preview = document.createElement("pre");
            preview.className = "graph-content-text";
            preview.textContent = String(entry.preview_text || entry.message || "").trim() || "No text preview available.";
            card.appendChild(preview);
        } else {
            const message = document.createElement("p");
            message.className = "text-muted";
            message.textContent = entry.message || "Preview unavailable.";
            card.appendChild(message);
        }

        const actions = document.createElement("div");
        actions.className = "graph-content-actions host-actions";
        const copyButton = document.createElement("button");
        copyButton.type = "button";
        copyButton.className = "icon-btn";
        copyButton.title = "Copy";
        copyButton.setAttribute("aria-label", "Copy");
        copyButton.innerHTML = '<i class="fa-solid fa-copy" aria-hidden="true"></i>';
        copyButton.addEventListener("click", async () => {
            if (entry.kind === "image" && entry.preview_url) {
                screenshotModalState.url = String(entry.preview_url || "");
                screenshotModalState.filename = String(entry.filename || "screenshot.png");
                screenshotModalState.port = "";
                await copyScreenshotAction();
                return;
            }
            await copyTextToClipboard(
                String(entry.preview_text || entry.ref || ""),
                `${entry.filename || entry.label || "Artifact"} copied to clipboard`,
                "Nothing to copy",
            );
        });
        actions.appendChild(copyButton);

        const downloadButton = document.createElement("button");
        downloadButton.type = "button";
        downloadButton.className = "icon-btn";
        downloadButton.title = "Download";
        downloadButton.setAttribute("aria-label", "Download");
        downloadButton.innerHTML = '<i class="fa-solid fa-download" aria-hidden="true"></i>';
        downloadButton.addEventListener("click", () => {
            if (entry.download_url) {
                window.location.assign(`${entry.download_url}${entry.download_url.includes("?") ? "&" : "?"}t=${Date.now()}`);
            }
        });
        actions.appendChild(downloadButton);

        if (entry.kind === "image" && entry.preview_url) {
            const openButton = document.createElement("button");
            openButton.type = "button";
            openButton.className = "icon-btn";
            openButton.title = "Open";
            openButton.setAttribute("aria-label", "Open");
            openButton.innerHTML = '<i class="fa-solid fa-up-right-from-square" aria-hidden="true"></i>';
            openButton.addEventListener("click", () => {
                openScreenshotModal(entry.preview_url, entry.filename || entry.label || "screenshot.png", "");
            });
            actions.appendChild(openButton);
        } else if (entry.kind === "text") {
            const openButton = document.createElement("button");
            openButton.type = "button";
            openButton.className = "icon-btn";
            openButton.title = "Open";
            openButton.setAttribute("aria-label", "Open");
            openButton.innerHTML = '<i class="fa-solid fa-up-right-from-square" aria-hidden="true"></i>';
            openButton.addEventListener("click", () => {
                openTextPreviewModal({
                    title: "Artifact Preview",
                    meta: entry.filename || entry.ref || "Artifact preview",
                    command: entry.ref || "",
                    output: entry.preview_text || "",
                    downloadName: entry.filename || "artifact.txt",
                });
            });
            actions.appendChild(openButton);
        }

        card.appendChild(actions);
        listNode.appendChild(card);
    });
    graphSyncDetailPresentation();
}

async function graphFetchRelatedContent() {
    const kind = String(graphWorkspaceState.selectedKind || "");
    const ref = String(graphWorkspaceState.selectedRef || "");
    const entity = kind === "node" ? graphSelectedNodeEntity() : null;
    if (!kind || !ref || kind !== "node") {
        graphWorkspaceState.relatedContent = [];
        graphRenderRelatedContent("No related artifacts or screenshots.");
        return;
    }
    if (!entity) {
        graphWorkspaceState.relatedContent = [];
        graphRenderRelatedContent("No related artifacts or screenshots.");
        return;
    }
    if (graphPropertyValue(entity, "summary_kind")) {
        graphWorkspaceState.relatedContent = [];
        graphRenderRelatedContent("Summary nodes do not have direct related content. Expand or focus the cluster to inspect individual artifacts.");
        return;
    }
    const requestId = Number(graphWorkspaceState.contentRequestId || 0) + 1;
    graphWorkspaceState.contentRequestId = requestId;
    graphWorkspaceState.relatedContent = [];
    graphRenderRelatedContent("Loading related content...");
    try {
        const payload = await fetchJson(`/api/graph/nodes/${encodeURIComponent(ref)}/content?max_chars=20000`);
        if (requestId !== graphWorkspaceState.contentRequestId) {
            return;
        }
        graphWorkspaceState.relatedContent = Array.isArray(payload?.entries) ? payload.entries : [];
        graphRenderRelatedContent();
    } catch (err) {
        if (requestId !== graphWorkspaceState.contentRequestId) {
            return;
        }
        graphWorkspaceState.relatedContent = [];
        graphRenderRelatedContent(`Related content load failed: ${err.message}`);
    }
}

function graphRenderMatrixView(filtered) {
    const container = document.getElementById("graph-matrix-view");
    if (!container) {
        return;
    }
    const matrix = filtered?.matrix || {};
    const groups = Array.isArray(matrix.groups) ? matrix.groups : [];
    const values = Array.isArray(matrix.values) ? matrix.values : [];
    const maxValue = Math.max(1, Number(matrix.maxValue || 0));
    container.innerHTML = "";
    if (!groups.length || !values.length) {
        const empty = document.createElement("p");
        empty.className = "text-muted";
        empty.textContent = "No dense matrix data is available for the current filters.";
        container.appendChild(empty);
        return;
    }

    const note = document.createElement("p");
    note.className = "graph-matrix-note";
    note.textContent = "Dense matrix fallback: group-to-group relationship intensity";
    container.appendChild(note);

    const table = document.createElement("table");
    table.className = "graph-matrix-table";
    const thead = document.createElement("thead");
    const headRow = document.createElement("tr");
    const corner = document.createElement("th");
    corner.textContent = "Source";
    headRow.appendChild(corner);
    groups.forEach((group) => {
        const th = document.createElement("th");
        th.textContent = group.label || group.key || "";
        th.title = `${group.label || group.key || ""} (${group.nodeCount || 0} nodes)`;
        headRow.appendChild(th);
    });
    thead.appendChild(headRow);
    table.appendChild(thead);

    const tbody = document.createElement("tbody");
    groups.forEach((rowGroup, rowIndex) => {
        const row = document.createElement("tr");
        const rowLabel = document.createElement("th");
        rowLabel.textContent = rowGroup.label || rowGroup.key || "";
        rowLabel.title = `${rowGroup.label || rowGroup.key || ""} (${rowGroup.nodeCount || 0} nodes)`;
        row.appendChild(rowLabel);
        groups.forEach((columnGroup, columnIndex) => {
            const count = Number(values?.[rowIndex]?.[columnIndex] || 0);
            const intensity = count > 0 ? Math.max(0.08, Math.min(1, count / maxValue)) : 0;
            const cell = document.createElement("td");
            cell.className = "graph-matrix-cell";
            cell.title = `${rowGroup.label || rowGroup.key || ""} -> ${columnGroup.label || columnGroup.key || ""}: ${count}`;
            cell.style.background = count > 0
                ? `rgba(126, 227, 203, ${Math.max(0.12, intensity * 0.88)})`
                : "rgba(255, 255, 255, 0.03)";
            cell.textContent = count > 0 ? String(count) : "";
            row.appendChild(cell);
        });
        tbody.appendChild(row);
    });
    table.appendChild(tbody);
    container.appendChild(table);
}

function graphRenderWorkspace({preserveDetail = false} = {}) {
    const svg = document.getElementById("graph-workspace-canvas");
    const emptyNode = document.getElementById("graph-workspace-empty");
    const matrixNode = document.getElementById("graph-matrix-view");
    if (!svg || !emptyNode || !matrixNode) {
        return;
    }
    const filtered = graphApplyLocalFilters(graphWorkspaceState.data);
    graphWorkspaceState.filtered = filtered;
    const nodes = filtered.nodes || [];
    const edges = filtered.edges || [];
    const positions = filtered.positions || {};

    let selectionCleared = false;
    const selectedEntity = graphWorkspaceState.selectedKind === "node"
        ? graphSelectedNodeEntity()
        : graphFindEntity(graphWorkspaceState.selectedKind, graphWorkspaceState.selectedRef);
    if (graphWorkspaceState.selectedKind && !selectedEntity) {
        graphWorkspaceState.selectedKind = "";
        graphWorkspaceState.selectedRef = "";
        graphWorkspaceState.selectedPayload = null;
        graphWorkspaceState.relatedContent = [];
        selectionCleared = true;
    }

    setText(
        "graph-workspace-summary",
        `${nodes.length} visible nodes | ${edges.length} visible edges | ${Number(filtered?.meta?.baseNodeCount || graphWorkspaceState.data?.meta?.total_nodes || nodes.length)} filtered nodes`
        + `${filtered?.meta?.summaryUsed ? " | summary mode" : ""}`
        + `${filtered?.renderKind === "matrix" ? " | matrix fallback" : ""}`
        + `${filtered?.meta?.focusActive ? ` | focus ${filtered.meta.focusDepth} hop` : ""}`,
    );

    if (!nodes.length) {
        matrixNode.hidden = true;
        svg.innerHTML = "";
        svg.setAttribute("viewBox", "0 0 1600 900");
        svg.style.width = "1180px";
        svg.style.height = "620px";
        svg.hidden = false;
        emptyNode.hidden = false;
        graphRenderSelectionDetail();
        graphSyncDetailPresentation();
        return;
    }

    emptyNode.hidden = true;
    if (filtered.renderKind === "matrix") {
        svg.hidden = true;
        matrixNode.hidden = false;
        graphRenderMatrixView(filtered);
        if (!preserveDetail || selectionCleared || !graphWorkspaceState.selectedKind) {
            graphRenderSelectionDetail();
        }
        graphSyncDetailPresentation();
        return;
    }

    matrixNode.hidden = true;
    matrixNode.innerHTML = "";
    svg.hidden = false;
    svg.innerHTML = "";
    svg.setAttribute("viewBox", `0 0 ${filtered.width} ${filtered.height}`);
    const zoomScale = Math.max(10, Math.min(200, Number(graphWorkspaceState.zoomPercent || 70))) / 100;
    svg.style.width = `${Math.max(1180, Math.round(filtered.width * zoomScale))}px`;
    svg.style.height = `${Math.max(620, Math.round(filtered.height * zoomScale))}px`;

    const defs = graphCreateSvgNode("defs");
    defs.appendChild(graphCreateSvgNode("marker", {
        id: "graph-arrow",
        markerWidth: 8,
        markerHeight: 8,
        refX: 7,
        refY: 4,
        orient: "auto",
        markerUnits: "strokeWidth",
    }));
    const arrow = graphCreateSvgNode("path", {
        d: "M0,0 L8,4 L0,8 z",
        fill: "rgba(121, 133, 158, 0.65)",
    });
    defs.firstChild.appendChild(arrow);
    defs.appendChild(graphCreateSvgNode("marker", {
        id: "graph-arrow-highlight",
        markerWidth: 9,
        markerHeight: 9,
        refX: 8,
        refY: 4.5,
        orient: "auto",
        markerUnits: "strokeWidth",
    }));
    const highlightArrow = graphCreateSvgNode("path", {
        d: "M0,0 L9,4.5 L0,9 z",
        fill: GRAPH_EDGE_HIGHLIGHT_COLOR,
    });
    defs.lastChild.appendChild(highlightArrow);
    svg.appendChild(defs);

    (filtered.groups || []).forEach((group) => {
        const groupNode = graphCreateSvgNode("g", {
            "class": "graph-group",
            "data-graph-group-key": group.key || "",
        });
        groupNode.appendChild(graphCreateSvgNode("rect", {
            x: group.x,
            y: group.y,
            width: group.width,
            height: group.height,
            rx: 18,
            fill: opaqueUiEnabled() ? "#14172d" : "rgba(14, 18, 38, 0.55)",
            stroke: "rgba(147, 159, 229, 0.16)",
            "data-graph-group-key": group.key || "",
        }));
        groupNode.appendChild(graphCreateSvgNode("text", {
            x: group.x + 16,
            y: group.y + 28,
            "class": "graph-group-label",
            "data-graph-group-key": group.key || "",
        }, group.label));
        svg.appendChild(groupNode);
    });

    const selectedNodeId = graphWorkspaceState.selectedKind === "node"
        ? String(graphWorkspaceState.selectedRef || "")
        : "";
    const selectedEdgeId = graphWorkspaceState.selectedKind === "edge"
        ? String(graphWorkspaceState.selectedRef || "")
        : "";
    const orderedEdges = [...edges].sort((left, right) => {
        const leftId = String(left?.edge_id || "");
        const rightId = String(right?.edge_id || "");
        const leftPriority = selectedEdgeId && leftId === selectedEdgeId
            ? 2
            : (selectedNodeId && (String(left?.from_node_id || "") === selectedNodeId || String(left?.to_node_id || "") === selectedNodeId) ? 1 : 0);
        const rightPriority = selectedEdgeId && rightId === selectedEdgeId
            ? 2
            : (selectedNodeId && (String(right?.from_node_id || "") === selectedNodeId || String(right?.to_node_id || "") === selectedNodeId) ? 1 : 0);
        return leftPriority - rightPriority;
    });

    orderedEdges.forEach((edge) => {
        const sourcePosition = positions[String(edge?.from_node_id || "")];
        const targetPosition = positions[String(edge?.to_node_id || "")];
        if (!sourcePosition || !targetPosition) {
            return;
        }
        const startX = sourcePosition.x + GRAPH_NODE_SIZE.width;
        const startY = sourcePosition.y + (GRAPH_NODE_SIZE.height / 2);
        const endX = targetPosition.x;
        const endY = targetPosition.y + (GRAPH_NODE_SIZE.height / 2);
        const controlOffset = Math.max(36, Math.min(140, Math.abs(endX - startX) / 2));
        const curveDirection = endX >= startX ? 1 : -1;
        const pathData = [
            `M ${startX} ${startY}`,
            `C ${startX + (controlOffset * curveDirection)} ${startY}`,
            `${endX - (controlOffset * curveDirection)} ${endY}`,
            `${endX} ${endY}`,
        ].join(" ");
        const edgeId = String(edge?.edge_id || "");
        const isSelected = selectedEdgeId && selectedEdgeId === edgeId;
        const isConnectedToSelectedNode = Boolean(
            selectedNodeId
            && (String(edge?.from_node_id || "") === selectedNodeId || String(edge?.to_node_id || "") === selectedNodeId)
        );
        const style = graphSourceStyle(edge);
        const aggregateCount = Math.max(1, Number(graphPropertyValue(edge, "aggregate_count") || 1));
        const strokeWidth = isSelected
            ? 4.2
            : (isConnectedToSelectedNode ? Math.min(6.8, 2.5 + Math.log2(aggregateCount + 1)) : Math.min(4.2, 1.05 + (Math.log2(aggregateCount + 1) * 0.7)));
        const opacity = isSelected
            ? 1
            : (isConnectedToSelectedNode ? 0.98 : Math.max(0.18, Math.min(0.34, 0.16 + (Math.log2(aggregateCount + 1) * 0.045))));
        const stroke = isSelected
            ? "#eef1ff"
            : (isConnectedToSelectedNode ? GRAPH_EDGE_HIGHLIGHT_COLOR : graphEdgeStrokeColor(edge));
        const markerEnd = isSelected || isConnectedToSelectedNode
            ? "url(#graph-arrow-highlight)"
            : "url(#graph-arrow)";
        svg.appendChild(graphCreateSvgNode("path", {
            d: pathData,
            stroke: "transparent",
            fill: "none",
            "stroke-width": 12,
            "data-graph-edge-id": edge.edge_id || "",
            "class": "graph-edge-hitbox",
        }));
        svg.appendChild(graphCreateSvgNode("path", {
            d: pathData,
            stroke,
            fill: "none",
            "stroke-width": strokeWidth,
            "stroke-dasharray": style.dash,
            "marker-end": markerEnd,
            opacity,
            "data-graph-edge-id": edge.edge_id || "",
            "class": `graph-edge${isSelected ? " is-selected" : ""}${isConnectedToSelectedNode ? " is-connected-selected" : ""}`,
        }));
    });

    nodes.forEach((node) => {
        const nodeId = String(node?.node_id || "");
        const point = positions[nodeId];
        if (!point) {
            return;
        }
        const style = graphSourceStyle(node);
        const color = graphNodeColor(node);
        const isSelected = graphWorkspaceState.selectedKind === "node" && String(graphWorkspaceState.selectedRef || "") === nodeId;
        const isHostSelected = graphNodeMatchesSelectedHost(node);
        const isSummaryNode = Boolean(graphPropertyValue(node, "summary_kind"));
        const groupNode = graphCreateSvgNode("g", {
            transform: `translate(${point.x}, ${point.y})`,
            "data-graph-node-id": nodeId,
            "class": `graph-node${isSelected ? " is-selected" : ""}${isHostSelected ? " is-host-selected" : ""}${isSummaryNode ? " is-summary" : ""}`,
        });
        groupNode.appendChild(graphCreateSvgNode("rect", {
            width: GRAPH_NODE_SIZE.width,
            height: GRAPH_NODE_SIZE.height,
            rx: 14,
            fill: graphNodeFillColor(node),
            stroke: isSelected ? "#eef1ff" : color,
            "stroke-width": isSelected ? 2.8 : 1.8,
            "data-graph-node-id": nodeId,
        }));
        groupNode.appendChild(graphCreateSvgNode("rect", {
            x: 10,
            y: 9,
            width: 8,
            height: GRAPH_NODE_SIZE.height - 18,
            rx: 4,
            fill: color,
            opacity: 0.9,
            "data-graph-node-id": nodeId,
        }));
        groupNode.appendChild(graphCreateSvgNode("text", {
            x: 28,
            y: 18,
            "class": "graph-node-type",
            "data-graph-node-id": nodeId,
        }, graphFriendlyLabel(node.type || "")));
        const labelNode = graphCreateSvgNode("text", {
            x: 28,
            y: 34,
            "class": "graph-node-label",
            "data-graph-node-id": nodeId,
        });
        graphSplitLabel(node.label || nodeId).forEach((line, index) => {
            const tspan = graphCreateSvgNode("tspan", {
                x: 28,
                dy: index === 0 ? 0 : 14,
                "data-graph-node-id": nodeId,
            }, line);
            labelNode.appendChild(tspan);
        });
        groupNode.appendChild(labelNode);
        if (graphWorkspaceState.pinnedNodeIds[nodeId]) {
            groupNode.appendChild(graphCreateSvgNode("circle", {
                cx: GRAPH_NODE_SIZE.width - 16,
                cy: 14,
                r: 5,
                fill: "#eef1ff",
                opacity: 0.9,
                "data-graph-node-id": nodeId,
            }));
        }
        if (isSummaryNode) {
            groupNode.appendChild(graphCreateSvgNode("circle", {
                cx: GRAPH_NODE_SIZE.width - 16,
                cy: GRAPH_NODE_SIZE.height - 14,
                r: 7,
                fill: color,
                opacity: 0.95,
                "data-graph-node-id": nodeId,
            }));
        }
        svg.appendChild(groupNode);
    });

    if (!preserveDetail || selectionCleared || !graphWorkspaceState.selectedKind) {
        graphRenderSelectionDetail();
    }
    graphSyncDetailPresentation();
}

function graphSelectEntity(kind, ref) {
    const entity = kind === "node" ? graphFindEntity("node", ref) : graphFindEntity("edge", ref);
    const relatedHostId = kind === "node" ? graphEntityHostId(entity) : 0;
    if (relatedHostId > 0) {
        const hostChanged = String(workspaceState.selectedHostId || "") !== String(relatedHostId);
        workspaceState.selectedHostId = relatedHostId;
        renderHostSelectionState({syncGraph: false});
        if (hostChanged || !workspaceState.hostDetail) {
            workspaceState.hostDetail = null;
            loadHostDetail(relatedHostId).catch((err) => {
                setWorkspaceStatus(`Load host detail failed: ${err.message}`, true);
            });
        }
    }
    graphWorkspaceState.selectedKind = String(kind || "");
    graphWorkspaceState.selectedRef = String(ref || "");
    graphWorkspaceState.selectedPayload = null;
    graphWorkspaceState.relatedContent = [];
    graphRenderWorkspace();
    graphFetchRelatedContent().catch(() => {});
}

async function graphLoadMetadata({force = false} = {}) {
    if (!graphWorkspaceEnabled()) {
        return;
    }
    if (graphWorkspaceState.metadataLoaded && !force) {
        graphRenderLayoutOptions();
        return;
    }
    const [layoutsBody, annotationsBody] = await Promise.all([
        fetchJson("/api/graph/layouts"),
        fetchJson("/api/graph/annotations"),
    ]);
    graphWorkspaceState.layouts = Array.isArray(layoutsBody?.layouts) ? layoutsBody.layouts : [];
    graphWorkspaceState.annotations = Array.isArray(annotationsBody?.annotations) ? annotationsBody.annotations : [];
    graphWorkspaceState.metadataLoaded = true;
    const currentViewId = String(getValue("graph-view-select") || graphWorkspaceState.viewId || "attack_surface").trim();
    if (!graphWorkspaceState.activeLayoutId) {
        const defaultLayout = graphWorkspaceState.layouts.find((item) => {
            return String(item?.view_id || "") === currentViewId && String(item?.name || "").trim().toLowerCase() === "default";
        }) || graphWorkspaceState.layouts.find((item) => String(item?.view_id || "") === currentViewId);
        graphWorkspaceState.activeLayoutId = String(defaultLayout?.layout_id || "");
        if (defaultLayout?.layout?.positions && typeof defaultLayout.layout.positions === "object") {
            graphWorkspaceState.positions = {...defaultLayout.layout.positions};
        }
        if (defaultLayout?.layout?.pinned_node_ids && typeof defaultLayout.layout.pinned_node_ids === "object") {
            graphWorkspaceState.pinnedNodeIds = {...defaultLayout.layout.pinned_node_ids};
        }
    }
    graphRenderLayoutOptions();
}

async function graphLoadSnapshot({background = false, forceMetadata = false} = {}) {
    if (!graphWorkspaceEnabled()) {
        return;
    }
    if (graphWorkspaceState.loading) {
        graphWorkspaceState.needsRefresh = true;
        return;
    }
    graphWorkspaceState.loading = true;
    if (!background) {
        setGraphStatus("Loading graph...");
    }
    try {
        if (!graphWorkspaceState.metadataLoaded || forceMetadata) {
            await graphLoadMetadata({force: forceMetadata});
        }
        const filters = graphCollectServerQuery();
        const params = new URLSearchParams();
        params.set("filter", String(filters.hostFilter || "hide_down"));
        if (filters.hostId > 0) {
            params.set("host_id", String(filters.hostId));
        }
        if (filters.nodeType) {
            params.set("node_type", filters.nodeType);
        }
        if (filters.edgeType) {
            params.set("edge_type", filters.edgeType);
        }
        if (filters.sourceKind) {
            params.set("source_kind", filters.sourceKind);
        }
        if (filters.search) {
            params.set("q", filters.search);
        }
        if (filters.minConfidence > 0) {
            params.set("min_confidence", String(filters.minConfidence));
        }
        if (filters.hideAiSuggested) {
            params.set("hide_ai_suggested", "true");
        }
        if (filters.hideNmapXmlArtifacts) {
            params.set("hide_nmap_xml_artifacts", "true");
        }
        params.set("limit_nodes", "8000");
        params.set("limit_edges", "24000");
        const body = await fetchJson(`/api/graph?${params.toString()}`);
        graphWorkspaceState.data = {
            nodes: Array.isArray(body?.nodes) ? body.nodes : [],
            edges: Array.isArray(body?.edges) ? body.edges : [],
            meta: body?.meta || {},
        };
        graphPopulateDynamicFilters();
        graphRenderLayoutOptions();
        graphRenderWorkspace({preserveDetail: background && Boolean(graphWorkspaceState.selectedKind)});
        if (
            graphWorkspaceState.selectedKind === "node"
            && graphWorkspaceState.selectedRef
            && (!background || !Array.isArray(graphWorkspaceState.relatedContent) || !graphWorkspaceState.relatedContent.length)
        ) {
            graphFetchRelatedContent().catch(() => {});
        }
        if (!background) {
            setGraphStatus(`Graph loaded: ${graphWorkspaceState.filtered.nodes.length} nodes, ${graphWorkspaceState.filtered.edges.length} edges`);
        }
    } catch (err) {
        setGraphStatus(`Graph load failed: ${err.message}`, true);
    } finally {
        graphWorkspaceState.loading = false;
        if (graphWorkspaceState.needsRefresh) {
            graphWorkspaceState.needsRefresh = false;
            graphLoadSnapshot({background: true}).catch(() => {});
        }
    }
}

function graphScheduleRefresh(delayMs = 900) {
    if (!graphWorkspaceEnabled()) {
        return;
    }
    if (graphWorkspaceState.refreshTimer) {
        window.clearTimeout(graphWorkspaceState.refreshTimer);
    }
    graphWorkspaceState.refreshTimer = window.setTimeout(() => {
        graphWorkspaceState.refreshTimer = null;
        graphLoadSnapshot({background: true}).catch(() => {});
    }, Math.max(100, Number(delayMs) || 900));
}

async function graphRefreshAction() {
    await graphLoadSnapshot({background: false});
}

async function graphRebuildAction() {
    const hostId = parseInt(getValue("graph-host-filter"), 10);
    setGraphStatus("Rebuilding graph...");
    try {
        const body = await postJson("/api/graph/rebuild", {
            host_id: Number.isFinite(hostId) && hostId > 0 ? hostId : 0,
        });
        setGraphStatus(`Graph rebuilt: ${Number(body?.mutation_count || 0)} mutations`);
        await graphLoadSnapshot({background: false, forceMetadata: true});
    } catch (err) {
        setGraphStatus(`Graph rebuild failed: ${err.message}`, true);
    }
}

function graphExportAction(format) {
    const normalized = String(format || "json").trim().toLowerCase();
    if (normalized === "graphml") {
        window.location.assign(`/api/graph/export/graphml?t=${Date.now()}`);
        return;
    }
    window.location.assign(`/api/graph/export/json?t=${Date.now()}`);
}

function graphDownloadBlob(blob, filename) {
    const objectUrl = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = objectUrl;
    anchor.download = String(filename || "graph-export").replace(/[^a-zA-Z0-9._-]+/g, "-");
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
}

function graphExportFilename(extension) {
    const viewId = String(getValue("graph-view-select") || graphWorkspaceState.viewId || "attack_surface").trim() || "attack_surface";
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    return `legion-graph-${viewId}-${stamp}.${String(extension || "txt").replace(/^\./, "")}`;
}

function graphBuildExportSvgString() {
    if (graphWorkspaceState.filtered?.renderKind === "matrix") {
        throw new Error("Switch Density Mode to graph or summary before exporting SVG or PNG.");
    }
    const svg = document.getElementById("graph-workspace-canvas");
    if (!svg) {
        throw new Error("Graph canvas is unavailable.");
    }
    const clone = svg.cloneNode(true);
    clone.setAttribute("xmlns", "http://www.w3.org/2000/svg");
    clone.setAttribute("xmlns:xlink", "http://www.w3.org/1999/xlink");
    const viewBox = clone.getAttribute("viewBox") || `0 0 ${graphWorkspaceState.filtered.width || 1600} ${graphWorkspaceState.filtered.height || 900}`;
    const parts = viewBox.split(/\s+/).map((value) => Number(value || 0));
    const width = Math.max(1, Math.round(parts[2] || graphWorkspaceState.filtered.width || 1600));
    const height = Math.max(1, Math.round(parts[3] || graphWorkspaceState.filtered.height || 900));
    clone.setAttribute("width", String(width));
    clone.setAttribute("height", String(height));

    const background = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    background.setAttribute("x", "0");
    background.setAttribute("y", "0");
    background.setAttribute("width", String(width));
    background.setAttribute("height", String(height));
    background.setAttribute("fill", "#090014");
    clone.insertBefore(background, clone.firstChild);

    const styleNode = document.createElementNS("http://www.w3.org/2000/svg", "style");
    styleNode.textContent = [
        ".graph-group-label{fill:rgba(180,187,221,0.84);font-size:12px;text-transform:uppercase;letter-spacing:.08em;font-family:system-ui,sans-serif;}",
        ".graph-node-type{fill:rgba(180,187,221,0.92);font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;font-family:system-ui,sans-serif;}",
        ".graph-node-label{fill:#eef1ff;font-size:12px;font-weight:600;font-family:system-ui,sans-serif;}",
    ].join("");
    clone.insertBefore(styleNode, clone.firstChild);
    return `<?xml version="1.0" encoding="UTF-8"?>\n${new XMLSerializer().serializeToString(clone)}`;
}

function graphExportSvgAction() {
    try {
        const svgString = graphBuildExportSvgString();
        graphDownloadBlob(new Blob([svgString], {type: "image/svg+xml;charset=utf-8"}), graphExportFilename("svg"));
        setGraphStatus("Workspace SVG exported");
    } catch (err) {
        setGraphStatus(`SVG export failed: ${err.message}`, true);
    }
}

async function graphExportPngAction() {
    try {
        const svgString = graphBuildExportSvgString();
        const svgBlob = new Blob([svgString], {type: "image/svg+xml;charset=utf-8"});
        const svgUrl = URL.createObjectURL(svgBlob);
        const image = new Image();
        image.decoding = "async";
        const loadPromise = new Promise((resolve, reject) => {
            image.onload = resolve;
            image.onerror = () => reject(new Error("Unable to rasterize graph SVG."));
        });
        image.src = svgUrl;
        await loadPromise;
        const width = Math.max(1, Number(graphWorkspaceState.filtered.width || 1600));
        const height = Math.max(1, Number(graphWorkspaceState.filtered.height || 900));
        const scale = Math.min(1, 12000 / Math.max(width, height));
        const canvas = document.createElement("canvas");
        canvas.width = Math.max(1, Math.round(width * scale));
        canvas.height = Math.max(1, Math.round(height * scale));
        const context = canvas.getContext("2d");
        if (!context) {
            throw new Error("Canvas export is unavailable.");
        }
        context.fillStyle = "#090014";
        context.fillRect(0, 0, canvas.width, canvas.height);
        context.setTransform(scale, 0, 0, scale, 0, 0);
        context.drawImage(image, 0, 0);
        const blob = await new Promise((resolve) => canvas.toBlob(resolve, "image/png"));
        window.setTimeout(() => URL.revokeObjectURL(svgUrl), 1000);
        if (!blob) {
            throw new Error("PNG export failed.");
        }
        graphDownloadBlob(blob, graphExportFilename("png"));
        setGraphStatus("Workspace PNG exported");
    } catch (err) {
        setGraphStatus(`PNG export failed: ${err.message}`, true);
    }
}

function graphApplyLayoutById(layoutId) {
    const selected = (graphWorkspaceState.layouts || []).find((item) => String(item?.layout_id || "") === String(layoutId || ""));
    graphWorkspaceState.activeLayoutId = String(selected?.layout_id || "");
    graphWorkspaceState.positions = selected?.layout?.positions && typeof selected.layout.positions === "object"
        ? {...selected.layout.positions}
        : {};
    graphWorkspaceState.pinnedNodeIds = selected?.layout?.pinned_node_ids && typeof selected.layout.pinned_node_ids === "object"
        ? {...selected.layout.pinned_node_ids}
        : {};
    if (selected?.layout?.group_by) {
        setValue("graph-group-select", selected.layout.group_by);
    }
    if (selected?.name) {
        setValue("graph-layout-name", selected.name);
    }
    graphRenderLayoutOptions();
    graphRenderWorkspace();
}

function graphTidyLayoutAction() {
    const current = graphApplyLocalFilters(graphWorkspaceState.data);
    const groupsMap = new Map();
    (current.nodes || []).forEach((item) => {
        const key = graphGroupKeyForNode(item, graphWorkspaceState.groupBy || graphCurrentViewConfig().defaultGroup || "subnet", graphBuildHostMaps(current.nodes)) || "other";
        if (!groupsMap.has(key)) {
            groupsMap.set(key, []);
        }
        groupsMap.get(key).push(item);
    });
    if (!Array.isArray(current?.nodes) || !current.nodes.length || !groupsMap.size) {
        setGraphStatus("No graph nodes are available to tidy.", true);
        return;
    }
    const tidied = graphComputeCompactLayout(
        current.nodes,
        current.edges,
        groupsMap,
        graphWorkspaceState.groupBy || graphCurrentViewConfig().defaultGroup || "subnet",
        {},
    );
    Object.entries(tidied.positions || {}).forEach(([nodeId, point]) => {
        graphWorkspaceState.positions[nodeId] = {
            x: Number(point?.x) || 0,
            y: Number(point?.y) || 0,
        };
    });
    graphRenderWorkspace({preserveDetail: true});
    setGraphStatus(`Layout tidied for ${current.nodes.length} nodes across ${(tidied.groups || []).length} groups`);
}

function graphFocusSelectionAction() {
    if (graphWorkspaceState.selectedKind !== "node" || !graphWorkspaceState.selectedRef) {
        setGraphStatus("Select a node or summary before focusing the neighborhood.", true);
        graphRefreshSelectionActionButtons();
        return;
    }
    const entity = graphSelectedNodeEntity();
    const seedNodeIds = graphEntityUnderlyingNodeIds(entity);
    if (!seedNodeIds.length) {
        setGraphStatus("The selected graph node cannot be focused.", true);
        graphRefreshSelectionActionButtons();
        return;
    }
    graphWorkspaceState.focusSeedNodeIds = seedNodeIds;
    graphWorkspaceState.focusSeedLabel = String(entity?.label || entity?.node_id || "selection");
    graphWorkspaceState.focusDepth = Math.max(1, Math.min(3, parseInt(getValue("graph-focus-depth-select"), 10) || graphWorkspaceState.focusDepth || 1));
    if (graphPropertyValue(entity, "summary_kind")) {
        graphWorkspaceState.selectedKind = "node";
        graphWorkspaceState.selectedRef = seedNodeIds[0];
    }
    graphRenderWorkspace();
    graphRefreshSelectionActionButtons();
    setGraphStatus(`Focused ${graphWorkspaceState.focusDepth}-hop neighborhood around ${graphWorkspaceState.focusSeedLabel}`);
}

function graphClearFocusAction() {
    if (!graphWorkspaceState.focusSeedNodeIds.length) {
        setGraphStatus("No graph focus is active.", true);
        graphRefreshSelectionActionButtons();
        return;
    }
    graphWorkspaceState.focusSeedNodeIds = [];
    graphWorkspaceState.focusSeedLabel = "";
    graphRenderWorkspace();
    graphRefreshSelectionActionButtons();
    setGraphStatus("Graph focus cleared");
}

function graphToggleExpandSelectionAction() {
    if (graphWorkspaceState.selectedKind !== "node" || !graphWorkspaceState.selectedRef) {
        setGraphStatus("Select a summary node before expanding it.", true);
        graphRefreshSelectionActionButtons();
        return;
    }
    const entity = graphSelectedNodeEntity();
    if (!graphPropertyValue(entity, "summary_kind")) {
        setGraphStatus("Selected node is already expanded.", true);
        graphRefreshSelectionActionButtons();
        return;
    }
    const nodeId = String(entity?.node_id || "");
    if (graphWorkspaceState.expandedSummaryIds[nodeId]) {
        delete graphWorkspaceState.expandedSummaryIds[nodeId];
        graphWorkspaceState.selectedKind = "node";
        graphWorkspaceState.selectedRef = nodeId;
        graphWorkspaceState.selectedPayload = null;
        setGraphStatus(`Collapsed ${entity.label || nodeId}`);
    } else {
        graphWorkspaceState.expandedSummaryIds[nodeId] = true;
        graphWorkspaceState.selectedKind = "node";
        graphWorkspaceState.selectedRef = nodeId;
        graphWorkspaceState.selectedPayload = entity;
        setGraphStatus(`Expanded ${entity.label || nodeId}`);
    }
    graphRenderWorkspace();
    graphRefreshSelectionActionButtons();
}

function graphCollapseExpandedAction() {
    const entity = graphSelectedNodeEntity();
    const summaryId = String(entity?.node_id || "");
    if (!graphPropertyValue(entity, "summary_kind") || !summaryId || !graphWorkspaceState.expandedSummaryIds[summaryId]) {
        setGraphStatus("Select an expanded summary cluster to collapse.", true);
        graphRefreshSelectionActionButtons();
        return;
    }
    delete graphWorkspaceState.expandedSummaryIds[summaryId];
    graphWorkspaceState.selectedKind = "node";
    graphWorkspaceState.selectedRef = summaryId;
    graphWorkspaceState.selectedPayload = null;
    graphRenderWorkspace();
    graphRefreshSelectionActionButtons();
    setGraphStatus(`Collapsed ${entity.label || summaryId}`);
}

async function graphSaveLayoutAction() {
    const viewId = String(getValue("graph-view-select") || graphWorkspaceState.viewId || "attack_surface").trim();
    const name = String(getValue("graph-layout-name") || "default").trim() || "default";
    const layoutId = String(graphWorkspaceState.activeLayoutId || "");
    const layout = {
        positions: graphWorkspaceState.filtered?.positions && typeof graphWorkspaceState.filtered.positions === "object"
            ? graphWorkspaceState.filtered.positions
            : graphWorkspaceState.positions,
        pinned_node_ids: graphWorkspaceState.pinnedNodeIds,
        group_by: String(getValue("graph-group-select") || graphWorkspaceState.groupBy || graphCurrentViewConfig().defaultGroup || "subnet").trim(),
        filters: {
            view_id: viewId,
            host_id: getValue("graph-host-filter"),
            node_type: getValue("graph-node-type-filter"),
            edge_type: getValue("graph-edge-type-filter"),
            source_kind: getValue("graph-source-kind-filter"),
            severity: getValue("graph-severity-filter"),
            pack: getValue("graph-pack-filter"),
            time_window: getValue("graph-time-window-filter"),
            hide_ai_suggested: getChecked("graph-hide-ai-suggested"),
            hide_nmap_xml_artifacts: getChecked("graph-hide-nmap-xml-artifacts"),
            min_confidence: getValue("graph-min-confidence"),
        },
    };
    try {
        const body = await postJson("/api/graph/layouts", {
            layout_id: layoutId,
            view_id: viewId,
            name,
            layout,
        });
        const returned = body?.layout || {};
        graphWorkspaceState.layouts = (graphWorkspaceState.layouts || []).filter((item) => {
            return String(item?.layout_id || "") !== String(returned.layout_id || "");
        });
        graphWorkspaceState.layouts.push(returned);
        graphWorkspaceState.activeLayoutId = String(returned.layout_id || "");
        graphRenderLayoutOptions();
        setValue("graph-layout-select", graphWorkspaceState.activeLayoutId);
        setGraphStatus(`Layout saved: ${returned.name || name}`);
    } catch (err) {
        setGraphStatus(`Layout save failed: ${err.message}`, true);
    }
}

function graphResetLayoutAction() {
    graphWorkspaceState.activeLayoutId = "";
    graphWorkspaceState.positions = {};
    graphWorkspaceState.pinnedNodeIds = {};
    setValue("graph-layout-select", "");
    graphRenderWorkspace();
    setGraphStatus("Layout reset");
}

async function graphSaveAnnotationAction() {
    const kind = String(graphWorkspaceState.selectedKind || "");
    const ref = String(graphWorkspaceState.selectedRef || "");
    const body = String(getValue("graph-note-input") || "").trim();
    if (!kind || !ref) {
        setGraphStatus("Select a node or edge before saving a note.", true);
        return;
    }
    if (!body) {
        setGraphStatus("Note text is required.", true);
        return;
    }
    try {
        const response = await postJson("/api/graph/annotations", {
            target_kind: kind,
            target_ref: ref,
            body,
            created_by: "web-operator",
            source_ref: `graph-workspace:${graphWorkspaceState.viewId}`,
        });
        const annotation = response?.annotation || {};
        graphWorkspaceState.annotations = (graphWorkspaceState.annotations || []).filter((item) => {
            return String(item?.annotation_id || "") !== String(annotation.annotation_id || "");
        });
        graphWorkspaceState.annotations.push(annotation);
        setValue("graph-note-input", "");
        closeGraphNoteModalAction(false);
        graphRenderSelectionDetail();
        setGraphStatus("Note saved");
    } catch (err) {
        setGraphStatus(`Note save failed: ${err.message}`, true);
    }
}

function graphOpenNoteModalAction() {
    const kind = String(graphWorkspaceState.selectedKind || "");
    const ref = String(graphWorkspaceState.selectedRef || "");
    if (!kind || !ref) {
        setGraphStatus("Select a node or edge before adding a note.", true);
        return;
    }
    const entity = kind === "node" ? graphFindEntity("node", ref) : graphFindEntity("edge", ref);
    const entityLabel = String(entity?.label || entity?.edge_id || ref || "").trim() || "selected item";
    setText("graph-note-modal-target", `Target: ${graphFriendlyLabel(kind)} | ${entityLabel}`);
    setGraphNoteModalOpen(true);
}

function graphTogglePinAction() {
    const entity = graphWorkspaceState.selectedKind === "node"
        ? graphFindEntity("node", graphWorkspaceState.selectedRef)
        : null;
    if (!entity) {
        setGraphStatus("Select a node to pin or unpin.", true);
        return;
    }
    const nodeId = String(entity.node_id || "");
    if (graphWorkspaceState.pinnedNodeIds[nodeId]) {
        delete graphWorkspaceState.pinnedNodeIds[nodeId];
        setGraphStatus(`Node unpinned: ${entity.label || nodeId}`);
    } else {
        const current = graphWorkspaceState.filtered.positions?.[nodeId] || graphWorkspaceState.positions?.[nodeId];
        if (current) {
            graphWorkspaceState.positions[nodeId] = {x: current.x, y: current.y};
        }
        graphWorkspaceState.pinnedNodeIds[nodeId] = true;
        setGraphStatus(`Node pinned: ${entity.label || nodeId}`);
    }
    graphRenderWorkspace();
}

function graphHandlePointerMove(event) {
    if (!graphWorkspaceState.drag) {
        return;
    }
    const svg = document.getElementById("graph-workspace-canvas");
    if (!svg) {
        return;
    }
    event.preventDefault();
    const deltaX = Number(event.clientX || 0) - Number(graphWorkspaceState.drag.startClientX || 0);
    const deltaY = Number(event.clientY || 0) - Number(graphWorkspaceState.drag.startClientY || 0);
    if (!graphWorkspaceState.drag.active && Math.hypot(deltaX, deltaY) < 4) {
        return;
    }
    graphWorkspaceState.drag.active = true;
    const point = graphSvgPoint(svg, event);
    const offsetX = Number(point.x || 0) - Number(graphWorkspaceState.drag.startPointX || 0);
    const offsetY = Number(point.y || 0) - Number(graphWorkspaceState.drag.startPointY || 0);
    Object.entries(graphWorkspaceState.drag.initialPositions || {}).forEach(([nodeId, origin]) => {
        graphWorkspaceState.positions[nodeId] = {
            x: Math.max(20, Math.round((Number(origin?.x) || 0) + offsetX)),
            y: Math.max(28, Math.round((Number(origin?.y) || 0) + offsetY)),
        };
    });
    graphRenderWorkspace({preserveDetail: true});
}

function graphHandlePointerUp() {
    if (!graphWorkspaceState.drag) {
        return;
    }
    const wasActive = Boolean(graphWorkspaceState.drag.active);
    window.removeEventListener("pointermove", graphHandlePointerMove);
    window.removeEventListener("pointerup", graphHandlePointerUp);
    graphWorkspaceState.drag = null;
    if (wasActive) {
        graphWorkspaceState.suppressClickUntil = Date.now() + 180;
    }
}

function bindGraphWorkspaceEvents() {
    if (!graphWorkspaceEnabled()) {
        return;
    }
    const refreshIds = [
        "graph-view-select",
        "graph-group-select",
        "graph-render-mode-select",
        "graph-host-filter",
        "graph-node-type-filter",
        "graph-edge-type-filter",
        "graph-source-kind-filter",
        "graph-severity-filter",
        "graph-pack-filter",
        "graph-time-window-filter",
    ];
    refreshIds.forEach((id) => {
        const node = document.getElementById(id);
        if (!node) {
            return;
        }
        node.addEventListener("change", async (event) => {
            if (id === "graph-view-select") {
                const viewId = String(event.target.value || "attack_surface").trim();
                const viewConfig = GRAPH_VIEW_PRESETS[viewId] || GRAPH_VIEW_PRESETS.attack_surface;
                setValue("graph-group-select", viewConfig.defaultGroup || "finding");
                graphWorkspaceState.activeLayoutId = "";
                graphWorkspaceState.positions = {};
                graphWorkspaceState.pinnedNodeIds = {};
                graphRenderLayoutOptions();
            }
            if (["graph-group-select", "graph-render-mode-select", "graph-severity-filter", "graph-pack-filter", "graph-time-window-filter"].includes(id)) {
                graphRenderWorkspace();
                return;
            }
            await graphLoadSnapshot({background: false});
        });
    });

    const searchNode = document.getElementById("graph-search-input");
    if (searchNode) {
        let searchTimer = null;
        searchNode.addEventListener("input", () => {
            if (searchTimer) {
                window.clearTimeout(searchTimer);
            }
            searchTimer = window.setTimeout(() => {
                graphLoadSnapshot({background: false}).catch(() => {});
            }, 350);
        });
    }

    const confidenceNode = document.getElementById("graph-min-confidence");
    if (confidenceNode) {
        confidenceNode.addEventListener("input", () => {
            graphUpdateConfidenceLabel();
            graphLoadSnapshot({background: false}).catch(() => {});
        });
    }

    const zoomNode = document.getElementById("graph-zoom-slider");
    if (zoomNode) {
        zoomNode.addEventListener("input", () => {
            graphUpdateZoomLabel();
            graphRenderWorkspace();
        });
    }

    const focusDepthNode = document.getElementById("graph-focus-depth-select");
    if (focusDepthNode) {
        focusDepthNode.addEventListener("change", () => {
            graphWorkspaceState.focusDepth = Math.max(1, Math.min(3, parseInt(focusDepthNode.value, 10) || 1));
            if (graphWorkspaceState.focusSeedNodeIds.length) {
                graphRenderWorkspace();
            }
        });
    }

    ["graph-hide-ai-suggested", "graph-hide-nmap-xml-artifacts"].forEach((id) => {
        const node = document.getElementById(id);
        if (!node) {
            return;
        }
        node.addEventListener("change", () => {
            graphLoadSnapshot({background: false}).catch(() => {});
        });
    });

    const layoutSelect = document.getElementById("graph-layout-select");
    if (layoutSelect) {
        layoutSelect.addEventListener("change", () => {
            const layoutId = String(layoutSelect.value || "");
            if (!layoutId) {
                graphResetLayoutAction();
                return;
            }
            graphApplyLayoutById(layoutId);
            setGraphStatus("Layout loaded");
        });
    }

    const svg = document.getElementById("graph-workspace-canvas");
    if (svg) {
        svg.addEventListener("click", (event) => {
            if (Number(graphWorkspaceState.suppressClickUntil || 0) > Date.now()) {
                return;
            }
            const nodeTarget = event.target.closest("[data-graph-node-id]");
            if (nodeTarget) {
                graphSelectEntity("node", nodeTarget.getAttribute("data-graph-node-id"));
                return;
            }
            const edgeTarget = event.target.closest("[data-graph-edge-id]");
            if (edgeTarget) {
                graphSelectEntity("edge", edgeTarget.getAttribute("data-graph-edge-id"));
                return;
            }
            const groupTarget = event.target.closest("[data-graph-group-key]");
            if (groupTarget) {
                return;
            }
            graphDismissSelection();
        });
        svg.addEventListener("dblclick", (event) => {
            const nodeTarget = event.target.closest("[data-graph-node-id]");
            if (!nodeTarget) {
                return;
            }
            const nodeId = String(nodeTarget.getAttribute("data-graph-node-id") || "");
            graphWorkspaceState.selectedKind = "node";
            graphWorkspaceState.selectedRef = nodeId;
            const entity = graphFindEntity("node", nodeId);
            if (graphPropertyValue(entity, "summary_kind")) {
                graphToggleExpandSelectionAction();
            }
        });
        svg.addEventListener("pointerdown", (event) => {
            const nodeTarget = event.target.closest("[data-graph-node-id]");
            if (!nodeTarget) {
                return;
            }
            const nodeId = String(nodeTarget.getAttribute("data-graph-node-id") || "");
            const point = graphSvgPoint(svg, event);
            const current = graphWorkspaceState.filtered.positions?.[nodeId] || graphWorkspaceState.positions?.[nodeId];
            if (!current) {
                return;
            }
            graphWorkspaceState.drag = {
                kind: "node",
                nodeIds: [nodeId],
                initialPositions: {
                    [nodeId]: {
                        x: Number(current.x) || 0,
                        y: Number(current.y) || 0,
                    },
                },
                startPointX: Number(point.x || 0),
                startPointY: Number(point.y || 0),
                startClientX: Number(event.clientX || 0),
                startClientY: Number(event.clientY || 0),
                active: false,
            };
            window.addEventListener("pointermove", graphHandlePointerMove);
            window.addEventListener("pointerup", graphHandlePointerUp);
            event.preventDefault();
        });
        svg.addEventListener("pointerdown", (event) => {
            const groupTarget = event.target.closest("[data-graph-group-key]");
            if (!groupTarget || event.target.closest("[data-graph-node-id]")) {
                return;
            }
            const groupKey = String(groupTarget.getAttribute("data-graph-group-key") || "");
            const group = graphFindGroup(groupKey);
            const nodeIds = Array.isArray(group?.nodeIds) ? group.nodeIds.filter(Boolean) : [];
            if (!nodeIds.length) {
                return;
            }
            const point = graphSvgPoint(svg, event);
            const initialPositions = {};
            nodeIds.forEach((nodeId) => {
                const current = graphWorkspaceState.filtered.positions?.[nodeId] || graphWorkspaceState.positions?.[nodeId];
                if (!current) {
                    return;
                }
                initialPositions[nodeId] = {
                    x: Number(current.x) || 0,
                    y: Number(current.y) || 0,
                };
            });
            if (!Object.keys(initialPositions).length) {
                return;
            }
            graphWorkspaceState.drag = {
                kind: "group",
                groupKey,
                nodeIds: Object.keys(initialPositions),
                initialPositions,
                startPointX: Number(point.x || 0),
                startPointY: Number(point.y || 0),
                startClientX: Number(event.clientX || 0),
                startClientY: Number(event.clientY || 0),
                active: false,
            };
            window.addEventListener("pointermove", graphHandlePointerMove);
            window.addEventListener("pointerup", graphHandlePointerUp);
            event.preventDefault();
        });
    }

    graphUpdateConfidenceLabel();
    graphUpdateZoomLabel();
    graphUpdateHostFilterOptions();
    graphRenderLayoutOptions();
}

function sleepMs(ms) {
    return new Promise((resolve) => {
        window.setTimeout(resolve, Math.max(0, Number(ms) || 0));
    });
}

async function waitForJobCompletion(jobId, timeoutMs = 120000, pollIntervalMs = 1200) {
    const id = Number(jobId);
    if (!Number.isFinite(id) || id <= 0) {
        throw new Error("Invalid job id.");
    }

    const started = Date.now();
    while ((Date.now() - started) < timeoutMs) {
        const job = await fetchJson(`/api/jobs/${id}`);
        const status = String(job.status || "").toLowerCase();
        if (status === "completed") {
            return job;
        }
        if (status === "failed") {
            throw new Error(String(job.error || "Save job failed."));
        }
        await sleepMs(pollIntervalMs);
    }

    throw new Error("Timed out waiting for job completion.");
}

async function loadWorkspaceHosts() {
    const body = await fetchJson(`/api/workspace/hosts?${currentHostFilterQuery()}`);
    if (body && body.filter) {
        workspaceState.hostFilter = String(body.filter || "hide_down").trim().toLowerCase() === "show_all"
            ? "show_all"
            : "hide_down";
    }
    workspaceState.hostServiceFilter = String(body?.service || "").trim();
    syncHostFilterControls();
    renderServices(workspaceState.services);
    renderHosts(body.hosts || []);
}

async function loadWorkspaceServices() {
    const body = await fetchJson("/api/workspace/services");
    renderServices(body.services || []);
}

async function loadWorkspaceTools({service = "", force = false} = {}) {
    if (workspaceState.toolsLoading && !force) {
        return;
    }

    workspaceState.toolsLoading = true;
    try {
        const allTools = [];
        let offset = 0;
        let pageGuard = 0;
        const pageLimit = 500;

        while (pageGuard < 200) {
            const params = new URLSearchParams();
            params.set("limit", String(pageLimit));
            params.set("offset", String(offset));
            if (service) {
                params.set("service", String(service));
            }
            const body = await fetchJson(`/api/workspace/tools?${params.toString()}`);
            const tools = Array.isArray(body.tools) ? body.tools : [];
            allTools.push(...tools);

            if (!body.has_more) {
                break;
            }

            const nextOffset = Number(body.next_offset);
            if (!Number.isFinite(nextOffset) || nextOffset <= offset) {
                break;
            }
            offset = nextOffset;
            pageGuard += 1;
        }

        workspaceState.toolsHydrated = true;
        renderTools(allTools);
    } finally {
        workspaceState.toolsLoading = false;
    }
}

async function loadHostDetail(hostId) {
    if (!hostId) {
        return;
    }
    const payload = await fetchJson(`/api/workspace/hosts/${hostId}`);
    renderHostDetail(payload);
}

async function refreshWorkspace() {
    setWorkspaceStatus("Refreshing workspace...");
    try {
        await Promise.all([
            loadWorkspaceHosts(),
            loadWorkspaceServices(),
            loadWorkspaceTools(),
        ]);
        if (workspaceState.selectedHostId) {
            await loadHostDetail(workspaceState.selectedHostId);
        }
        try {
            await graphLoadSnapshot({background: true});
        } catch (_err) {
        }
        setWorkspaceStatus("Workspace refreshed");
    } catch (err) {
        setWorkspaceStatus(`Workspace refresh failed: ${err.message}`, true);
    }
}

async function saveHostNote() {
    const hostId = workspaceState.selectedHostId;
    if (!hostId) {
        setWorkspaceStatus("No host selected", true);
        return;
    }
    const text = getValue("workspace-note");
    try {
        await postJson(`/api/workspace/hosts/${hostId}/note`, {text});
        setWorkspaceStatus("Note saved");
    } catch (err) {
        setWorkspaceStatus(`Save note failed: ${err.message}`, true);
    }
}

async function runManualTool() {
    const hostIp = getValue("workspace-tool-host-ip").trim();
    const port = getValue("workspace-tool-port").trim();
    const protocol = getValue("workspace-tool-protocol").trim() || "tcp";
    const toolId = getValue("workspace-tool-select").trim();
    if (!hostIp || !port || !toolId) {
        setWorkspaceStatus("host ip, port and tool are required", true);
        return;
    }
    setWorkspaceStatus("Queueing tool run...");
    try {
        const body = await postJson("/api/workspace/tools/run", {
            host_ip: hostIp,
            port,
            protocol,
            tool_id: toolId,
        });
        setWorkspaceStatus(`Tool run queued (job ${body?.job?.id || "?"})`);
        await pollSnapshot();
    } catch (err) {
        setWorkspaceStatus(`Tool run failed: ${err.message}`, true);
    }
}

async function runSchedulerNow() {
    setWorkspaceStatus("Queueing scheduler run...");
    try {
        const body = await postJson("/api/scheduler/run", {});
        setWorkspaceStatus(`Scheduler run queued (job ${body?.job?.id || "?"})`);
        await pollSnapshot();
    } catch (err) {
        setWorkspaceStatus(`Scheduler run failed: ${err.message}`, true);
    }
}

async function addScriptEntry() {
    const hostId = workspaceState.selectedHostId;
    const scriptId = getValue("workspace-script-id").trim();
    const output = getValue("workspace-script-output");
    const port = getValue("workspace-script-port").trim() || getValue("workspace-tool-port").trim();
    const protocol = getValue("workspace-script-protocol").trim() || getValue("workspace-tool-protocol").trim() || "tcp";
    if (!hostId || !scriptId || !port) {
        setWorkspaceStatus("select host and provide script id + port", true);
        return;
    }
    try {
        await postJson(`/api/workspace/hosts/${hostId}/scripts`, {
            script_id: scriptId,
            output,
            port,
            protocol,
        });
        setWorkspaceStatus("Script saved");
        await loadHostDetail(hostId);
    } catch (err) {
        setWorkspaceStatus(`Add script failed: ${err.message}`, true);
    }
}

async function addCveEntry() {
    const hostId = workspaceState.selectedHostId;
    const name = getValue("workspace-cve-name").trim();
    const severity = getValue("workspace-cve-severity").trim();
    if (!hostId || !name) {
        setWorkspaceStatus("select host and provide CVE name", true);
        return;
    }
    try {
        await postJson(`/api/workspace/hosts/${hostId}/cves`, {
            name,
            severity,
        });
        setWorkspaceStatus("CVE saved");
        await loadHostDetail(hostId);
    } catch (err) {
        setWorkspaceStatus(`Add CVE failed: ${err.message}`, true);
    }
}

async function deleteScript(scriptId) {
    try {
        const response = await fetch(`/api/workspace/scripts/${scriptId}`, {method: "DELETE"});
        if (!response.ok) {
            throw new Error(`Request failed (${response.status})`);
        }
        setWorkspaceStatus("Script deleted");
        if (workspaceState.selectedHostId) {
            await loadHostDetail(workspaceState.selectedHostId);
        }
    } catch (err) {
        setWorkspaceStatus(`Delete script failed: ${err.message}`, true);
    }
}

async function deleteCve(cveId) {
    try {
        const response = await fetch(`/api/workspace/cves/${cveId}`, {method: "DELETE"});
        if (!response.ok) {
            throw new Error(`Request failed (${response.status})`);
        }
        setWorkspaceStatus("CVE deleted");
        if (workspaceState.selectedHostId) {
            await loadHostDetail(workspaceState.selectedHostId);
        }
    } catch (err) {
        setWorkspaceStatus(`Delete CVE failed: ${err.message}`, true);
    }
}

async function loadApprovals() {
    try {
        const body = await fetchJson("/api/scheduler/approvals?status=pending&limit=200");
        renderApprovals(body.approvals || []);
    } catch (_err) {
    }
}

async function approveApproval(approvalId, familyAction = "") {
    const resolvedFamilyAction = String(familyAction || "");
    const approveFamily = resolvedFamilyAction === "allowed";
    try {
        await postJson(`/api/scheduler/approvals/${approvalId}/approve`, {
            approve_family: approveFamily,
            run_now: true,
            family_action: resolvedFamilyAction,
        });
        setWorkspaceStatus(
            resolvedFamilyAction === "allowed"
                ? `Approval ${approvalId} accepted and family allowed`
                : `Approval ${approvalId} accepted`,
        );
        await Promise.all([loadApprovals(), pollSnapshot()]);
    } catch (err) {
        setWorkspaceStatus(`Approve failed: ${err.message}`, true);
    }
}

async function rejectApproval(approvalId, familyAction = "") {
    const resolvedFamilyAction = String(familyAction || "");
    try {
        await postJson(`/api/scheduler/approvals/${approvalId}/reject`, {
            reason: "rejected in web workspace",
            family_action: resolvedFamilyAction,
        });
        setWorkspaceStatus(
            resolvedFamilyAction === "suppressed"
                ? `Approval ${approvalId} rejected and family suppressed`
                : `Approval ${approvalId} rejected`,
        );
        await Promise.all([loadApprovals(), pollSnapshot()]);
    } catch (err) {
        setWorkspaceStatus(`Reject failed: ${err.message}`, true);
    }
}

function renderSnapshot(snapshot) {
    if (!snapshot) {
        return;
    }
    if (snapshot.project) {
        renderProject(snapshot.project);
    }
    if (snapshot.summary) {
        renderSummary(snapshot.summary);
    }
    syncHostFilterControls();
    if (Array.isArray(snapshot.hosts)) {
        const hostFilter = String(workspaceState.hostFilter || "hide_down").trim().toLowerCase() === "show_all"
            ? "show_all"
            : "hide_down";
        const serviceFilter = String(workspaceState.hostServiceFilter || "").trim();
        if (hostFilter !== "show_all") {
            const filteredHosts = serviceFilter
                ? snapshot.hosts.filter((host) => hostMatchesServiceFilter(host, serviceFilter))
                : snapshot.hosts;
            renderHosts(filteredHosts);
        }
    }
    if (Array.isArray(snapshot.services)) {
        renderServices(snapshot.services);
    }
    if (Array.isArray(snapshot.tools) && !workspaceState.toolsHydrated) {
        renderTools(snapshot.tools);
    }
    if (snapshot.tools_meta && typeof snapshot.tools_meta === "object") {
        const totalTools = Number(snapshot.tools_meta.total || 0);
        if (Number.isFinite(totalTools) && totalTools >= 0) {
            setText("tool-count", totalTools);
            if (workspaceState.toolsHydrated && !workspaceState.toolsLoading && totalTools !== workspaceState.tools.length) {
                loadWorkspaceTools().catch(() => {});
            }
        }
    }
    if (Array.isArray(snapshot.processes)) {
        renderProcesses(snapshot.processes);
    }
    if (snapshot.scheduler) {
        setText("scheduler-mode", snapshot.scheduler.mode || "");
        setText("scheduler-goal", snapshot.scheduler.goal_profile || "");
        setText("scheduler-families", snapshot.scheduler.preapproved_families_count || 0);
    }
    if (Array.isArray(snapshot.scheduler_decisions)) {
        renderDecisions(snapshot.scheduler_decisions);
    }
    if (Array.isArray(snapshot.scheduler_approvals)) {
        renderApprovals(snapshot.scheduler_approvals);
    }
    if (Array.isArray(snapshot.jobs)) {
        renderJobs(snapshot.jobs);
    }
    if (Array.isArray(snapshot.scan_history)) {
        renderScanHistory(snapshot.scan_history);
    }

    if (workspaceState.selectedHostId && !workspaceState.hostDetail) {
        loadHostDetail(workspaceState.selectedHostId).catch(() => {});
    }
    graphScheduleRefresh();
}

function wsUrl(path) {
    const scheme = window.location.protocol === "https:" ? "wss" : "ws";
    return `${scheme}://${window.location.host}${path}`;
}

function setLiveChip(text, isError) {
    const chip = document.getElementById("live-status");
    if (!chip) {
        return;
    }
    chip.textContent = text;
    chip.style.color = isError ? "#ff9b9b" : "";
}

function connectSnapshotWebSocket() {
    const socket = new WebSocket(wsUrl("/ws/snapshot"));
    socket.onopen = () => setLiveChip("Live", false);
    socket.onmessage = (event) => {
        try {
            const snapshot = JSON.parse(event.data);
            renderSnapshot(snapshot);
        } catch (_err) {
            setLiveChip("Decode Error", true);
        }
    };
    socket.onerror = () => setLiveChip("Socket Error", true);
    socket.onclose = () => {
        setLiveChip("Reconnecting", true);
        window.setTimeout(connectSnapshotWebSocket, 1500);
    };
}

async function pollSnapshot() {
    try {
        const response = await fetch("/api/snapshot");
        if (!response.ok) {
            setLiveChip("Polling Error", true);
            return;
        }
        const snapshot = await response.json();
        renderSnapshot(snapshot);
    } catch (_err) {
        setLiveChip("Polling Error", true);
    }
}

async function loadSchedulerPreferences() {
    try {
        const response = await fetch("/api/scheduler/preferences");
        if (!response.ok) {
            return;
        }
        const prefs = await response.json();
        applySchedulerPreferences(prefs);
        syncStartupSchedulerFromMain();
    } catch (_err) {
    }
}

async function saveSchedulerPreferences(event) {
    event.preventDefault();
    const statusNode = document.getElementById("scheduler-save-status");
    if (statusNode) {
        statusNode.textContent = "Saving...";
    }
    let payload;
    try {
        payload = collectSchedulerPreferencesFromForm();
    } catch (err) {
        if (statusNode) {
            statusNode.textContent = err.message || "Save failed";
        }
        return;
    }
    try {
        const response = await fetch("/api/scheduler/preferences", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify(payload),
        });
        if (!response.ok) {
            if (statusNode) {
                statusNode.textContent = "Save failed";
            }
            return;
        }
        const prefs = await response.json();
        applySchedulerPreferences(prefs);
        if (statusNode) {
            statusNode.textContent = "Saved";
        }
    } catch (_err) {
        if (statusNode) {
            statusNode.textContent = "Save failed";
        }
    }
}

async function saveProjectReportDeliveryPreferences(event) {
    if (event) {
        event.preventDefault();
    }
    const statusNode = document.getElementById("report-provider-save-status");
    if (statusNode) {
        statusNode.textContent = "Saving...";
    }
    let delivery;
    try {
        delivery = collectProjectReportDeliveryFromForm();
    } catch (err) {
        if (statusNode) {
            statusNode.textContent = err.message || "Save failed";
        }
        return;
    }
    try {
        const response = await fetch("/api/scheduler/preferences", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({
                project_report_delivery: delivery,
            }),
        });
        if (!response.ok) {
            if (statusNode) {
                statusNode.textContent = "Save failed";
            }
            return;
        }
        const prefs = await response.json();
        applySchedulerPreferences(prefs);
        if (statusNode) {
            statusNode.textContent = "Saved";
        }
        setActionStatus("Report provider settings saved");
    } catch (_err) {
        if (statusNode) {
            statusNode.textContent = "Save failed";
        }
    }
}

async function testSchedulerProviderAction(event) {
    if (event) {
        event.preventDefault();
    }
    const statusNode = document.getElementById("scheduler-save-status");
    if (statusNode) {
        statusNode.textContent = "Testing provider...";
    }
    let payload;
    try {
        payload = collectSchedulerPreferencesFromForm();
    } catch (err) {
        if (statusNode) {
            statusNode.textContent = err.message || "Provider test failed";
        }
        return;
    }
    try {
        const result = await postJson("/api/scheduler/provider/test", payload);
        if (!result.ok) {
            if (statusNode) {
                statusNode.textContent = `Provider test failed: ${result.error || "unknown error"}`;
            }
            return;
        }

        const summaryParts = [];
        if (result.provider) {
            summaryParts.push(result.provider);
        }
        if (result.model) {
            summaryParts.push(`model=${result.model}`);
        }
        if (result.api_style) {
            summaryParts.push(`api=${result.api_style}`);
        }
        if (result.endpoint) {
            summaryParts.push(result.endpoint);
        }
        if (result.auto_selected_model) {
            summaryParts.push("auto-selected");
        }
        if (typeof result.latency_ms === "number") {
            summaryParts.push(`${result.latency_ms}ms`);
        }
        if (statusNode) {
            const suffix = summaryParts.length ? ` (${summaryParts.join(" | ")})` : "";
            statusNode.textContent = `Provider OK${suffix}`;
        }
    } catch (err) {
        if (statusNode) {
            statusNode.textContent = `Provider test failed: ${err.message}`;
        }
    }
}

async function createNewTemporaryProject() {
    setActionStatus("Creating temporary project...");
    try {
        const body = await postJson("/api/project/new-temp", {});
        setActionStatus("Created temporary project");
        resetWorkspaceDisplayForProjectSwitch({clearProjectPaths: true});
        renderProject(body?.project || {});
        await refreshWorkspace();
        await Promise.all([pollSnapshot(), loadApprovals()]);
    } catch (err) {
        setActionStatus(`Create failed: ${err.message}`, true);
    }
}

async function openProject() {
    const path = getValue("project-open-path").trim();
    if (!path) {
        setActionStatus("Open failed: project path is required", true);
        return;
    }
    setActionStatus("Opening project...");
    try {
        const body = await postJson("/api/project/open", {path});
        setActionStatus("Project opened");
        resetWorkspaceDisplayForProjectSwitch({clearProjectPaths: false});
        setValue("project-save-path", "");
        renderProject(body?.project || {});
        await refreshWorkspace();
        await Promise.all([pollSnapshot(), loadApprovals()]);
    } catch (err) {
        setActionStatus(`Open failed: ${err.message}`, true);
    }
}

async function saveProjectAs() {
    const path = getValue("project-save-path").trim();
    if (!path) {
        setActionStatus("Save failed: destination path is required", true);
        return;
    }
    setActionStatus("Saving project...");
    try {
        const body = await postJson("/api/project/save-as", {
            path,
            replace: getChecked("project-save-replace"),
        });
        const jobId = Number(body?.job?.id || 0);
        if (jobId > 0) {
            setActionStatus(`Save queued (job ${jobId})...`);
            await waitForJobCompletion(jobId, 10 * 60 * 1000, 1500);
        }
        setActionStatus("Project saved");
        await pollSnapshot();
    } catch (err) {
        setActionStatus(`Save failed: ${err.message}`, true);
    }
}

async function importTargetsFile() {
    const path = getValue("targets-file-path").trim();
    if (!path) {
        setActionStatus("Import failed: targets file path is required", true);
        return;
    }
    setActionStatus("Queueing targets import job...");
    try {
        const body = await postJson("/api/targets/import-file", {path});
        const jobId = body?.job?.id;
        setActionStatus(jobId ? `Targets import queued (job ${jobId})` : "Targets import queued");
        await pollSnapshot();
    } catch (err) {
        setActionStatus(`Import failed: ${err.message}`, true);
    }
}

async function importNmapXml() {
    const path = getValue("nmap-xml-path").trim();
    if (!path) {
        setActionStatus("Import failed: XML path is required", true);
        return;
    }
    setActionStatus("Queueing Nmap XML import job...");
    try {
        const body = await postJson("/api/nmap/import-xml", {
            path,
            run_actions: getChecked("nmap-xml-run-actions"),
        });
        const jobId = body?.job?.id;
        setActionStatus(jobId ? `Nmap XML import queued (job ${jobId})` : "Nmap XML import queued");
        await pollSnapshot();
    } catch (err) {
        setActionStatus(`Import failed: ${err.message}`, true);
    }
}

function parseTargets(text) {
    return (text || "")
        .split(/[\s,]+/)
        .map((token) => token.trim())
        .filter((token) => token.length > 0);
}

function getSelectedNmapMode() {
    const node = document.querySelector("input[name='nmap-scan-mode']:checked");
    return node ? String(node.value || "rfc1918_discovery") : "rfc1918_discovery";
}

function normalizeTiming(value, fallback = "T3") {
    const text = String(value || fallback).toUpperCase();
    const normalized = text.startsWith("T") ? text : `T${text}`;
    if (["T0", "T1", "T2", "T3", "T4", "T5"].includes(normalized)) {
        return normalized;
    }
    return fallback;
}

function normalizePortCount(value, fallback = 1000) {
    const parsed = parseInt(value, 10);
    if (!Number.isFinite(parsed)) {
        return fallback;
    }
    return Math.min(65535, Math.max(1, parsed));
}

function collectNmapWizardTargets() {
    const dedup = new Set(parseTargets(getValue("nmap-targets")));
    if (getChecked("nmap-include-rfc1918")) {
        if (getChecked("nmap-rfc-10")) {
            dedup.add("10.0.0.0/8");
        }
        if (getChecked("nmap-rfc-172")) {
            dedup.add("172.16.0.0/12");
        }
        if (getChecked("nmap-rfc-192")) {
            dedup.add("192.168.0.0/16");
        }
    }
    return Array.from(dedup);
}

function getNmapScanOptions(mode) {
    if (mode === "easy") {
        return {
            discovery: getChecked("nmap-easy-discovery"),
            skip_dns: getChecked("nmap-easy-skip-dns"),
            force_pn: getChecked("nmap-easy-force-pn"),
            timing: normalizeTiming(getValue("nmap-easy-timing"), "T3"),
            top_ports: normalizePortCount(getValue("nmap-easy-top-ports"), 1000),
            service_detection: getChecked("nmap-easy-service-detection"),
            default_scripts: getChecked("nmap-easy-default-scripts"),
            os_detection: getChecked("nmap-easy-os-detection"),
            aggressive: false,
            full_ports: false,
            vuln_scripts: false,
            host_discovery_only: false,
            arp_ping: false,
        };
    }

    if (mode === "hard") {
        return {
            discovery: getChecked("nmap-hard-discovery"),
            skip_dns: getChecked("nmap-hard-skip-dns"),
            force_pn: getChecked("nmap-hard-force-pn"),
            timing: normalizeTiming(getValue("nmap-hard-timing"), "T4"),
            top_ports: normalizePortCount(getValue("nmap-hard-top-ports"), 1000),
            service_detection: getChecked("nmap-hard-service-detection"),
            default_scripts: getChecked("nmap-hard-default-scripts"),
            os_detection: getChecked("nmap-hard-os-detection"),
            aggressive: getChecked("nmap-hard-aggressive"),
            full_ports: getChecked("nmap-hard-full-ports"),
            vuln_scripts: getChecked("nmap-hard-vuln-scripts"),
            host_discovery_only: false,
            arp_ping: false,
        };
    }

    return {
        discovery: getChecked("nmap-rfc-discovery"),
        host_discovery_only: getChecked("nmap-rfc-host-discovery-only"),
        skip_dns: getChecked("nmap-rfc-skip-dns"),
        arp_ping: getChecked("nmap-rfc-arp-ping"),
        force_pn: getChecked("nmap-rfc-force-pn"),
        timing: normalizeTiming(getValue("nmap-rfc-timing"), "T3"),
        top_ports: normalizePortCount(getValue("nmap-rfc-top-ports"), 100),
        service_detection: getChecked("nmap-rfc-service-detection"),
        default_scripts: getChecked("nmap-rfc-default-scripts"),
        os_detection: getChecked("nmap-rfc-os-detection"),
        aggressive: false,
        full_ports: false,
        vuln_scripts: false,
    };
}

function getSelectedRfcSubnetCount() {
    const selected = [getChecked("nmap-rfc-10"), getChecked("nmap-rfc-172"), getChecked("nmap-rfc-192")];
    return selected.filter(Boolean).length;
}

function setRfcTargetControlsEnabled(enabled) {
    const include = document.getElementById("nmap-include-rfc1918");
    if (include) {
        include.disabled = !enabled;
    }
    ["nmap-rfc-10", "nmap-rfc-172", "nmap-rfc-192"].forEach((id) => {
        const node = document.getElementById(id);
        if (node) {
            node.disabled = !enabled;
        }
    });
}

function applyNmapModeTargetDefaults(mode) {
    if (mode === "rfc1918_discovery") {
        setChecked("nmap-include-rfc1918", true);
        setChecked("nmap-rfc-10", true);
        setChecked("nmap-rfc-172", true);
        setChecked("nmap-rfc-192", true);
        setRfcTargetControlsEnabled(true);
        return;
    }
    setChecked("nmap-include-rfc1918", false);
    setChecked("nmap-rfc-10", false);
    setChecked("nmap-rfc-172", false);
    setChecked("nmap-rfc-192", false);
    setRfcTargetControlsEnabled(false);
}

function isValidTopPortsValue(inputId) {
    const node = document.getElementById(inputId);
    if (!node || node.disabled) {
        return true;
    }
    const raw = String(node.value || "").trim();
    if (!raw) {
        return false;
    }
    const parsed = parseInt(raw, 10);
    return Number.isInteger(parsed) && parsed >= 1 && parsed <= 65535;
}

function validateNmapWizardState() {
    const mode = getSelectedNmapMode();
    const explicitTargets = parseTargets(getValue("nmap-targets"));
    const hasExplicitTargets = explicitTargets.length > 0;
    const hasRfcRanges = mode === "rfc1918_discovery"
        && getChecked("nmap-include-rfc1918")
        && getSelectedRfcSubnetCount() > 0;
    if (!hasExplicitTargets && !hasRfcRanges) {
        return {valid: false, reason: "Add targets, or select RFC1918 ranges in RFC1918 mode."};
    }

    const targets = collectNmapWizardTargets();
    if (!targets.length) {
        return {valid: false, reason: "Provide at least one target."};
    }

    if (mode === "easy") {
        if (!isValidTopPortsValue("nmap-easy-top-ports")) {
            return {valid: false, reason: "Easy mode Top Ports must be 1-65535."};
        }
        return {valid: true, reason: ""};
    }

    if (mode === "hard") {
        const fullPorts = getChecked("nmap-hard-full-ports");
        if (!fullPorts && !isValidTopPortsValue("nmap-hard-top-ports")) {
            return {valid: false, reason: "Hard mode Top Ports must be 1-65535 when full scan is disabled."};
        }
        return {valid: true, reason: ""};
    }

    const discoveryOnly = getChecked("nmap-rfc-host-discovery-only");
    if (!discoveryOnly && !isValidTopPortsValue("nmap-rfc-top-ports")) {
        return {valid: false, reason: "RFC1918 mode Top Ports must be 1-65535 when discovery-only is disabled."};
    }
    return {valid: true, reason: ""};
}

function refreshNmapScanButtonState() {
    const button = document.getElementById("nmap-scan-button");
    if (!button) {
        return;
    }
    const verdict = validateNmapWizardState();
    const unlocked = !nmapWizardState.postSubmitLock;
    button.disabled = !verdict.valid || !unlocked;
    if (!unlocked) {
        button.title = "Enter scan inputs to enable this action.";
    } else {
        button.title = verdict.valid ? "" : verdict.reason;
    }
}

function parseShellArgs(text) {
    const value = String(text || "").trim();
    if (!value) {
        return [];
    }
    const matches = value.match(/(?:[^\s"'`]+|"[^"]*"|'[^']*')+/g) || [];
    return matches
        .map((token) => token.trim())
        .map((token) => token.replace(/^"(.*)"$/, "$1").replace(/^'(.*)'$/, "$1"))
        .filter((token) => token.length > 0);
}

function joinShellTokens(tokens) {
    return (tokens || [])
        .map((token) => {
            const text = String(token ?? "");
            if (!text) {
                return "''";
            }
            if (/^[A-Za-z0-9_./:=@-]+$/.test(text)) {
                return text;
            }
            return `'${text.replace(/'/g, "'\\''")}'`;
        })
        .join(" ");
}

function updateNmapCommandPreview() {
    const previewNode = document.getElementById("nmap-command-preview");
    if (!previewNode) {
        return;
    }
    const targets = collectNmapWizardTargets();
    const mode = getSelectedNmapMode();
    const options = getNmapScanOptions(mode);
    const nmapPath = "nmap";
    const extraArgs = getValue("nmap-args").trim();
    const extraTokens = parseShellArgs(extraArgs);
    const hasStatsEvery = extraTokens.some((token) => {
        const value = String(token || "").trim().toLowerCase();
        return value === "--stats-every" || value.startsWith("--stats-every=");
    });
    const hasVerbose = extraTokens.some((token) => {
        const value = String(token || "").trim().toLowerCase();
        return value === "-v" || value === "-vv" || value === "-vvv" || value === "--verbose";
    });
    const targetTokens = targets.length ? targets : ["<targets>"];
    const cmd = [nmapPath];

    if (options.host_discovery_only) {
        cmd.push("-sn");
        if (options.skip_dns) {
            cmd.push("-n");
        }
        if (options.arp_ping) {
            cmd.push("-PR");
        }
        cmd.push(`-${normalizeTiming(options.timing, "T3")}`);
    } else {
        if (options.force_pn || !options.discovery) {
            cmd.push("-Pn");
        }
        if (options.skip_dns) {
            cmd.push("-n");
        }
        cmd.push(`-${normalizeTiming(options.timing, "T3")}`);

        if (options.full_ports) {
            cmd.push("-p-");
        } else {
            cmd.push("--top-ports", String(normalizePortCount(options.top_ports, 1000)));
        }

        if (options.aggressive) {
            cmd.push("-A");
        } else {
            if (options.service_detection) {
                cmd.push("-sV");
            }
            if (options.default_scripts) {
                cmd.push("-sC");
            }
            if (options.os_detection) {
                cmd.push("-O");
            }
        }

        if (options.vuln_scripts) {
            cmd.push("--script", "vuln");
        }
    }
    let finalExtraTokens = hasStatsEvery ? extraTokens : [...extraTokens, "--stats-every", "15s"];
    if (!hasVerbose) {
        finalExtraTokens = [...finalExtraTokens, "-vv"];
    }
    cmd.push(...finalExtraTokens, ...targetTokens, "-oA", "<output_prefix>");

    previewNode.textContent = `Command Preview: ${joinShellTokens(cmd)}`;
    refreshNmapScanButtonState();
}

function setNmapWizardStep(step) {
    const nextStep = Math.max(1, Math.min(3, parseInt(step, 10) || 1));
    nmapWizardState.step = nextStep;

    [1, 2, 3].forEach((index) => {
        const indicator = document.getElementById(`nmap-wizard-indicator-${index}`);
        if (indicator) {
            indicator.classList.toggle("is-active", index === nextStep);
        }
        const page = document.getElementById(`nmap-wizard-step-${index}`);
        if (page) {
            page.classList.toggle("is-active", index === nextStep);
        }
    });

    const back = document.getElementById("nmap-wizard-back");
    const next = document.getElementById("nmap-wizard-next");
    if (back) {
        back.disabled = nextStep <= 1;
    }
    if (next) {
        next.disabled = nextStep >= 3;
        next.style.display = nextStep >= 3 ? "none" : "";
    }
    refreshNmapScanButtonState();
}

function refreshNmapModeOptions() {
    const mode = getSelectedNmapMode();
    if (mode !== nmapWizardState.lastMode) {
        applyNmapModeTargetDefaults(mode);
        nmapWizardState.lastMode = mode;
    }
    const blocks = document.querySelectorAll("[data-mode-options]");
    blocks.forEach((block) => {
        const blockMode = String(block.getAttribute("data-mode-options") || "");
        block.classList.toggle("is-active", blockMode === mode);
    });
    const hardTopPorts = document.getElementById("nmap-hard-top-ports");
    if (hardTopPorts) {
        hardTopPorts.disabled = getChecked("nmap-hard-full-ports");
    }
    const rfcDiscoveryOnly = getChecked("nmap-rfc-host-discovery-only");
    ["nmap-rfc-top-ports", "nmap-rfc-service-detection", "nmap-rfc-default-scripts", "nmap-rfc-os-detection", "nmap-rfc-force-pn"]
        .forEach((id) => {
            const node = document.getElementById(id);
            if (node) {
                node.disabled = rfcDiscoveryOnly;
            }
        });
    updateNmapCommandPreview();
    refreshNmapScanButtonState();
}

async function runNmapScan() {
    if (nmapWizardState.postSubmitLock) {
        setActionStatus("Scan failed: enter scan inputs before starting a job.", true);
        refreshNmapScanButtonState();
        return;
    }
    const validation = validateNmapWizardState();
    if (!validation.valid) {
        setActionStatus(`Scan failed: ${validation.reason}`, true);
        const reason = String(validation.reason || "").toLowerCase();
        if (reason.includes("target") || reason.includes("rfc1918")) {
            setNmapWizardStep(2);
        } else {
            setNmapWizardStep(3);
        }
        return;
    }
    const targets = collectNmapWizardTargets();
    const scanMode = getSelectedNmapMode();
    const scanOptions = getNmapScanOptions(scanMode);
    const discovery = Boolean(scanOptions.discovery);
    const staged = false;

    setActionStatus("Queueing Nmap scan job...");
    try {
        const body = await postJson("/api/nmap/scan", {
            targets,
            discovery,
            staged,
            run_actions: getChecked("nmap-run-actions"),
            nmap_path: "nmap",
            nmap_args: getValue("nmap-args").trim(),
            scan_mode: scanMode,
            scan_options: scanOptions,
        });
        const jobId = body?.job?.id;
        setActionStatus(jobId ? `Nmap scan queued (job ${jobId})` : "Nmap scan queued");
        closeNmapScanModalAction();
        setValue("nmap-targets", "");
        nmapWizardState.postSubmitLock = true;
        setNmapWizardStep(1);
        updateNmapCommandPreview();
        refreshNmapScanButtonState();
        await pollSnapshot();
    } catch (err) {
        setActionStatus(`Scan failed: ${err.message}`, true);
    }
}

function bindActionButtons() {
    const bind = (id, handler) => {
        const node = document.getElementById(id);
        if (node) {
            node.addEventListener("click", handler);
        }
    };

    bind("nmap-scan-button", runNmapScan);
    bind("ribbon-launch-wizard-button", launchStartupWizardAction);
    bind("ribbon-workspace-new-action-button", createNewTemporaryProject);
    bind("ribbon-workspace-open-action-button", openWorkspaceFromRibbonAction);
    bind("ribbon-workspace-save-action-button", saveWorkspaceAction);
    bind("ribbon-workspace-save-as-action-button", saveWorkspaceAsAction);
    bind("ribbon-workspace-download-action-button", downloadWorkspaceBundleAction);
    bind("ribbon-workspace-restore-action-button", restoreWorkspaceBundleAction);
    bind("ribbon-import-xml-action-button", importNmapXmlFromRibbonAction);
    bind("ribbon-import-targets-action-button", importTargetsFromRibbonAction);
    bind("ribbon-export-json-action-button", exportWorkspaceJsonAction);
    bind("ribbon-export-csv-action-button", exportWorkspaceCsvAction);
    bind("ribbon-export-hosts-csv-action-button", exportHostsCsvAction);
    bind("hosts-export-json-button", exportHostsJsonAction);
    bind("hosts-export-csv-button", exportHostsCsvAction);
    bind("hosts-reset-filter-button", resetHostFiltersAction);
    bind("hosts-filter-show-all-button", () => setHostFilterAction("show_all"));
    bind("hosts-filter-hide-down-button", () => setHostFilterAction("hide_down"));
    bind("services-panel-toggle-button", toggleServicesPanelAction);
    bind("ribbon-export-project-report-json-action-button", () => exportProjectAiReportAction("json"));
    bind("ribbon-export-project-report-md-action-button", () => exportProjectAiReportAction("md"));
    bind("ribbon-export-project-report-push-action-button", pushProjectAiReportAction);
    bind("ribbon-export-ai-reports-action-button", exportAllHostAiReportsZipAction);
    bind("ribbon-scan-add-action-button", openAddScanAction);
    bind("ribbon-scan-manual-action-button", openManualScanAction);
    bind("ribbon-misc-host-selection-action-button", openHostSelectionAction);
    bind("ribbon-misc-script-cve-action-button", openScriptCveAction);
    bind("ribbon-logging-jobs-button", openJobsAction);
    bind("ribbon-logging-submitted-scans-button", openSubmittedScansAction);
    bind("ribbon-logging-scheduler-decisions-button", openSchedulerDecisionsAction);
    bind("ribbon-logging-ai-provider-button", openProviderLogsAction);
    bind("ribbon-scheduler-settings-button", openSchedulerSettingsAction);
    bind("ribbon-report-provider-settings-button", openReportProviderAction);
    bind("ribbon-app-settings-button", openAppSettingsAction);

    bind("workspace-refresh-button", refreshWorkspace);
    bind("workspace-save-note-button", saveHostNote);
    bind("workspace-run-tool-button", runManualTool);
    bind("workspace-run-scheduler-button", runSchedulerNow);
    bind("workspace-add-script-button", addScriptEntry);
    bind("workspace-add-cve-button", addCveEntry);
    bind("process-clear-finished-button", () => clearProcessesAction(false));
    bind("process-clear-all-button", () => clearProcessesAction(true));
    bind("graph-refresh-button", graphRefreshAction);
    bind("graph-rebuild-button", graphRebuildAction);
    bind("graph-export-json-button", () => graphExportAction("json"));
    bind("graph-export-graphml-button", () => graphExportAction("graphml"));
    bind("graph-export-svg-button", graphExportSvgAction);
    bind("graph-export-png-button", graphExportPngAction);
    bind("graph-filters-toggle-button", () => graphSetFiltersExpanded(!graphWorkspaceState.filtersExpanded));
    bind("graph-focus-selection-button", graphFocusSelectionAction);
    bind("graph-clear-focus-button", graphClearFocusAction);
    bind("graph-expand-selection-button", graphToggleExpandSelectionAction);
    bind("graph-collapse-expanded-button", graphCollapseExpandedAction);
    bind("graph-layout-save-button", graphSaveLayoutAction);
    bind("graph-layout-reset-button", graphResetLayoutAction);
    bind("graph-note-open-button", graphOpenNoteModalAction);
    bind("graph-note-save-button", graphSaveAnnotationAction);
    bind("graph-note-modal-close", () => closeGraphNoteModalAction(false));
    bind("graph-note-modal-cancel", () => closeGraphNoteModalAction(false));
    bind("graph-pin-toggle-button", graphTogglePinAction);
    bind("graph-detail-dock-toggle-button", graphToggleDetailModeAction);
    bind("graph-detail-close-button", graphDismissSelection);
    graphSetFiltersExpanded(graphWorkspaceState.filtersExpanded);
    setServicesPanelCollapsed(true);

    const graphScrollNode = getGraphCanvasScrollNode();
    if (graphScrollNode) {
        graphScrollNode.addEventListener("scroll", () => {
            if (graphWorkspaceState.detailMode === "floating" && graphHasActiveSelection()) {
                graphSyncDetailPresentation();
            }
        });
    }
    window.addEventListener("resize", () => {
        if (graphWorkspaceEnabled()) {
            graphSyncDetailPresentation();
        }
    });

    const hostSelect = document.getElementById("workspace-host-select");
    if (hostSelect) {
        hostSelect.addEventListener("change", async (event) => {
            await selectHost(event.target.value, {syncGraph: true, preserveGraphDetail: true});
        });
    }

    const hostsBody = document.getElementById("hosts-body");
    if (hostsBody) {
        hostsBody.addEventListener("click", async (event) => {
            const actionBtn = event.target.closest("button[data-host-action]");
            if (actionBtn) {
                if (await handleHostActionButtonAction(actionBtn)) {
                    return;
                }
            }

            const row = event.target.closest("tr[data-host-id]");
            if (!row) {
                return;
            }
            const hostId = parseInt(row.dataset.hostId, 10);
            if (!hostId) {
                return;
            }
            await selectHost(hostId, {syncGraph: true, preserveGraphDetail: true});
        });
    }

    const approvalsBody = document.getElementById("approvals-body");
    if (approvalsBody) {
        approvalsBody.addEventListener("click", async (event) => {
            const btn = event.target.closest("button[data-action]");
            if (!btn) {
                return;
            }
            const approvalId = parseInt(btn.dataset.approvalId, 10);
            if (!approvalId) {
                return;
            }
            if (btn.dataset.action === "approve") {
                await approveApproval(approvalId);
            } else if (btn.dataset.action === "allow-family") {
                await approveApproval(approvalId, "allowed");
            } else if (btn.dataset.action === "reject") {
                await rejectApproval(approvalId);
            } else if (btn.dataset.action === "suppress-family") {
                await rejectApproval(approvalId, "suppressed");
            }
        });
    }

    const jobsBody = document.getElementById("jobs-body");
    if (jobsBody) {
        jobsBody.addEventListener("click", async (event) => {
            const btn = event.target.closest("button[data-job-action]");
            if (!btn) {
                return;
            }
            const jobId = parseInt(btn.dataset.jobId, 10);
            if (!jobId) {
                return;
            }
            const action = String(btn.dataset.jobAction || "");
            if (action === "stop") {
                await stopJobAction(jobId);
            }
        });
    }

    const hostDetailPortsBody = document.getElementById("host-detail-ports");
    if (hostDetailPortsBody) {
        hostDetailPortsBody.addEventListener("click", (event) => {
            const btn = event.target.closest("button[data-screenshot-url]");
            if (!btn) {
                return;
            }
            openScreenshotModal(
                btn.dataset.screenshotUrl,
                btn.dataset.screenshotName,
                btn.dataset.screenshotPort,
            );
        });
    }

    const scriptsBody = document.getElementById("host-detail-scripts");
    if (scriptsBody) {
        scriptsBody.addEventListener("click", async (event) => {
            const viewBtn = event.target.closest("button[data-script-view-id]");
            if (viewBtn) {
                const viewId = parseInt(viewBtn.dataset.scriptViewId, 10);
                if (!viewId) {
                    return;
                }
                await openScriptOutputModal(viewId);
                return;
            }
            const deleteBtn = event.target.closest("button[data-script-delete-id]");
            if (!deleteBtn) {
                return;
            }
            const id = parseInt(deleteBtn.dataset.scriptDeleteId, 10);
            if (!id) {
                return;
            }
            await deleteScript(id);
        });
    }

    const cvesBody = document.getElementById("host-detail-cves");
    if (cvesBody) {
        cvesBody.addEventListener("click", async (event) => {
            const btn = event.target.closest("button[data-cve-delete-id]");
            if (!btn) {
                return;
            }
            const id = parseInt(btn.dataset.cveDeleteId, 10);
            if (!id) {
                return;
            }
            await deleteCve(id);
        });
    }

    const processesBody = document.getElementById("processes-body");
    if (processesBody) {
        processesBody.addEventListener("click", async (event) => {
            const btn = event.target.closest("button[data-process-action]");
            if (!btn) {
                return;
            }
            const processId = parseInt(btn.dataset.processId, 10);
            if (!processId) {
                return;
            }
            const action = btn.dataset.processAction;
            if (action === "output") {
                await openProcessOutputModal(processId);
                return;
            }
            if (action === "kill") {
                await killProcessAction(processId);
                return;
            }
            if (action === "retry") {
                await retryProcessAction(processId);
                return;
            }
            if (action === "close") {
                await closeProcessAction(processId);
            }
        });
    }

    bind("nmap-wizard-back", () => setNmapWizardStep(nmapWizardState.step - 1));
    bind("nmap-wizard-next", () => setNmapWizardStep(nmapWizardState.step + 1));
    bind("startup-wizard-back", startupWizardBackAction);
    bind("startup-wizard-next", startupWizardNextAction);
    bind("startup-wizard-skip", startupWizardSkipAction);
    bind("scheduler-test-provider-button", testSchedulerProviderAction);
    bind("project-report-push-button", pushProjectAiReportAction);
    bind("scheduler-modal-close", closeSchedulerSettingsAction);
    bind("report-provider-modal-close", closeReportProviderModalAction);
    bind("settings-modal-close", closeAppSettingsAction);
    bind("settings-config-refresh-button", refreshAppSettingsConfigAction);
    bind("settings-config-save-button", saveAppSettingsConfigAction);
    bind("settings-tool-audit-refresh-button", refreshToolAuditAction);
    bind("nmap-scan-modal-close", closeNmapScanModalAction);
    bind("manual-scan-modal-close", closeManualScanModalAction);
    bind("host-selection-modal-close", closeHostSelectionModalAction);
    bind("script-cve-modal-close", closeScriptCveModalAction);
    bind("provider-logs-modal-close", closeProviderLogsModalAction);
    bind("jobs-modal-close", closeJobsModalAction);
    bind("submitted-scans-modal-close", closeSubmittedScansModalAction);
    bind("scheduler-decisions-modal-close", closeSchedulerDecisionsModalAction);
    bind("provider-logs-refresh-button", loadProviderLogsAction);
    bind("provider-logs-copy-button", copyProviderLogsAction);
    bind("provider-logs-download-button", downloadProviderLogsAction);
    bind("host-ai-export-json-button", () => exportSelectedHostAiReportAction("json"));
    bind("host-ai-export-md-button", () => exportSelectedHostAiReportAction("md"));
    bind("host-remove-modal-close", () => closeHostRemoveModalAction(true));
    bind("host-remove-modal-cancel", () => closeHostRemoveModalAction(true));
    bind("host-remove-modal-confirm", confirmHostRemoveAction);
    bind("process-output-modal-close", () => closeProcessOutputModal(true));
    bind("process-output-refresh-button", () => refreshProcessOutputAction(true, false));
    bind("process-output-copy-button", copyProcessOutputAction);
    bind("process-output-command-copy", copyProcessCommandAction);
    bind("process-output-download-button", downloadProcessOutputAction);
    bind("script-output-modal-close", () => closeScriptOutputModal(true));
    bind("script-output-copy-button", copyScriptOutputAction);
    bind("script-output-command-copy", copyScriptCommandAction);
    bind("script-output-download-button", downloadScriptOutputAction);
    bind("screenshot-modal-close", () => closeScreenshotModal(true));
    bind("screenshot-copy-button", copyScreenshotAction);
    bind("screenshot-download-button", downloadScreenshotAction);
    bind("graph-layout-tidy-button", graphTidyLayoutAction);

    const restoreZipInput = document.getElementById("project-restore-zip-file");
    if (restoreZipInput) {
        restoreZipInput.addEventListener("change", restoreWorkspaceBundleSelectedAction);
    }

    const ribbonMenuToggles = document.querySelectorAll("[data-ribbon-menu-toggle]");
    ribbonMenuToggles.forEach((toggle) => {
        toggle.addEventListener("click", (event) => {
            event.preventDefault();
            event.stopPropagation();
            toggleRibbonMenu(toggle.getAttribute("data-ribbon-menu-toggle"));
        });
    });

    document.addEventListener("click", (event) => {
        if (!event.target.closest(".ribbon-menu")) {
            closeRibbonMenus();
        }
    });

    const graphResizeHandle = document.getElementById("graph-resize-handle");
    if (graphResizeHandle) {
        graphResizeHandle.addEventListener("pointerdown", startGraphWorkspaceResize);
        graphResizeHandle.addEventListener("dblclick", (event) => {
            event.preventDefault();
            resetGraphWorkspaceHeight();
        });
    }

    restoreGraphWorkspaceHeight();

    const processOutputModal = document.getElementById("process-output-modal");
    if (processOutputModal) {
        processOutputModal.addEventListener("click", (event) => {
            if (event.target === processOutputModal) {
                closeProcessOutputModal(true);
            }
        });
    }

    const scriptOutputModal = document.getElementById("script-output-modal");
    if (scriptOutputModal) {
        scriptOutputModal.addEventListener("click", (event) => {
            if (event.target === scriptOutputModal) {
                closeScriptOutputModal(true);
            }
        });
    }

    const screenshotModal = document.getElementById("screenshot-modal");
    if (screenshotModal) {
        screenshotModal.addEventListener("click", (event) => {
            if (event.target === screenshotModal) {
                closeScreenshotModal(true);
            }
        });
    }

    const nmapScanModal = document.getElementById("nmap-scan-modal");
    if (nmapScanModal) {
        nmapScanModal.addEventListener("click", (event) => {
            if (event.target === nmapScanModal) {
                closeNmapScanModalAction();
            }
        });
    }

    const manualScanModal = document.getElementById("manual-scan-modal");
    if (manualScanModal) {
        manualScanModal.addEventListener("click", (event) => {
            if (event.target === manualScanModal) {
                closeManualScanModalAction();
            }
        });
    }

    const hostSelectionModal = document.getElementById("host-selection-modal");
    if (hostSelectionModal) {
        hostSelectionModal.addEventListener("click", (event) => {
            if (event.target === hostSelectionModal) {
                closeHostSelectionModalAction();
            }
        });
    }

    const scriptCveModal = document.getElementById("script-cve-modal");
    if (scriptCveModal) {
        scriptCveModal.addEventListener("click", (event) => {
            if (event.target === scriptCveModal) {
                closeScriptCveModalAction();
            }
        });
    }

    const providerLogsModal = document.getElementById("provider-logs-modal");
    if (providerLogsModal) {
        providerLogsModal.addEventListener("click", (event) => {
            if (event.target === providerLogsModal) {
                closeProviderLogsModalAction();
            }
        });
    }

    const jobsModal = document.getElementById("jobs-modal");
    if (jobsModal) {
        jobsModal.addEventListener("click", (event) => {
            if (event.target === jobsModal) {
                closeJobsModalAction();
            }
        });
    }

    const submittedScansModal = document.getElementById("submitted-scans-modal");
    if (submittedScansModal) {
        submittedScansModal.addEventListener("click", (event) => {
            if (event.target === submittedScansModal) {
                closeSubmittedScansModalAction();
            }
        });
    }

    const schedulerDecisionsModal = document.getElementById("scheduler-decisions-modal");
    if (schedulerDecisionsModal) {
        schedulerDecisionsModal.addEventListener("click", (event) => {
            if (event.target === schedulerDecisionsModal) {
                closeSchedulerDecisionsModalAction();
            }
        });
    }

    const hostRemoveModal = document.getElementById("host-remove-modal");
    if (hostRemoveModal) {
        hostRemoveModal.addEventListener("click", (event) => {
            if (event.target === hostRemoveModal) {
                closeHostRemoveModalAction(true);
            }
        });
    }

    const graphNoteModal = document.getElementById("graph-note-modal");
    if (graphNoteModal) {
        graphNoteModal.addEventListener("click", (event) => {
            if (event.target === graphNoteModal) {
                closeGraphNoteModalAction(false);
            }
        });
    }

    const schedulerModal = document.getElementById("scheduler-settings-modal");
    if (schedulerModal) {
        schedulerModal.addEventListener("click", (event) => {
            if (event.target === schedulerModal) {
                closeSchedulerSettingsAction();
            }
        });
    }

    const reportProviderModal = document.getElementById("report-provider-modal");
    if (reportProviderModal) {
        reportProviderModal.addEventListener("click", (event) => {
            if (event.target === reportProviderModal) {
                closeReportProviderModalAction();
            }
        });
    }

    const appSettingsModal = document.getElementById("app-settings-modal");
    if (appSettingsModal) {
        appSettingsModal.addEventListener("click", (event) => {
            if (event.target === appSettingsModal) {
                closeAppSettingsAction();
            }
        });
    }

    document.addEventListener("keydown", (event) => {
        if (event.key !== "Escape") {
            return;
        }
        if (ribbonMenuState.openMenuId) {
            closeRibbonMenus();
            return;
        }
        if (processOutputState.modalOpen) {
            closeProcessOutputModal(true);
            return;
        }
        if (scriptOutputState.modalOpen) {
            closeScriptOutputModal(true);
            return;
        }
        if (screenshotModalState.modalOpen) {
            closeScreenshotModal(true);
            return;
        }
        if (uiModalState.nmapScanOpen) {
            closeNmapScanModalAction();
            return;
        }
        if (uiModalState.manualScanOpen) {
            closeManualScanModalAction();
            return;
        }
        if (uiModalState.hostSelectionOpen) {
            closeHostSelectionModalAction();
            return;
        }
        if (uiModalState.scriptCveOpen) {
            closeScriptCveModalAction();
            return;
        }
        if (uiModalState.providerLogsOpen) {
            closeProviderLogsModalAction();
            return;
        }
        if (uiModalState.jobsOpen) {
            closeJobsModalAction();
            return;
        }
        if (uiModalState.submittedScansOpen) {
            closeSubmittedScansModalAction();
            return;
        }
        if (uiModalState.schedulerDecisionsOpen) {
            closeSchedulerDecisionsModalAction();
            return;
        }
        if (uiModalState.hostRemoveOpen) {
            closeHostRemoveModalAction(true);
            return;
        }
        if (uiModalState.graphNoteOpen) {
            closeGraphNoteModalAction(false);
            return;
        }
        if (uiModalState.settingsOpen) {
            closeAppSettingsAction();
            return;
        }
        if (uiModalState.schedulerOpen) {
            closeSchedulerSettingsAction();
            return;
        }
        if (uiModalState.reportProviderOpen) {
            closeReportProviderModalAction();
            return;
        }
        if (graphWorkspaceState.detailMode === "floating" && graphHasActiveSelection()) {
            graphDismissSelection();
            return;
        }
        if (startupWizardState.open) {
            setStartupWizardOpen(false);
        }
    });

    document.addEventListener("pointerdown", (event) => {
        if (graphWorkspaceState.detailMode !== "floating" || !graphHasActiveSelection()) {
            return;
        }
        if (
            ribbonMenuState.openMenuId
            || processOutputState.modalOpen
            || scriptOutputState.modalOpen
            || screenshotModalState.modalOpen
            || uiModalState.nmapScanOpen
            || uiModalState.manualScanOpen
            || uiModalState.hostSelectionOpen
            || uiModalState.scriptCveOpen
            || uiModalState.providerLogsOpen
            || uiModalState.jobsOpen
            || uiModalState.submittedScansOpen
            || uiModalState.schedulerDecisionsOpen
            || uiModalState.hostRemoveOpen
            || uiModalState.graphNoteOpen
            || uiModalState.settingsOpen
            || uiModalState.schedulerOpen
            || uiModalState.reportProviderOpen
            || startupWizardState.open
        ) {
            return;
        }
        const target = event.target;
        if (!(target instanceof Element)) {
            return;
        }
        if (target.closest("#graph-detail-panel")) {
            return;
        }
        if (target.closest("[data-graph-node-id], [data-graph-edge-id]")) {
            return;
        }
        const graphSection = getGraphWorkspaceSection();
        if (graphSection && graphSection.contains(target)) {
            return;
        }
        graphDismissSelection();
    });

    const wizardGotoButtons = document.querySelectorAll("[data-wizard-goto]");
    wizardGotoButtons.forEach((button) => {
        button.addEventListener("click", () => {
            setNmapWizardStep(button.getAttribute("data-wizard-goto"));
        });
    });

    const nmapWizardRoot = document.getElementById("nmap-wizard");
    if (nmapWizardRoot) {
        const inputs = nmapWizardRoot.querySelectorAll("input, select, textarea");
        inputs.forEach((node) => {
            const eventName = node.tagName === "INPUT" && (node.type === "checkbox" || node.type === "radio")
                ? "change"
                : (node.tagName === "SELECT" ? "change" : "input");
            node.addEventListener(eventName, () => {
                nmapWizardState.postSubmitLock = false;
                if (node.name === "nmap-scan-mode") {
                    setNmapWizardStep(2);
                }
                refreshNmapModeOptions();
            });
        });
    }

    ["nmap-args"].forEach((id) => {
        const node = document.getElementById(id);
        if (!node) {
            return;
        }
        node.addEventListener("input", () => {
            nmapWizardState.postSubmitLock = false;
            updateNmapCommandPreview();
        });
    });

    resetNmapScanWizardState({scrollIntoView: false, focusTargets: false});
}

window.addEventListener("DOMContentLoaded", () => {
    const bootstrapNode = document.getElementById("initial-snapshot");
    if (bootstrapNode && bootstrapNode.textContent) {
        try {
            const snapshot = JSON.parse(bootstrapNode.textContent);
            renderSnapshot(snapshot);
        } catch (_err) {
            setLiveChip("Init Error", true);
        }
    }

    if (window.LEGION_WS_ENABLED) {
        connectSnapshotWebSocket();
    } else {
        setLiveChip("Polling/API", false);
        pollSnapshot();
        window.setInterval(pollSnapshot, 2000);
    }

    loadSchedulerPreferences();
    loadApprovals();

    const schedulerForm = document.getElementById("scheduler-form");
    if (schedulerForm) {
        schedulerForm.addEventListener("submit", saveSchedulerPreferences);
    }
    const schedulerProviderSelect = document.getElementById("scheduler-provider-select");
    if (schedulerProviderSelect) {
        schedulerProviderSelect.addEventListener("change", () => {
            setSchedulerProviderFieldVisibility(schedulerProviderSelect.value);
        });
        setSchedulerProviderFieldVisibility(schedulerProviderSelect.value);
    }
    const reportProviderForm = document.getElementById("report-provider-form");
    if (reportProviderForm) {
        reportProviderForm.addEventListener("submit", saveProjectReportDeliveryPreferences);
    }

    bindActionButtons();
    bindGraphWorkspaceEvents();
    initializeStartupWizard();
    refreshWorkspace();
});
