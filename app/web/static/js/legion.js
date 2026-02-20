const workspaceState = {
    hosts: [],
    services: [],
    tools: [],
    toolsHydrated: false,
    toolsLoading: false,
    selectedHostId: null,
    hostDetail: null,
};

const processOutputState = {
    processId: null,
    offset: 0,
    complete: true,
    status: "",
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
    hostRemoveOpen: false,
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
        || uiModalState.hostRemoveOpen
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
        return;
    }

    const hasPrevious = hosts.some((host) => String(host.id) === String(previous));
    workspaceState.selectedHostId = hasPrevious ? previous : hosts[0].id;
    select.value = String(workspaceState.selectedHostId);
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

        const rescanBtn = document.createElement("button");
        rescanBtn.type = "button";
        rescanBtn.className = "icon-btn";
        rescanBtn.dataset.hostAction = "rescan";
        rescanBtn.dataset.hostId = String(host.id || "");
        rescanBtn.title = "Rescan";
        rescanBtn.setAttribute("aria-label", "Rescan");
        rescanBtn.innerHTML = '<i class="fa-solid fa-rotate-right" aria-hidden="true"></i>';
        actionsCell.appendChild(rescanBtn);

        const digDeeperBtn = document.createElement("button");
        digDeeperBtn.type = "button";
        digDeeperBtn.className = "icon-btn";
        digDeeperBtn.dataset.hostAction = "dig-deeper";
        digDeeperBtn.dataset.hostId = String(host.id || "");
        digDeeperBtn.title = "Dig Deeper";
        digDeeperBtn.setAttribute("aria-label", "Dig Deeper");
        digDeeperBtn.innerHTML = '<i class="fa-solid fa-brain" aria-hidden="true"></i>';
        actionsCell.appendChild(digDeeperBtn);

        const removeBtn = document.createElement("button");
        removeBtn.type = "button";
        removeBtn.className = "icon-btn icon-btn-danger";
        removeBtn.dataset.hostAction = "remove";
        removeBtn.dataset.hostId = String(host.id || "");
        removeBtn.title = "Remove host";
        removeBtn.setAttribute("aria-label", "Remove host");
        removeBtn.innerHTML = '<i class="fa-solid fa-trash" aria-hidden="true"></i>';
        actionsCell.appendChild(removeBtn);

        tr.appendChild(actionsCell);
        body.appendChild(tr);
    });
    setText("host-count", workspaceState.hosts.length);
    renderHostSelector(workspaceState.hosts);
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
        tr.appendChild(makeCell(service.service || ""));
        tr.appendChild(makeCell(service.host_count || 0));
        tr.appendChild(makeCell(service.port_count || 0));
        tr.appendChild(makeCell(Array.isArray(service.protocols) ? service.protocols.join(",") : ""));
        body.appendChild(tr);
    });
    setText("service-count", workspaceState.services.length);
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
        const target = `${process.hostIp || ""}:${process.port || ""}/${process.protocol || ""}`;
        tr.appendChild(makeCell(target));
        const statusCell = document.createElement("td");
        const statusWrap = document.createElement("span");
        statusWrap.className = "process-status";
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
        viewBtn.textContent = "Output";
        viewBtn.dataset.processAction = "output";
        viewBtn.dataset.processId = String(process.id || "");
        actions.appendChild(viewBtn);

        const retryBtn = document.createElement("button");
        retryBtn.type = "button";
        retryBtn.textContent = "Retry";
        retryBtn.dataset.processAction = "retry";
        retryBtn.dataset.processId = String(process.id || "");
        actions.appendChild(retryBtn);

        if (isProcessRunning(process.status)) {
            const killBtn = document.createElement("button");
            killBtn.type = "button";
            killBtn.textContent = "Kill";
            killBtn.dataset.processAction = "kill";
            killBtn.dataset.processId = String(process.id || "");
            actions.appendChild(killBtn);
        }

        const hideBtn = document.createElement("button");
        hideBtn.type = "button";
        hideBtn.textContent = "Hide";
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
    setValue("process-output-text", text || "");
}

function setProcessOutputCommand(text) {
    setText("process-output-command", text || "");
}

function setScriptOutputMeta(text) {
    setText("script-output-meta", text || "");
}

function setScriptOutputText(text) {
    setValue("script-output-text", text || "");
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
        await postJson("/api/project/open", {path});
        setValue("project-open-path", path);
        startupWizardState.summary.project = `opened ${path}`;
    } else {
        await postJson("/api/project/new-temp", {});
        startupWizardState.summary.project = "created new temporary project";
    }
    workspaceState.selectedHostId = null;
    workspaceState.hostDetail = null;
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

function closeHostRemoveModalAction(clearSelection = true) {
    setHostRemoveModalOpen(false);
    if (clearSelection) {
        hostRemoveState.hostId = null;
        hostRemoveState.hostIp = "";
        hostRemoveState.hostName = "";
        setText("host-remove-modal-target", "");
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
        workspaceState.hostDetail = null;
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
        setWorkspaceStatus("Select a host first to export AI report.", true);
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

    setActionStatus("Pushing project AI report...");
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
    await refreshAppSettingsConfigAction();
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
    const text = getValue("process-output-text");
    await copyTextToClipboard(text, "Process output copied to clipboard", "No process output to copy");
}

async function copyProcessCommandAction() {
    const node = document.getElementById("process-output-command");
    const text = node ? String(node.textContent || "") : "";
    await copyTextToClipboard(text, "Command copied to clipboard", "No command to copy");
}

async function copyScriptOutputAction() {
    const text = getValue("script-output-text");
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
    const text = getValue("process-output-text");
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
    const text = getValue("script-output-text");
    if (!text) {
        setWorkspaceStatus("No script output to download", true);
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
        setValue("provider-logs-text", providerLogsState.text);
        setText(
            "provider-logs-meta",
            `Entries ${providerLogsState.count} | bytes ${providerLogsState.text.length}`
        );
    } catch (err) {
        const message = `Failed to load provider logs: ${err.message}`;
        providerLogsState.text = message;
        setValue("provider-logs-text", message);
        setText("provider-logs-meta", "Load failed");
        setWorkspaceStatus(message, true);
    }
}

async function copyProviderLogsAction() {
    const text = getValue("provider-logs-text");
    await copyTextToClipboard(text, "AI provider logs copied to clipboard", "No provider logs to copy");
}

function downloadProviderLogsAction() {
    const text = getValue("provider-logs-text");
    if (!text) {
        setWorkspaceStatus("No provider logs to download", true);
        return;
    }
    const blob = new Blob([text], {type: "text/plain;charset=utf-8"});
    const url = URL.createObjectURL(blob);
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const a = document.createElement("a");
    a.href = url;
    a.download = `ai-provider-logs-${stamp}.txt`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    setWorkspaceStatus("AI provider logs downloaded");
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
    const current = getValue("process-output-text");
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
        setWorkspaceStatus(resetAll ? "Hidden all non-running processes" : "Hidden finished/failed processes");
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
        const target = `${decision.host_ip || ""}:${decision.port || ""}/${decision.protocol || ""}`;
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

        const familyLabel = document.createElement("label");
        familyLabel.className = "checkbox";
        const familyCheckbox = document.createElement("input");
        familyCheckbox.type = "checkbox";
        familyCheckbox.dataset.approvalFamily = String(item.id || "");
        familyLabel.appendChild(familyCheckbox);
        familyLabel.appendChild(document.createTextNode("Always allow family"));

        actionsCell.appendChild(approveBtn);
        actionsCell.appendChild(rejectBtn);
        actionsCell.appendChild(familyLabel);

        const target = `${item.host_ip || ""}:${item.port || ""}/${item.protocol || ""}`;
        tr.appendChild(makeCell(item.id || ""));
        tr.appendChild(makeCell(target));
        tr.appendChild(makeCell(item.tool_id || item.label || ""));
        tr.appendChild(makeCell(item.danger_categories || ""));
        tr.appendChild(makeCell(item.status || ""));
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

function renderHostDetail(payload) {
    workspaceState.hostDetail = payload || null;
    const host = payload?.host || {};
    const ports = payload?.ports || [];
    const cves = payload?.cves || [];
    const screenshots = payload?.screenshots || [];
    const aiAnalysis = payload?.ai_analysis || {};
    const aiTechnologies = Array.isArray(aiAnalysis?.technologies) ? aiAnalysis.technologies : [];
    const aiFindings = Array.isArray(aiAnalysis?.findings) ? aiAnalysis.findings : [];
    const aiManualTests = Array.isArray(aiAnalysis?.manual_tests) ? aiAnalysis.manual_tests : [];
    const aiHostUpdates = aiAnalysis?.host_updates || {};

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
                tr.appendChild(makeCell((scriptRow.output || "").slice(0, 140)));
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
    setText("scheduler-mode", prefs.mode || "");
    setText("scheduler-goal", prefs.goal_profile || "");
    setText("scheduler-families", prefs.preapproved_families_count || 0);

    setValue("scheduler-mode-select", prefs.mode || "deterministic");
    setValue("scheduler-goal-select", prefs.goal_profile || "internal_asset_discovery");
    setValue("scheduler-provider-select", prefs.provider || "none");
    setValue("scheduler-concurrency-input", String(prefs.max_concurrency || 1));
    setValue("scheduler-max-jobs-input", String(prefs.max_jobs || 200));

    const providers = prefs.providers || {};
    const lmStudio = providers.lm_studio || {};
    const openai = providers.openai || {};
    const claude = providers.claude || {};
    const projectDelivery = prefs.project_report_delivery || {};
    const projectDeliveryMtls = projectDelivery.mtls || {};

    setChecked("provider-lmstudio-enabled", lmStudio.enabled);
    setValue("provider-lmstudio-baseurl", lmStudio.base_url || "");
    setValue("provider-lmstudio-model", lmStudio.model || "");
    setValue("provider-lmstudio-apikey", "");

    setChecked("provider-openai-enabled", openai.enabled);
    setValue("provider-openai-baseurl", openai.base_url || "");
    setValue("provider-openai-model", openai.model || "");
    setValue("provider-openai-apikey", "");

    setChecked("provider-claude-enabled", claude.enabled);
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
            enabled: getChecked("provider-lmstudio-enabled"),
            base_url: getValue("provider-lmstudio-baseurl"),
            model: getValue("provider-lmstudio-model"),
        },
        openai: {
            enabled: getChecked("provider-openai-enabled"),
            base_url: getValue("provider-openai-baseurl"),
            model: getValue("provider-openai-model"),
        },
        claude: {
            enabled: getChecked("provider-claude-enabled"),
            base_url: getValue("provider-claude-baseurl"),
            model: getValue("provider-claude-model"),
        },
    };

    if (mode === "ai") {
        if (selectedProvider === "lm_studio") {
            providers.lm_studio.enabled = true;
            providers.lm_studio.base_url = providers.lm_studio.base_url || "http://127.0.0.1:1234/v1";
            providers.lm_studio.model = providers.lm_studio.model || "o3-7b";
        } else if (selectedProvider === "openai") {
            providers.openai.enabled = true;
            providers.openai.base_url = providers.openai.base_url || "https://api.openai.com/v1";
            providers.openai.model = providers.openai.model || "gpt-4.1-mini";
        } else if (selectedProvider === "claude") {
            providers.claude.enabled = true;
        }
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

    return {
        mode,
        goal_profile: getValue("scheduler-goal-select"),
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
    const body = await fetchJson("/api/workspace/hosts");
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

async function approveApproval(approvalId) {
    const familyCheckbox = document.querySelector(`input[data-approval-family='${approvalId}']`);
    const approveFamily = Boolean(familyCheckbox?.checked);
    try {
        await postJson(`/api/scheduler/approvals/${approvalId}/approve`, {
            approve_family: approveFamily,
            run_now: true,
        });
        setWorkspaceStatus(`Approval ${approvalId} accepted`);
        await Promise.all([loadApprovals(), pollSnapshot()]);
    } catch (err) {
        setWorkspaceStatus(`Approve failed: ${err.message}`, true);
    }
}

async function rejectApproval(approvalId) {
    try {
        await postJson(`/api/scheduler/approvals/${approvalId}/reject`, {
            reason: "rejected in web workspace",
        });
        setWorkspaceStatus(`Approval ${approvalId} rejected`);
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
    if (Array.isArray(snapshot.hosts)) {
        renderHosts(snapshot.hosts);
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

    if (workspaceState.selectedHostId && !workspaceState.hostDetail) {
        loadHostDetail(workspaceState.selectedHostId).catch(() => {});
    }
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
        await postJson("/api/project/new-temp", {});
        setActionStatus("Created temporary project");
        workspaceState.hostDetail = null;
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
        await postJson("/api/project/open", {path});
        setActionStatus("Project opened");
        workspaceState.hostDetail = null;
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
    const finalExtraTokens = hasStatsEvery ? extraTokens : [...extraTokens, "--stats-every", "15s"];
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
    bind("ribbon-export-project-report-json-action-button", () => exportProjectAiReportAction("json"));
    bind("ribbon-export-project-report-md-action-button", () => exportProjectAiReportAction("md"));
    bind("ribbon-export-project-report-push-action-button", pushProjectAiReportAction);
    bind("ribbon-export-ai-reports-action-button", exportAllHostAiReportsZipAction);
    bind("ribbon-scan-add-action-button", openAddScanAction);
    bind("ribbon-scan-manual-action-button", openManualScanAction);
    bind("ribbon-misc-host-selection-action-button", openHostSelectionAction);
    bind("ribbon-misc-script-cve-action-button", openScriptCveAction);
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

    const hostSelect = document.getElementById("workspace-host-select");
    if (hostSelect) {
        hostSelect.addEventListener("change", async (event) => {
            workspaceState.selectedHostId = parseInt(event.target.value, 10);
            workspaceState.hostDetail = null;
            try {
                await loadHostDetail(workspaceState.selectedHostId);
            } catch (err) {
                setWorkspaceStatus(`Load host detail failed: ${err.message}`, true);
            }
        });
    }

    const hostsBody = document.getElementById("hosts-body");
    if (hostsBody) {
        hostsBody.addEventListener("click", async (event) => {
            const actionBtn = event.target.closest("button[data-host-action]");
            if (actionBtn) {
                const hostId = parseInt(actionBtn.dataset.hostId, 10);
                const action = String(actionBtn.dataset.hostAction || "");
                if (!hostId) {
                    return;
                }
                if (action === "rescan") {
                    await rescanHostAction(hostId);
                    return;
                }
                if (action === "dig-deeper") {
                    await digDeeperHostAction(hostId);
                    return;
                }
                if (action === "remove") {
                    requestHostRemoveAction(hostId);
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
            workspaceState.selectedHostId = hostId;
            setValue("workspace-host-select", hostId);
            workspaceState.hostDetail = null;
            try {
                await loadHostDetail(hostId);
            } catch (err) {
                setWorkspaceStatus(`Load host detail failed: ${err.message}`, true);
            }
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
            } else if (btn.dataset.action === "reject") {
                await rejectApproval(approvalId);
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
    bind("nmap-scan-modal-close", closeNmapScanModalAction);
    bind("manual-scan-modal-close", closeManualScanModalAction);
    bind("host-selection-modal-close", closeHostSelectionModalAction);
    bind("script-cve-modal-close", closeScriptCveModalAction);
    bind("provider-logs-modal-close", closeProviderLogsModalAction);
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

    const hostRemoveModal = document.getElementById("host-remove-modal");
    if (hostRemoveModal) {
        hostRemoveModal.addEventListener("click", (event) => {
            if (event.target === hostRemoveModal) {
                closeHostRemoveModalAction(true);
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
        if (uiModalState.hostRemoveOpen) {
            closeHostRemoveModalAction(true);
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
        if (startupWizardState.open) {
            setStartupWizardOpen(false);
        }
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
    const reportProviderForm = document.getElementById("report-provider-form");
    if (reportProviderForm) {
        reportProviderForm.addEventListener("submit", saveProjectReportDeliveryPreferences);
    }

    bindActionButtons();
    initializeStartupWizard();
    refreshWorkspace();
});
