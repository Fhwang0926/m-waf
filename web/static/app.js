(() => {
  "use strict";

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));
  const svgNS = "http://www.w3.org/2000/svg";
  const kstTimeZone = "Asia/Seoul";
  const kstDateTimeFormatter = new Intl.DateTimeFormat("en-US", {
    timeZone: kstTimeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  });
  let sidebarTrigger = null;
  let lastEventTrigger = null;
  let taskDialogTrigger = null;
  let globalBusyDialog = null;
  let globalBusyTimer = 0;

  function formatKSTDateTime(value) {
    const date = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(date.getTime())) return "";
    const parts = {};
    kstDateTimeFormatter.formatToParts(date).forEach((part) => {
      if (part.type !== "literal") parts[part.type] = part.value;
    });
    return `${parts.year}-${parts.month}-${parts.day} ${parts.hour}:${parts.minute}:${parts.second}`;
  }

  function ensureGlobalBusyDialog() {
    if (globalBusyDialog) return globalBusyDialog;
    const dialog = document.createElement("dialog");
    dialog.className = "global-busy-dialog";
    dialog.dataset.globalBusy = "true";
    dialog.tabIndex = -1;
    dialog.setAttribute("aria-labelledby", "global-busy-title");
    dialog.setAttribute("aria-describedby", "global-busy-detail");
    const content = document.createElement("div");
    content.className = "global-busy-content";
    content.setAttribute("role", "status");
    content.setAttribute("aria-live", "polite");
    const spinner = document.createElement("span");
    spinner.className = "global-busy-spinner";
    spinner.setAttribute("aria-hidden", "true");
    const text = document.createElement("div");
    const title = document.createElement("strong");
    title.id = "global-busy-title";
    const detail = document.createElement("p");
    detail.id = "global-busy-detail";
    detail.className = "muted";
    text.append(title, detail);
    content.append(spinner, text);
    dialog.append(content);
    dialog.addEventListener("cancel", (event) => event.preventDefault());
    document.body.append(dialog);
    globalBusyDialog = dialog;
    return dialog;
  }

  function showGlobalBusy(message = "작업을 처리하는 중입니다.") {
    const dialog = ensureGlobalBusyDialog();
    const title = $("#global-busy-title", dialog);
    const detail = $("#global-busy-detail", dialog);
    if (title) title.textContent = message;
    if (detail) detail.textContent = "잠시만 기다려 주세요.";
    document.body.classList.add("global-busy");
    document.body.setAttribute("aria-busy", "true");
    if (!dialog.open) {
      if (typeof dialog.showModal === "function") dialog.showModal();
      else dialog.setAttribute("open", "");
    }
    window.clearTimeout(globalBusyTimer);
    globalBusyTimer = window.setTimeout(() => {
      if (detail && dialog.open) detail.textContent = "처리가 지연되고 있습니다. 새로고침하거나 같은 작업을 다시 요청하지 마세요.";
    }, 10000);
  }

  function hideGlobalBusy() {
    window.clearTimeout(globalBusyTimer);
    globalBusyTimer = 0;
    document.body.classList.remove("global-busy");
    document.body.removeAttribute("aria-busy");
    if (!globalBusyDialog || !globalBusyDialog.open) return;
    if (typeof globalBusyDialog.close === "function") globalBusyDialog.close();
    else globalBusyDialog.removeAttribute("open");
  }

  function navigationNeedsBusy(event, link) {
    if (!link || event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return false;
    if (link.hasAttribute("download") || link.dataset.noBusy !== undefined || link.target && link.target !== "_self") return false;
    let destination;
    try {
      destination = new URL(link.href, window.location.href);
    } catch (_) {
      return false;
    }
    if (destination.origin !== window.location.origin || !/^https?:$/.test(destination.protocol)) return false;
    const current = new URL(window.location.href);
    return destination.pathname !== current.pathname || destination.search !== current.search;
  }

  function initializeGlobalBusy() {
    document.addEventListener("submit", (event) => {
      const form = event.target;
      if (!(form instanceof HTMLFormElement) || event.defaultPrevented || form.dataset.noBusy !== undefined || form.method === "dialog" || form.target && form.target !== "_self") return;
      if (form.dataset.submitting === "true") {
        event.preventDefault();
        return;
      }
      form.dataset.submitting = "true";
      const method = (form.method || "get").toUpperCase();
      const submitter = event.submitter;
      const message = submitter && submitter.dataset.busyMessage || form.dataset.busyMessage || (method === "GET" ? "페이지를 불러오는 중입니다." : "작업 요청을 처리하는 중입니다.");
      showGlobalBusy(message);
    });
    document.addEventListener("click", (event) => {
      const link = event.target.closest("a[href]");
      if (navigationNeedsBusy(event, link)) showGlobalBusy(link.dataset.busyMessage || "페이지를 불러오는 중입니다.");
    });
    window.addEventListener("pageshow", () => {
      $$('form[data-submitting="true"]').forEach((form) => delete form.dataset.submitting);
      hideGlobalBusy();
    });
  }

  async function copyText(text) {
    if (!navigator.clipboard || !window.isSecureContext) throw new Error("clipboard unavailable");
    await navigator.clipboard.writeText(text);
  }

  function setSidebar(open) {
    const wasOpen = document.body.classList.contains("sidebar-open");
    document.body.classList.toggle("sidebar-open", open);
    const trigger = $("[data-sidebar-open]");
    if (trigger) trigger.setAttribute("aria-expanded", open ? "true" : "false");
    if (open) {
      sidebarTrigger = document.activeElement;
      const close = $("[data-sidebar-close]");
      if (close) window.requestAnimationFrame(() => close.focus());
    } else if (wasOpen && sidebarTrigger && typeof sidebarTrigger.focus === "function") {
      sidebarTrigger.focus();
      sidebarTrigger = null;
    }
  }

  function desktopSidebarExpanded() {
    if (document.body.classList.contains("sidebar-expanded")) return true;
    if (document.body.classList.contains("sidebar-collapsed")) return false;
    return !window.matchMedia("(max-width: 1100px)").matches;
  }

  function updateDesktopSidebarButton() {
    const expanded = desktopSidebarExpanded();
    $$('[data-sidebar-toggle]').forEach((button) => {
      const label = expanded ? "메뉴 접기" : "메뉴 펼치기";
      const icon = $("[data-sidebar-toggle-icon]", button);
      button.setAttribute("aria-expanded", expanded ? "true" : "false");
      button.setAttribute("aria-label", label);
      button.title = label;
      if (icon) icon.textContent = expanded ? "‹" : "›";
    });
  }

  function setDesktopSidebar(expanded) {
    document.body.classList.toggle("sidebar-expanded", expanded);
    document.body.classList.toggle("sidebar-collapsed", !expanded);
    try {
      window.localStorage.setItem("mwaf-sidebar", expanded ? "expanded" : "collapsed");
    } catch (_) {
      // Storage may be unavailable in hardened browser profiles.
    }
    updateDesktopSidebarButton();
  }

  function initializeDesktopSidebar() {
    if (!$(".sidebar")) return;
    let preference = "";
    try {
      preference = window.localStorage.getItem("mwaf-sidebar") || "";
    } catch (_) {
      preference = "";
    }
    if (preference === "expanded") document.body.classList.add("sidebar-expanded");
    if (preference === "collapsed") document.body.classList.add("sidebar-collapsed");
    updateDesktopSidebarButton();
    window.requestAnimationFrame(() => {
      window.requestAnimationFrame(() => document.body.classList.add("sidebar-ready"));
    });
    window.addEventListener("resize", () => {
      if (!window.matchMedia("(max-width: 760px)").matches) setSidebar(false);
      updateDesktopSidebarButton();
    });
  }

  function openTaskDialog(dialog, trigger) {
    if (!dialog) return;
    taskDialogTrigger = trigger || document.activeElement;
    if (typeof dialog.showModal === "function") {
      if (!dialog.open) dialog.showModal();
    } else {
      dialog.setAttribute("open", "");
    }
    const focusTarget = $("[autofocus]", dialog) || $("input:not([type=hidden]), select, textarea, button", dialog);
    if (focusTarget) window.requestAnimationFrame(() => focusTarget.focus());
  }

  function closeTaskDialog(dialog) {
    if (!dialog) return;
    if (typeof dialog.close === "function" && dialog.open) dialog.close();
    else dialog.removeAttribute("open");
    if (taskDialogTrigger && typeof taskDialogTrigger.focus === "function") taskDialogTrigger.focus();
    taskDialogTrigger = null;
  }

  function initializeTaskDialogs() {
    $$('dialog[data-task-dialog]').forEach((dialog) => {
      dialog.addEventListener("close", () => {
        if (taskDialogTrigger && typeof taskDialogTrigger.focus === "function") taskDialogTrigger.focus();
        taskDialogTrigger = null;
      });
      if (!dialog.hasAttribute("data-dialog-auto-open")) return;
      if (dialog.hasAttribute("open") && typeof dialog.showModal === "function") dialog.removeAttribute("open");
      openTaskDialog(dialog, null);
    });
  }

  function initializeLiveReload() {
    const shell = $(".app-shell[data-live-reload=true]");
    if (!shell) return;
    let instanceID = shell.dataset.liveReloadInstance || "";
    const check = async () => {
      try {
        const response = await fetch("/health/live", { headers: { Accept: "application/json" }, cache: "no-store" });
        if (response.ok) {
          const data = await response.json();
          if (instanceID && data.instance_id && data.instance_id !== instanceID) {
            window.location.reload();
            return;
          }
          if (data.instance_id) instanceID = data.instance_id;
        }
      } catch (_) {
        // The Manager is briefly unavailable while the development binary restarts.
      }
      window.setTimeout(check, 1000);
    };
    check();
  }

  function setRefreshState(delayed, at = new Date()) {
    const status = $("[data-refresh-status]");
    const dot = status && $(".status-dot", status);
    const time = $("[data-last-refreshed]");
    if (status) status.title = delayed ? "API 갱신에 실패해 기존 데이터를 유지하고 있습니다." : "정상적으로 갱신되었습니다.";
    if (dot) dot.className = `status-dot ${delayed ? "warn" : "ok"}`;
    if (time) time.textContent = delayed ? "갱신 지연" : `${formatKSTDateTime(at).slice(11)} KST`;
  }

  function startVisiblePolling(callback) {
    let timer = 0;
    const schedule = () => {
      window.clearTimeout(timer);
      if (!document.hidden) timer = window.setTimeout(run, 30000);
    };
    const run = async () => {
      if (document.hidden) return;
      try {
        await callback();
        setRefreshState(false);
      } catch (_) {
        setRefreshState(true);
      } finally {
        schedule();
      }
    };
    document.addEventListener("visibilitychange", () => {
      window.clearTimeout(timer);
      if (!document.hidden) run();
    });
    schedule();
  }

  function createSVGElement(name, attributes = {}) {
    const element = document.createElementNS(svgNS, name);
    Object.entries(attributes).forEach(([key, value]) => element.setAttribute(key, String(value)));
    return element;
  }

  function drawTrendChart(container, series) {
    if (!container) return;
    container.replaceChildren();
    if (!series.length) {
      const empty = document.createElement("div");
      empty.className = "empty";
      empty.textContent = "선택한 범위에 이벤트가 없습니다.";
      container.append(empty);
      return;
    }
    const width = 640;
    const height = 210;
    const plot = { top: 12, right: 12, bottom: 30, left: 42 };
    const plotWidth = width - plot.left - plot.right;
    const plotHeight = height - plot.top - plot.bottom;
    const maxValue = Math.max(1, ...series.flatMap((item) => [item.events, item.blocked]));
    const point = (item, index, key) => {
      const x = series.length === 1 ? plot.left + plotWidth / 2 : plot.left + (index * plotWidth) / (series.length - 1);
      const y = plot.top + plotHeight - (item[key] * plotHeight) / maxValue;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    };
    const svg = createSVGElement("svg", { viewBox: `0 0 ${width} ${height}`, role: "img", "aria-label": `시간별 이벤트와 차단 추이, 최대 ${maxValue}건` });
    const title = createSVGElement("title");
    title.textContent = `시간별 이벤트와 차단 추이, 최대 ${maxValue}건`;
    svg.append(title);
    [0, 0.5, 1].forEach((ratio) => {
      const y = plot.top + plotHeight - ratio * plotHeight;
      svg.append(createSVGElement("line", { x1: plot.left, y1: y, x2: width - plot.right, y2: y, class: "chart-grid-line" }));
      const label = createSVGElement("text", { x: plot.left - 8, y: y + 4, class: "chart-axis-label", "text-anchor": "end" });
      label.textContent = String(Math.round(maxValue * ratio));
      svg.append(label);
    });
    [...new Set([0, Math.floor((series.length - 1) / 2), series.length - 1])].forEach((index) => {
      const x = series.length === 1 ? plot.left + plotWidth / 2 : plot.left + (index * plotWidth) / (series.length - 1);
      const date = new Date(series[index].at);
      const label = createSVGElement("text", { x, y: height - 7, class: "chart-axis-label", "text-anchor": index === 0 ? "start" : index === series.length - 1 ? "end" : "middle" });
      label.textContent = Number.isNaN(date.getTime()) ? "" : date.toLocaleString("ko-KR", { timeZone: kstTimeZone, month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit" });
      svg.append(label);
    });
    const eventPoints = series.map((item, index) => point(item, index, "events"));
    const blockedPoints = series.map((item, index) => point(item, index, "blocked"));
    svg.append(createSVGElement("polyline", { points: eventPoints.join(" "), class: "chart-line" }));
    svg.append(createSVGElement("polyline", { points: blockedPoints.join(" "), class: "chart-blocked" }));
    container.append(svg);
  }

  function initialOverviewSeries() {
    return $$("[data-overview-series] tr").map((row) => ({ at: row.dataset.at, events: Number(row.dataset.events), blocked: Number(row.dataset.blocked) }));
  }

  function renderActions(items) {
    const root = $("[data-overview-actions]");
    const counter = $("[data-action-count]");
    if (!root) return;
    root.replaceChildren();
    if (counter) counter.textContent = `${items.length}건`;
    if (!items.length) {
      const empty = document.createElement("div");
      empty.className = "empty";
      empty.textContent = "즉시 조치가 필요한 항목이 없습니다.";
      root.append(empty);
      return;
    }
    items.forEach((item) => {
      const link = document.createElement("a");
      link.className = "action-item";
      link.href = item.url;
      const dot = document.createElement("span");
      dot.className = `status-dot ${item.level}`;
      const content = document.createElement("span");
      const title = document.createElement("strong");
      title.textContent = `${item.title} · ${item.target_name}`;
      const detail = document.createElement("small");
      detail.textContent = item.detail;
      content.append(title, detail);
      const arrow = document.createElement("span");
      arrow.className = "action-arrow";
      arrow.textContent = "열기";
      link.append(dot, content, arrow);
      root.append(link);
    });
  }

  function renderRank(kind, items) {
    const root = $(`[data-overview-rank="${kind}"]`);
    if (!root) return;
    root.replaceChildren();
    if (!items.length) {
      const empty = document.createElement("li");
      empty.className = "muted";
      empty.textContent = "수집된 항목이 없습니다.";
      root.append(empty);
      return;
    }
    items.forEach((item) => {
      const row = document.createElement("li");
      const number = document.createElement("span");
      number.className = "rank-number";
      const link = document.createElement("a");
      link.className = "rank-label";
      link.href = item.url;
      link.textContent = item.label;
      link.title = item.label;
      const value = document.createElement("span");
      value.className = "rank-value";
      value.textContent = `${item.count}건`;
      row.append(number, link, value);
      root.append(row);
    });
  }

  function updateOverview(data) {
    Object.entries(data.summary).forEach(([key, value]) => {
      const target = $(`[data-overview-field="${key}"]`);
      if (target) target.textContent = key === "block_rate" ? `${Number(value).toFixed(1)}%` : String(value);
    });
    const series = (data.series || []).map((item) => ({ at: item.at, events: Number(item.events), blocked: Number(item.blocked) }));
    drawTrendChart($("[data-overview-chart]"), series);
    renderActions(data.actions || []);
    renderRank("top_categories", data.top_categories || []);
    renderRank("top_uris", data.top_uris || []);
    renderRank("top_servers", data.top_servers || []);
  }

  function initializeOverview() {
    if (!document.body.hasAttribute("data-overview-page")) return;
    drawTrendChart($("[data-overview-chart]"), initialOverviewSeries());
    startVisiblePolling(async () => {
      const response = await fetch(`/api/v1/overview${window.location.search}`, { headers: { Accept: "application/json" }, cache: "no-store" });
      if (!response.ok) throw new Error("overview refresh failed");
      updateOverview(await response.json());
    });
  }

  function severityLabel(value) {
    return ({ "0": "긴급 (EMERGENCY)", "1": "경보 (ALERT)", "2": "치명적 (CRITICAL)", "3": "오류 (ERROR)", "4": "주의 (WARNING)", "5": "알림 (NOTICE)", "6": "정보 (INFO)", "7": "디버그 (DEBUG)" })[value] || value;
  }

  function appendDetailItem(list, term, value, mono = false) {
    const item = document.createElement("div");
    const dt = document.createElement("dt");
    dt.textContent = term;
    const dd = document.createElement("dd");
    if (mono) dd.className = "mono";
    dd.textContent = value || "없음";
    item.append(dt, dd);
    list.append(item);
  }

  function setDrawerURL(id) {
    const url = new URL(window.location.href);
    url.searchParams.delete("event");
    if (id) url.searchParams.set("incident", id);
    else url.searchParams.delete("incident");
    window.history.replaceState({}, "", url);
  }

  async function openEventDrawer(id) {
    const drawer = $("[data-event-drawer]");
    const body = $("[data-event-drawer-body]");
    const scrim = $("[data-drawer-scrim]");
    if (!drawer || !body) return;
    drawer.classList.add("open");
    drawer.setAttribute("aria-hidden", "false");
    if (scrim) scrim.classList.add("open");
    const close = $("[data-event-drawer-close]", drawer);
    if (close) window.requestAnimationFrame(() => close.focus());
    body.textContent = "공격 요청 상세를 불러오는 중입니다.";
    setDrawerURL(id);
    try {
      const response = await fetch(`/api/v1/incidents/${encodeURIComponent(id)}`, { headers: { Accept: "application/json" }, cache: "no-store" });
      if (!response.ok) throw new Error("incident detail failed");
      const data = await response.json();
      const event = data.incident;
      body.replaceChildren();
      const result = document.createElement("div");
      result.className = `alert ${event.blocked ? "error" : "warn"}`;
      const title = document.createElement("strong");
      title.textContent = event.blocked ? "요청 차단" : "탐지 후 허용";
      const message = document.createElement("div");
      message.textContent = `${data.labels.category} · ${event.method || ""} ${event.uri || ""}`;
      result.append(title, message);
      const details = document.createElement("dl");
      details.className = "detail-list";
      appendDetailItem(details, "발생 시각", `${formatKSTDateTime(event.occurred_at) || event.occurred_at} KST`);
      appendDetailItem(details, "서버", event.server_name);
      appendDetailItem(details, "요청", `${event.method} ${event.uri}`, true);
      appendDetailItem(details, "탐지 입력 위치", event.matched_variable || "확인 불가", true);
      appendDetailItem(details, "출발지 IP", event.client_ip || "확인 불가", true);
      appendDetailItem(details, "국가", data.labels.country);
      appendDetailItem(details, "HTTP 상태", String(event.status_code || "확인 안 됨"));
      appendDetailItem(details, "정책 개정본", event.policy_revision, true);
      appendDetailItem(details, "요청 식별자", event.incident_key, true);
      const heading = document.createElement("h3");
      heading.textContent = `관련 Rule ${(data.related_rules || []).length}건`;
      const tableWrap = document.createElement("div");
      tableWrap.className = "table-scroll";
      const table = document.createElement("table");
      const tbody = document.createElement("tbody");
      (data.related_rules || []).forEach((rule) => {
        const row = document.createElement("tr");
        [rule.rule_id || "-", severityLabel(rule.severity), rule.message || "-", rule.blocked ? "차단" : "탐지"].forEach((value) => {
          const cell = document.createElement("td");
          cell.textContent = value;
          row.append(cell);
        });
        tbody.append(row);
      });
      table.append(tbody);
      tableWrap.append(table);
      const links = document.createElement("div");
      links.className = "actions";
      [[data.links.server, "서버 상세"], [data.links.policy, "보호 정책"]].forEach(([href, label]) => {
        if (!href) return;
        const link = document.createElement("a");
        link.className = "button secondary";
        link.href = href;
        link.textContent = label;
        links.append(link);
      });
      const actionHeading = document.createElement("h3");
      actionHeading.textContent = "바로 조치";
      const actionPanel = document.createElement("div");
      actionPanel.className = "drawer-actions";
      const csrf = document.body.dataset.csrf || "";
      const actionForm = (action, fields, label, dangerous = false) => {
        const form = document.createElement("form");
        form.method = "post";
        form.action = action;
        Object.entries({ csrf, expected_revision_id: event.policy_revision, ...fields }).forEach(([name, value]) => {
          const input = document.createElement("input");
          input.type = "hidden";
          input.name = name;
          input.value = value || "";
          form.append(input);
        });
        const button = document.createElement("button");
        button.type = "submit";
        button.className = dangerous ? "danger" : "secondary";
        button.textContent = label;
        form.append(button);
        return form;
      };
      const confirmedActionForm = (action, fields, label, confirmation) => {
        const form = actionForm(action, fields, label, true);
        const button = $("button[type=submit]", form);
        const confirmLabel = document.createElement("label");
        confirmLabel.className = "check-row danger-check";
        const checkbox = document.createElement("input");
        checkbox.type = "checkbox";
        checkbox.name = "confirm";
        checkbox.value = "confirmed";
        checkbox.required = true;
        const text = document.createElement("span");
        text.textContent = confirmation;
        confirmLabel.append(checkbox, text);
        form.insertBefore(confirmLabel, button);
        return form;
      };
      if (event.policy_id && data.can_create_exception) {
        if (event.matched_variable) actionPanel.append(actionForm(`/policies/${encodeURIComponent(event.policy_id)}/exceptions/from-incident`, { incident_id: event.id, scope: "input" }, "이 입력 항목에서만 예외"));
        actionPanel.append(actionForm(`/policies/${encodeURIComponent(event.policy_id)}/exceptions/from-incident`, { incident_id: event.id, scope: "url" }, "이 URL에서만 예외"));
        const global = document.createElement("details");
        const summary = document.createElement("summary");
        summary.textContent = "모든 요청에서 이 Rule 제외";
        global.append(summary, confirmedActionForm(`/policies/${encodeURIComponent(event.policy_id)}/exceptions/from-incident`, { incident_id: event.id, scope: "global" }, "전체 범위 예외 적용", "모든 URL에서 이 Rule이 더 이상 검사되지 않음을 확인합니다."));
        actionPanel.append(global);
      }
      if (event.policy_id && event.client_ip) actionPanel.append(actionForm(`/policies/${encodeURIComponent(event.policy_id)}/ip-rules`, { action: "BLOCK", network: event.client_ip, reason: `보안 이벤트 ${event.id} 출발지 차단` }, "이 IP 차단", true));
      body.append(result, details, actionHeading, actionPanel, heading, tableWrap, links);
    } catch (_) {
      body.textContent = "상세 정보를 불러오지 못했습니다. 목록 데이터는 유지됩니다.";
      setRefreshState(true);
    }
  }

  function closeEventDrawer() {
    const drawer = $("[data-event-drawer]");
    const scrim = $("[data-drawer-scrim]");
    if (!drawer) return;
    drawer.classList.remove("open");
    drawer.setAttribute("aria-hidden", "true");
    if (scrim) scrim.classList.remove("open");
    setDrawerURL("");
    if (lastEventTrigger && typeof lastEventTrigger.focus === "function") lastEventTrigger.focus();
    lastEventTrigger = null;
  }

  function categoryLabel(value) {
    return ({ HTTP_PROTOCOL: "HTTP·프로토콜", INJECTION: "인젝션", XSS: "XSS", FILE_PATH: "파일·경로 공격", SCANNER_BOT: "스캐너·자동화", OTHER: "기타" })[value] || "기타";
  }

  function countryLabel(value) {
    if (!value || value === "ZZ") return "알 수 없음";
    if (value === "--") return "내부 네트워크";
    return value;
  }

  function eventRow(event, systemAdmin) {
    const row = document.createElement("tr");
    row.className = "selectable-row";
    row.tabIndex = 0;
    row.dataset.incidentId = event.id;
    row.setAttribute("aria-label", `${event.server_name} ${event.method} ${event.uri} ${event.blocked ? "차단" : "탐지"}`);
    const timeCell = document.createElement("td");
    const occurredAt = new Date(event.occurred_at);
    timeCell.textContent = Number.isNaN(occurredAt.getTime()) ? event.occurred_at : formatKSTDateTime(occurredAt);
    const timezone = document.createElement("small");
    timezone.textContent = "KST";
    timeCell.append(timezone);
    row.append(timeCell);
    if (systemAdmin) {
      const enterpriseCell = document.createElement("td");
      enterpriseCell.textContent = event.enterprise_name;
      row.append(enterpriseCell);
    }
    const categoryCell = document.createElement("td");
    const category = document.createElement("span");
    category.className = `badge ${event.category === "OTHER" ? "info" : "warn"}`;
    category.textContent = categoryLabel(event.category);
    categoryCell.append(category);
    row.append(categoryCell);
    const requestCell = document.createElement("td");
    const request = document.createElement("span");
    request.className = "mono cell-truncate";
    request.textContent = `${event.method} ${event.uri}`;
    request.title = request.textContent;
    const target = document.createElement("small");
    target.textContent = event.matched_variable ? `입력 위치 · ${event.matched_variable}` : "입력 위치 확인 불가";
    requestCell.append(request, target);
    row.append(requestCell);
    const sourceCell = document.createElement("td");
    const source = document.createElement("span");
    source.className = "mono";
    source.textContent = event.client_ip || "-";
    const country = document.createElement("small");
    country.textContent = countryLabel(event.country_code);
    sourceCell.append(source, country);
    row.append(sourceCell);
    const serverCell = document.createElement("td");
    serverCell.textContent = event.server_name;
    row.append(serverCell);
    const resultCell = document.createElement("td");
    const result = document.createElement("span");
    result.className = `badge ${event.blocked ? "danger" : "warn"}`;
    const dot = document.createElement("span");
    dot.className = `status-dot ${event.blocked ? "danger" : "warn"}`;
    result.append(dot, event.blocked ? "차단" : "탐지");
    resultCell.append(result);
    row.append(resultCell);
    return row;
  }

  function initializeEvents() {
    if (!document.body.hasAttribute("data-events-page")) return;
    const selected = document.body.dataset.selectedIncident;
    if (selected) openEventDrawer(selected);
    startVisiblePolling(async () => {
      const params = new URLSearchParams(window.location.search);
      params.delete("event");
      params.delete("incident");
      const response = await fetch(`/api/v1/incidents?${params}`, { headers: { Accept: "application/json" }, cache: "no-store" });
      if (!response.ok) throw new Error("events refresh failed");
      const data = await response.json();
      const items = data.items || [];
      const tbody = $("[data-event-table-body]");
      if (tbody) {
        tbody.replaceChildren(...items.map((item) => eventRow(item, document.body.dataset.systemAdmin === "true")));
        const table = $("[data-event-table]");
        const empty = $("[data-event-empty]");
        const count = $("[data-event-result-count]");
        if (table) table.hidden = items.length === 0;
        if (empty) empty.hidden = items.length !== 0;
        if (count) count.textContent = String(items.length);
      }
    });
  }

  function serializeGuidedRules(form) {
    const rules = $$("[data-guided-rule-row]", form).map((row) => ({
      field: $("[data-rule-field]", row).value,
      argument: $("[data-rule-argument]", row) ? $("[data-rule-argument]", row).value : "",
      operator: $("[data-rule-operator]", row).value,
      value: $("[data-rule-value]", row).value,
      action: $("[data-rule-action]", row).value
    })).filter((rule) => rule.value.trim());
    const hidden = $("[name=guided_rules_json]", form);
    if (hidden) hidden.value = JSON.stringify(rules);
    return rules;
  }

  function addGuidedRule(root, rule = {}) {
    const template = $("[data-guided-rule-template]");
    if (!template || !root) return;
    const row = template.content.firstElementChild.cloneNode(true);
    if (rule.field) $("[data-rule-field]", row).value = rule.field;
    if (rule.argument && $("[data-rule-argument]", row)) $("[data-rule-argument]", row).value = rule.argument;
    if (rule.operator) $("[data-rule-operator]", row).value = rule.operator;
    if (rule.value) $("[data-rule-value]", row).value = rule.value;
    if (rule.action) $("[data-rule-action]", row).value = rule.action;
    alignGuidedRuleOperator(row);
    root.append(row);
  }

  function alignGuidedRuleOperator(row) {
    const field = $("[data-rule-field]", row);
    const operator = $("[data-rule-operator]", row);
    if (!field || !operator) return;
    const argument = $("[data-rule-argument]", row);
    const argumentLabel = $("[data-rule-argument-label]", row);
    const needsArgument = field.value === "ARGS";
    if (argument) {
      argument.disabled = !needsArgument;
      argument.required = needsArgument;
      if (!needsArgument) argument.value = "";
    }
    if (argumentLabel) argumentLabel.hidden = !needsArgument;
  }

  function initializeSimplePolicyForm() {
    const form = $("[data-simple-policy-form]");
    if (!form) return;
    const guidedRoot = $("[data-guided-rule-list]", form);
    const guidedValue = $("[name=guided_rules_json]", form);
    if (guidedRoot && guidedValue && guidedValue.value) {
      try {
        const rules = JSON.parse(guidedValue.value);
        if (Array.isArray(rules)) rules.forEach((rule) => addGuidedRule(guidedRoot, rule));
      } catch (_) {
        // The server keeps the original hidden value and will reject malformed input.
      }
    }
    form.addEventListener("change", (event) => {
      if (event.target.matches("[data-rule-field]")) alignGuidedRuleOperator(event.target.closest("[data-guided-rule-row]"));
    });
    form.addEventListener("click", (event) => {
      if (event.target.closest("[data-add-guided-rule]")) addGuidedRule(guidedRoot);
      const remove = event.target.closest("[data-remove-guided-rule]");
      if (remove) remove.closest("[data-guided-rule-row]").remove();
    });
    form.addEventListener("submit", () => {
      serializeGuidedRules(form);
    });
  }

  function policyValidationPayload(form) {
    const data = new FormData(form);
    return {
      policy_id: data.get("policy_id") || "",
      expected_revision_id: data.get("expected_revision_id") || "",
      template_key: data.get("template_key") || "",
      name: data.get("name") || "",
      description: data.get("description") || "",
      target: data.get("target") || "",
      mode: data.get("mode") || "",
      paranoia_level: Number(data.get("paranoia_level")),
      executing_paranoia_level: Number(data.get("executing_paranoia_level")),
      inbound_score: Number(data.get("inbound_score")),
      outbound_score: Number(data.get("outbound_score")),
      request_body: data.get("request_body") === "on",
      response_body: data.get("response_body") === "on",
      early_blocking: data.get("early_blocking") === "on",
      sampling_percentage: Number(data.get("sampling_percentage")),
      excluded_paths: data.get("excluded_paths") || "",
      excluded_ips: data.get("excluded_ips") || "",
      custom_rules: data.get("custom_rules") || "",
      guided_rules: serializeGuidedRules(form)
    };
  }

  function updatePolicyReview(form) {
    const data = new FormData(form);
    const target = $("[name=target] option:checked", form);
    const profile = $("[name=protection_profile]:checked", form);
    const profileLabels = { detection: "탐지만", basic: "기본 차단", strict: "강화 차단" };
    const mapping = {
      name: data.get("name") || "입력 필요",
      target: target ? target.textContent.trim() : "선택 필요",
      mode: profile ? profileLabels[profile.value] : "선택 필요",
      exceptions: `Rule ${(data.get("rule_exclusions") || "").split("\n").filter((value) => value.trim()).length} · Target ${(data.get("target_exclusions") || "").split("\n").filter((value) => value.trim()).length} · Tag ${(data.get("tag_exclusions") || "").split("\n").filter((value) => value.trim()).length}`
    };
    Object.entries(mapping).forEach(([key, value]) => {
      const targetElement = $(`[data-review="${key}"]`, form);
      if (targetElement) targetElement.textContent = value;
    });
  }

  function createWizardController(form, onStepChange) {
    let step = 1;
    const showStep = (next) => {
      step = Math.max(1, Math.min(5, next));
      $$('[data-wizard-panel]', form).forEach((panel) => {
        const active = Number(panel.dataset.wizardPanel) === step;
        panel.hidden = !active;
        panel.setAttribute("aria-hidden", active ? "false" : "true");
      });
      $$('[data-wizard-step]', form).forEach((item) => {
        const itemStep = Number(item.dataset.wizardStep);
        const active = itemStep === step;
        const completed = itemStep < step;
        item.classList.toggle("active", active);
        item.classList.toggle("completed", completed);
        if (active) item.setAttribute("aria-current", "step");
        else item.removeAttribute("aria-current");
        const status = $("[data-step-status]", item);
        if (status) {
          status.hidden = !active && !completed;
          status.textContent = active ? "현재 단계" : completed ? "완료" : "";
        }
      });
      if (onStepChange) onStepChange(step);
    };
    const validateStep = () => {
      const panel = $(`[data-wizard-panel="${step}"]`, form);
      if (!panel) return true;
      const invalid = $$('input,select,textarea', panel).find((field) => !field.disabled && !field.checkValidity());
      if (!invalid) return true;
      invalid.reportValidity();
      return false;
    };
    return { currentStep: () => step, showStep, validateStep };
  }

  function initializePolicyWizard() {
    const form = $("[data-policy-wizard]");
    if (!form) return;
    const wizard = createWizardController(form, (step) => {
      if (step === 5) updatePolicyReview(form);
    });
    wizard.showStep(1);
    const guidedRoot = $("[data-guided-rule-list]", form);
    if (guidedRoot && !guidedRoot.children.length) addGuidedRule(guidedRoot);
    const applyProtectionProfile = () => {
      const profile = $("[name=protection_profile]:checked", form);
      const mode = $("[name=mode]", form);
      const paranoia = $("[name=paranoia_level]", form);
	  const executing = $("[name=executing_paranoia_level]", form);
	  if (!profile || !mode || !paranoia || !executing) return;
      mode.value = profile.value === "detection" ? "DetectionOnly" : "On";
      if (profile.value === "detection" || profile.value === "basic") paranoia.value = "1";
      if (profile.value === "strict" && Number(paranoia.value) < 2) paranoia.value = "2";
	  if (Number(executing.value) < Number(paranoia.value)) executing.value = paranoia.value;
    };
    applyProtectionProfile();
    form.addEventListener("change", (event) => {
      if (event.target.matches("[name=protection_profile]")) applyProtectionProfile();
	  if (event.target.matches("[name=paranoia_level]") && Number(form.elements.executing_paranoia_level.value) < Number(event.target.value)) form.elements.executing_paranoia_level.value = event.target.value;
      if (event.target.matches("[data-rule-field]")) alignGuidedRuleOperator(event.target.closest("[data-guided-rule-row]"));
    });
    form.addEventListener("submit", () => serializeGuidedRules(form));
    form.addEventListener("invalid", (event) => {
      const panel = event.target.closest("[data-wizard-panel]");
      if (panel) wizard.showStep(Number(panel.dataset.wizardPanel));
    }, true);
    form.addEventListener("click", async (event) => {
      if (event.target.closest("[data-wizard-prev]")) wizard.showStep(wizard.currentStep() - 1);
      if (event.target.closest("[data-wizard-next]") && wizard.validateStep()) wizard.showStep(wizard.currentStep() + 1);
      if (event.target.closest("[data-add-guided-rule]")) addGuidedRule(guidedRoot);
      const remove = event.target.closest("[data-remove-guided-rule]");
      if (remove) remove.closest("[data-guided-rule-row]").remove();
      const validate = event.target.closest("[data-policy-validate]");
      if (validate) {
        const result = $("[data-policy-validation-result]", form);
        if (result) result.textContent = "정책 설정과 적용 대상을 확인하는 중입니다.";
        showGlobalBusy("정책 설정과 적용 대상을 검증하는 중입니다.");
        try {
          const response = await fetch("/api/v1/policies/validate", {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-CSRF-Token": form.elements.csrf.value, Accept: "application/json" },
            body: JSON.stringify(policyValidationPayload(form))
          });
          const data = await response.json();
          $$(".field-error", form).forEach((item) => item.remove());
          if (!response.ok || !data.valid) {
            Object.entries(data.field_errors || {}).forEach(([name, message]) => {
              const input = form.elements[name];
              const anchor = name === "guided_rules" ? guidedRoot : input && (input.closest("label") || input);
              if (!anchor) return;
              const error = document.createElement("div");
              error.className = "field-error";
              error.textContent = message;
              anchor.append(error);
            });
            if (result) result.textContent = "표시된 항목을 수정한 뒤 다시 검증하세요.";
          } else if (result) {
            result.textContent = `검증 완료 · 영향 서버 ${data.impact.server_count}대 · 제출 시 새 불변 개정본을 즉시 단계 배포합니다.`;
          }
        } catch (_) {
          if (result) result.textContent = "검증 API에 연결하지 못했습니다. 기존 입력은 유지됩니다.";
        } finally {
          hideGlobalBusy();
        }
      }
    });
  }

  function migrationTextElement(tag, text, className = "") {
    const element = document.createElement(tag);
    if (className) element.className = className;
    element.textContent = text;
    return element;
  }

  function migrationMetricGrid(items) {
    const grid = document.createElement("div");
    grid.className = "detail-grid";
    items.forEach(({ label, value, detail }) => {
      const item = document.createElement("div");
      item.append(migrationTextElement("span", label), migrationTextElement("strong", value));
      if (detail) item.append(migrationTextElement("small", detail));
      grid.append(item);
    });
    return grid;
  }

  function migrationAlert(kind, title, messages) {
    const alert = document.createElement("div");
    alert.className = `alert ${kind}`;
    alert.append(migrationTextElement("strong", title));
    if (messages.length === 1) {
      alert.append(migrationTextElement("div", messages[0]));
    } else {
      const list = document.createElement("ul");
      messages.forEach((message) => list.append(migrationTextElement("li", message)));
      alert.append(list);
    }
    return alert;
  }

  function renderSystemPolicyDiff(form, diff) {
    const root = $("[data-source-diff]", form);
    if (!root) return;
    root.replaceChildren();
    const rules = diff.rules || {};
    const added = rules.added || [];
    const removed = rules.removed || [];
    const changed = rules.changed || [];
    const setup = diff.setup || [];
    const sourceSetup = diff.source_setup || [];
    const files = diff.files || [];
    const directives = diff.directives || [];
    root.append(migrationMetricGrid([
      { label: "추가 Rule", value: `${added.length}개`, detail: "새 보호 범위" },
      { label: "삭제 Rule", value: `${removed.length}개`, detail: removed.length ? "기존 예외 참조 확인" : "영향 없음" },
      { label: "내용 변경 Rule", value: `${changed.length}개`, detail: changed.length ? "공통 예외 영향 확인" : "영향 없음" },
      { label: "관리 Setup 변경", value: `${setup.length}개`, detail: setup.length ? "지원 항목 구조 변경" : "구조 변경 없음" },
      { label: "원본 Setup 변경", value: `${sourceSetup.length}개`, detail: sourceSetup.length ? "읽기 전용 항목 포함" : "변경 없음" },
      { label: "파일 변경", value: `${files.length}개`, detail: files.length ? ".data와 원본 구성 포함" : "변경 없음" },
      { label: "기타 지시문 변경", value: `${directives.length}개`, detail: directives.length ? "marker와 target 제외 포함" : "변경 없음" }
    ]));
    if (removed.length || changed.length) {
      const messages = [];
      if (removed.length) messages.push(`삭제된 Rule ${removed.slice(0, 8).map((item) => item.id).join(", ")}${removed.length > 8 ? " 외" : ""}`);
      if (changed.length) messages.push(`내용이 변경된 Rule ${changed.slice(0, 8).map((item) => item.id).join(", ")}${changed.length > 8 ? " 외" : ""}`);
      root.append(migrationAlert("warn", "공통 예외와 추가 Rule을 다시 확인하세요", messages));
    }
  }

  async function loadSystemPolicyDiff(form) {
    const root = $("[data-source-diff]", form);
    const source = form.elements.source_id && form.elements.source_id.value;
    if (!root || !source) return;
    root.replaceChildren(migrationTextElement("div", "현재 정책과 선택한 CRS를 비교하는 중입니다.", "validation-placeholder"));
    const base = form.elements.expected_system_policy_id && form.elements.expected_system_policy_id.value;
    const query = base ? `?base_system_policy_id=${encodeURIComponent(base)}` : "";
    try {
      const response = await fetch(`/api/v1/open-source-policies/${encodeURIComponent(source)}/diff${query}`, { headers: { Accept: "application/json" } });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "CRS 변경 내용을 불러오지 못했습니다.");
      renderSystemPolicyDiff(form, data);
    } catch (error) {
      root.replaceChildren(migrationAlert("danger", "CRS 변경 비교 실패", [error.message || "잠시 후 다시 시도하세요."]));
    }
  }

  function setupTokenValues(root) {
    const editor = $("[data-setup-editor]", root);
    if (!editor) return [];
    const raw = editor.value.trim();
    if (root.dataset.tokenFormat === "pipe") {
      const matches = [...raw.matchAll(/\|([^|]+)\|/g)].map((match) => match[1].trim()).filter(Boolean);
      if (matches.length) return matches;
    }
    return raw.split(/[\s,]+/).map((value) => value.trim()).filter(Boolean);
  }

  function populateSetupTokenEditor(root) {
    const values = setupTokenValues(root);
    const known = new Set($$("[data-setup-token-option]", root).map((option) => option.value));
    $$("[data-setup-token-option]", root).forEach((option) => {
      option.checked = values.includes(option.value);
    });
    const custom = $("[data-setup-token-custom]", root);
    if (custom) custom.value = values.filter((value) => !known.has(value)).join(" ");
  }

  function writeSetupTokenEditor(root) {
    const editor = $("[data-setup-editor]", root);
    if (!editor) return;
    const values = $$("[data-setup-token-option]:checked", root).map((option) => option.value);
    const custom = $("[data-setup-token-custom]", root);
    if (custom) {
      custom.value.split(/[\s,]+/).map((value) => value.trim()).filter(Boolean).forEach((value) => {
        if (!values.includes(value)) values.push(value);
      });
    }
    editor.value = root.dataset.tokenFormat === "pipe" ? values.map((value) => `|${value}|`).join(" ") : values.join(" ");
    const effective = $("[data-setup-effective-value]", root.closest("[data-setup-override-card]"));
    if (effective) effective.textContent = editor.value || "미설정";
  }

  function setSetupEditorDisabled(editor, disabled) {
    editor.disabled = disabled;
    const tokenRoot = editor.closest("[data-setup-token-editor]");
    if (tokenRoot) $$('[data-setup-token-option],[data-setup-token-custom]', tokenRoot).forEach((input) => { input.disabled = disabled; });
  }

  function syncSetupOverride(toggle, focusEditor = false) {
    const card = toggle.closest("[data-setup-override-card]");
    if (!card) return;
    const inherited = $("[data-setup-inherited]", card);
    const editor = $("[data-setup-editor]", card);
    const editorPanel = $("[data-setup-editor-panel]", card);
    if (!inherited || !editor) return;
    card.classList.toggle("is-overridden", toggle.checked);
    toggle.setAttribute("aria-expanded", String(toggle.checked));
    if (editorPanel) editorPanel.hidden = !toggle.checked;
    if (toggle.checked) {
      inherited.removeAttribute("name");
      editor.name = editor.dataset.setupName;
      setSetupEditorDisabled(editor, false);
    } else {
      editor.value = inherited.value;
      editor.removeAttribute("name");
      setSetupEditorDisabled(editor, true);
      inherited.name = editor.dataset.setupName;
      const tokenRoot = editor.closest("[data-setup-token-editor]");
      if (tokenRoot) populateSetupTokenEditor(tokenRoot);
    }
    const status = $("[data-setup-inheritance-status]", card);
    if (status) {
      if (!card.dataset.inheritedLabel && !toggle.checked) card.dataset.inheritedLabel = status.textContent.trim();
      status.textContent = toggle.checked ? "직접 설정" : card.dataset.inheritedLabel || "상속값 사용";
      status.classList.toggle("info", toggle.checked);
    }
    const effective = $("[data-setup-effective-value]", card);
    if (effective) effective.textContent = editor.value || inherited.value || "미설정";
    if (focusEditor && toggle.checked) {
      const target = editor.type === "hidden" ? $('[data-setup-token-option],[data-setup-token-custom]', card) : editor;
      if (target) target.focus();
    }
  }

  function migrationInput(form, field) {
    const name = field.startsWith("crs_setup.") ? `setup.${field.slice("crs_setup.".length)}` : field;
    const setupEditor = $$('[data-setup-name]', form).find((item) => item.dataset.setupName === name);
    if (setupEditor) return setupEditor;
    const input = form.elements.namedItem(name);
    return input instanceof HTMLElement ? input : null;
  }

  function migrationFieldStep(form, field) {
    const input = migrationInput(form, field);
    if (input && input.dataset.fieldStep) return Number(input.dataset.fieldStep);
    if (field === "confirm_changed_rules" || field === "confirm_channel_change") return 2;
    if (field.startsWith("crs_setup.") || field === "mode") return 3;
    if (["excluded_paths", "excluded_ips", "rule_exclusions", "target_exclusions", "conditional_exclusions", "service_rules", "policy"].includes(field)) return 4;
    return 5;
  }

  function migrationFieldLabel(field) {
    const labels = {
      expected_system_policy_id: "현재 기준 정책", source_id: "CRS 소스", name: "정책 이름", mode: "보호 모드",
      confirm_changed_rules: "변경 Rule 확인", confirm_channel_change: "CRS 채널 전환 확인", excluded_paths: "URL 예외", excluded_ips: "IP/CIDR 예외",
      rule_exclusions: "Rule ID 제외", target_exclusions: "Target 제외", conditional_exclusions: "조건부 예외",
      service_rules: "시스템 공통 Service Rule", compatibility: "서버 호환성", enterprise_impact: "기업 적용 영향",
      artifact: "정책 배포 파일", candidate: "시스템 오버라이드", policy: "공통 보호 설정"
    };
    if (field.startsWith("crs_setup.")) return "CRS 고급 설정";
    return labels[field] || "검증 항목";
  }

  function clearMigrationFieldErrors(form) {
    $$(".field-error", form).forEach((item) => item.remove());
    const contextErrors = $("[data-system-policy-context-errors]", form);
    const contextErrorList = $("[data-system-policy-context-error-list]", form);
    if (contextErrors) contextErrors.hidden = true;
    if (contextErrorList) contextErrorList.replaceChildren();
    $$('[data-wizard-step]', form).forEach((item) => {
      item.classList.remove("has-error");
      const count = $("[data-step-error-count]", item);
      if (count) {
        count.hidden = true;
        count.textContent = "";
      }
    });
  }

  function showMigrationFieldErrors(form, errors, wizard, focusFirst) {
    clearMigrationFieldErrors(form);
    const counts = new Map();
    let first = null;
    Object.entries(errors || {}).forEach(([field, message]) => {
      const step = migrationFieldStep(form, field);
      counts.set(step, (counts.get(step) || 0) + 1);
      const input = migrationInput(form, field);
      if (!input) return;
      const card = input.closest("[data-setup-override-card]");
      if (input.type === "hidden" && !card) {
        const contextErrors = $("[data-system-policy-context-errors]", form);
        const contextErrorList = $("[data-system-policy-context-error-list]", form);
        if (step === 1 && contextErrors && contextErrorList) {
          contextErrorList.append(migrationTextElement("li", `${migrationFieldLabel(field)} — ${message}`));
          contextErrors.hidden = false;
          if (!first) first = { input: contextErrors, step };
        }
        return;
      }
      const details = input.closest("details");
      if (details) details.open = true;
      let focusTarget = input;
      if (card && input.disabled) {
        const toggle = $("[data-setup-override]", card);
        if (toggle) {
          toggle.checked = true;
          syncSetupOverride(toggle);
        }
      }
      if (card && input.type === "hidden") focusTarget = $('[data-setup-token-option],[data-setup-token-custom]', card) || input;
      const anchor = card || input.closest("label") || input;
      const error = migrationTextElement("div", message, "field-error");
      error.setAttribute("role", "alert");
      anchor.append(error);
      if (!first) first = { input: focusTarget, step };
    });
    counts.forEach((count, step) => {
      const item = $(`[data-wizard-step="${step}"]`, form);
      if (!item) return;
      item.classList.add("has-error");
      const badge = $("[data-step-error-count]", item);
      if (badge) {
        badge.hidden = false;
        badge.textContent = `${count}개 수정 필요`;
      }
    });
    if (focusFirst && first) {
      wizard.showStep(first.step);
      window.requestAnimationFrame(() => first.input.focus());
    } else if (focusFirst && counts.size) {
      wizard.showStep(Math.min(...counts.keys()));
    }
  }

  function renderSystemPolicyValidation(form, data) {
    const root = $("[data-policy-validation-result]", form);
    if (!root) return;
    root.replaceChildren();
    const errors = data.field_errors || {};
    const warnings = data.warnings || [];
    if (Object.keys(errors).length) root.append(migrationAlert("danger", "게시 차단 항목", Object.entries(errors).map(([field, message]) => `${migrationFieldLabel(field)} — ${message}`)));
    if (warnings.length) root.append(migrationAlert("warn", "확인이 필요한 경고", warnings));

    const impactSection = document.createElement("section");
    impactSection.className = "validation-section";
    impactSection.append(migrationTextElement("h3", "게시 후 기업 적용"));
    const impact = data.strategy_impact || {};
    const compatibility = data.compatibility || [];
    impactSection.append(migrationMetricGrid([
      { label: "자동 업데이트", value: `${impact.automatic || 0}개`, detail: "카나리·확대 배포" },
      { label: "수동 승인", value: `${impact.manual || 0}개`, detail: "승인 전까지 현재 CRS 기준 유지" },
      { label: "CRS 고정", value: `${impact.pinned || 0}개`, detail: "변경 없음" },
      { label: "활성 서버", value: `${compatibility.length}대`, detail: "Agent·모듈·롤백 조합 확인" }
    ]));
    root.append(impactSection);

    if (compatibility.length) {
      const section = document.createElement("section");
      section.className = "validation-section";
      section.append(migrationTextElement("h3", "서버 호환성"));
      const wrap = document.createElement("div");
      wrap.className = "table-scroll";
      const table = document.createElement("table");
      table.className = "table-wide";
      const head = document.createElement("thead");
      const headRow = document.createElement("tr");
      ["활성 서버", "판정", "Agent", "웹서버 모듈", "확인 내용"].forEach((title) => headRow.append(migrationTextElement("th", title)));
      head.append(headRow);
      const body = document.createElement("tbody");
      compatibility.slice().sort((left, right) => Number(left.compatible) - Number(right.compatible)).forEach((item) => {
        const row = document.createElement("tr");
        const serverCell = document.createElement("td");
        const link = document.createElement("a");
        link.href = `/servers/${encodeURIComponent(item.server_id)}`;
        link.append(migrationTextElement("strong", item.server_name || item.server_id));
        serverCell.append(link);
        const statusCell = document.createElement("td");
        statusCell.append(migrationTextElement("span", item.compatible ? "호환·복구 준비" : "게시 차단", `badge ${item.compatible ? "ok" : "danger"}`));
        row.append(serverCell, statusCell, migrationTextElement("td", item.agent_package_id || "-", "mono"), migrationTextElement("td", item.module_package_id || "-", "mono"), migrationTextElement("td", item.reason || "배포 및 롤백 패키지를 확인했습니다."));
        body.append(row);
      });
      table.append(head, body);
      wrap.append(table);
      section.append(wrap);
      root.append(section);
    } else {
      root.append(migrationTextElement("div", "등록된 활성 서버가 없어 패키지 호환성 대상이 없습니다.", "empty"));
    }

    if (data.valid) root.append(migrationAlert("ok", "게시 가능", ["선택한 CRS 버전에 현재 시스템 오버라이드를 게시할 수 있습니다."]));
    const details = document.createElement("details");
    details.className = "validation-details";
    details.append(migrationTextElement("summary", "검증 상세 정보"));
    const list = document.createElement("dl");
    appendDetailItem(list, "검증 digest", data.validation_digest || "생성되지 않음", true);
    appendDetailItem(list, "artifact SHA-256", data.artifact_sha256 || "생성되지 않음", true);
    details.append(list);
    root.append(details);
  }

  function initializeSystemPolicyWizard() {
    const form = $("[data-system-policy-wizard]");
    if (!form) return;
    const status = $("[data-policy-validation-status]", form);
    const digest = form.elements.validation_digest;
    const confirmRoot = $("[data-publish-confirm]", form);
    const confirm = form.elements.publish_confirm;
    const publish = $("[data-system-policy-publish]", form);
    let validationInFlight = false;
    let dirty = false;
    let leaving = false;
    let wizard;

    const updateConfirmationGates = () => {
      $$('[data-confirm-fields]', form).forEach((button) => {
        const fieldNames = (button.dataset.confirmFields || "").split(/\s+/).filter(Boolean);
        button.disabled = fieldNames.some((name) => {
          const field = form.elements[name];
          return !field || !field.checked;
        });
      });
    };

    $$("[data-setup-token-editor]", form).forEach((root) => {
      populateSetupTokenEditor(root);
      root.addEventListener("input", () => writeSetupTokenEditor(root));
      root.addEventListener("change", () => writeSetupTokenEditor(root));
    });
    $$("[data-setup-override]", form).forEach((toggle) => syncSetupOverride(toggle));

    const updatePublishAvailability = () => {
      if (publish) publish.disabled = form.dataset.validationState !== "valid" || !confirm || !confirm.checked;
    };
    const setValidationState = (state, data) => {
      form.dataset.validationState = state;
      if (status) {
        status.classList.toggle("is-loading", state === "loading");
        status.classList.toggle("is-valid", state === "valid");
        status.classList.toggle("is-invalid", state === "invalid");
        const labels = {
          idle: "설정을 확인한 뒤 검증을 실행합니다.", dirty: "설정이 변경되어 재검증이 필요합니다.", loading: "정책 설정과 전체 활성 서버를 검증하는 중입니다.",
          valid: "검증이 완료되었습니다. 게시 내용을 확인하세요.", invalid: "수정이 필요한 항목이 있습니다.", error: "검증 서비스에 연결하지 못했습니다. 입력값은 유지됩니다."
        };
        status.textContent = labels[state] || labels.idle;
      }
      if (digest) digest.value = state === "valid" && data ? data.validation_digest || "" : "";
      if (confirmRoot) confirmRoot.hidden = state !== "valid";
      if (confirm) {
        confirm.disabled = state !== "valid";
        if (state !== "valid") confirm.checked = false;
      }
      updatePublishAvailability();
    };
    const validateMigration = async (focusErrors = true) => {
      if (validationInFlight) return;
      const invalid = $$('input,select,textarea', form).find((field) => !field.disabled && field.name !== "publish_confirm" && !field.checkValidity());
      if (invalid) {
        const panel = invalid.closest("[data-wizard-panel]");
        if (panel) wizard.showStep(Number(panel.dataset.wizardPanel));
        invalid.reportValidity();
        return;
      }
      validationInFlight = true;
      clearMigrationFieldErrors(form);
      setValidationState("loading");
      const result = $("[data-policy-validation-result]", form);
      if (result) result.replaceChildren(migrationTextElement("div", "서버 호환성과 기업별 적용 영향을 확인하는 중입니다.", "validation-placeholder"));
      try {
        const response = await fetch("/api/v1/system-policy-migrations/validate", {
          method: "POST",
          headers: { "X-CSRF-Token": form.elements.csrf.value, Accept: "application/json" },
          // The Go handler uses Request.ParseForm, so send the standard
          // application/x-www-form-urlencoded representation.
          body: new URLSearchParams(new FormData(form))
        });
        const data = await response.json();
        if (!response.ok && !data.field_errors) throw new Error(data.detail || "검증 요청을 처리하지 못했습니다.");
        renderSystemPolicyValidation(form, data);
        if (data.valid) {
          setValidationState("valid", data);
          showMigrationFieldErrors(form, {}, wizard, false);
        } else {
          setValidationState("invalid", data);
          showMigrationFieldErrors(form, data.field_errors || {}, wizard, focusErrors);
        }
      } catch (error) {
        setValidationState("error");
        if (result) result.replaceChildren(migrationAlert("danger", "검증 연결 실패", [error.message || "잠시 후 다시 시도하세요."]));
      } finally {
        validationInFlight = false;
      }
    };

    wizard = createWizardController(form, (step) => {
      if (step === 5 && !validationInFlight && form.dataset.validationState !== "valid") validateMigration(true);
    });
    wizard.showStep(1);
    loadSystemPolicyDiff(form);

    const initialErrors = {};
    $$('[data-validation-error-field]', form).forEach((item) => {
      const parts = item.textContent.split("—");
      initialErrors[item.dataset.validationErrorField] = parts.length > 1 ? parts.slice(1).join("—").trim() : item.textContent.trim();
    });
    if (Object.keys(initialErrors).length) showMigrationFieldErrors(form, initialErrors, wizard, true);
    updateConfirmationGates();
    updatePublishAvailability();

    form.addEventListener("invalid", (event) => {
      const panel = event.target.closest("[data-wizard-panel]");
      if (panel) wizard.showStep(Number(panel.dataset.wizardPanel));
    }, true);
    form.addEventListener("input", (event) => {
      const setupTokenInput = event.target.matches("[data-setup-token-option],[data-setup-token-custom]");
      if (event.target.matches("[data-setup-editor]")) {
        const effective = $("[data-setup-effective-value]", event.target.closest("[data-setup-override-card]"));
        if (effective) effective.textContent = event.target.value || "미설정";
      }
      if ((!event.target.name && !setupTokenInput) || ["csrf", "expected_system_policy_id", "validation_digest", "publish_confirm"].includes(event.target.name)) return;
      dirty = true;
      if (form.dataset.validationState !== "idle" && form.dataset.validationState !== "dirty") {
        clearMigrationFieldErrors(form);
        setValidationState("dirty");
      }
    });
    form.addEventListener("change", (event) => {
      if (event.target.matches("[data-setup-override]")) syncSetupOverride(event.target, event.target.checked);
      if (event.target.matches("[data-wizard-confirm]")) updateConfirmationGates();
      if (event.target.name === "publish_confirm") updatePublishAvailability();
    });
    form.addEventListener("click", (event) => {
      const previous = event.target.closest("[data-wizard-prev]");
      if (previous) wizard.showStep(wizard.currentStep() - 1);
      const next = event.target.closest("[data-wizard-next]");
      if (next && wizard.validateStep()) wizard.showStep(wizard.currentStep() + 1);
      const stepButton = event.target.closest("[data-wizard-step] .wizard-step-button");
      if (stepButton) {
        const item = stepButton.closest("[data-wizard-step]");
        const target = Number(item.dataset.wizardStep);
        if (target <= wizard.currentStep() || item.classList.contains("has-error")) wizard.showStep(target);
      }
    });
    form.addEventListener("submit", (event) => {
      if (event.submitter && event.submitter.matches("[data-system-policy-validate]")) {
        event.preventDefault();
        validateMigration(true);
        return;
      }
      if (!event.submitter || !event.submitter.matches("[data-system-policy-publish]")) return;
      if (form.dataset.validationState !== "valid") {
        event.preventDefault();
        validateMigration(true);
        return;
      }
      dirty = false;
      leaving = true;
    });
    window.addEventListener("beforeunload", (event) => {
      if (!dirty || leaving) return;
      event.preventDefault();
      event.returnValue = "";
    });
  }

  document.addEventListener("click", async (event) => {
    const accountMenu = $("[data-account-menu]");
    if (accountMenu && accountMenu.open && !event.target.closest("[data-account-menu]")) accountMenu.removeAttribute("open");
    const dialogOpen = event.target.closest("[data-dialog-open]");
    if (dialogOpen) {
      const dialog = document.getElementById(dialogOpen.dataset.dialogOpen);
      if (dialog) {
        event.preventDefault();
        openTaskDialog(dialog, dialogOpen);
      }
    }
    const dialogClose = event.target.closest("[data-dialog-close]");
    if (dialogClose) {
      const dialog = dialogClose.closest("dialog[data-task-dialog]");
      if (dialog) {
        event.preventDefault();
        closeTaskDialog(dialog);
      }
    }
    if (event.target.matches("dialog[data-task-dialog]")) closeTaskDialog(event.target);
    if (event.target.closest("[data-sidebar-open]")) setSidebar(true);
    if (event.target.closest("[data-sidebar-close]")) setSidebar(false);
    if (event.target.closest("[data-sidebar-toggle]")) setDesktopSidebar(!desktopSidebarExpanded());
    if (event.target.closest("[data-refresh-page]")) {
      showGlobalBusy("페이지를 새로 불러오는 중입니다.");
      window.location.reload();
    }
    if (event.target.closest("[data-event-drawer-close]")) closeEventDrawer();
    const row = event.target.closest("[data-incident-id]");
    if (row) {
      lastEventTrigger = row;
      openEventDrawer(row.dataset.incidentId);
    }
    const navigationRow = event.target.closest("[data-row-href]");
    const rowControl = event.target.closest("a, button, input, select, textarea, summary, [role='button']");
    if (navigationRow && !rowControl && event.button === 0 && !event.metaKey && !event.ctrlKey && !event.shiftKey && !event.altKey) {
      showGlobalBusy("상세 정보를 불러오는 중입니다.");
      window.location.assign(navigationRow.dataset.rowHref);
      return;
    }
    const detailsButton = event.target.closest("[data-open-details]");
    if (detailsButton) {
      const details = document.getElementById(detailsButton.dataset.openDetails);
      if (details) {
        details.open = true;
        details.scrollIntoView({ behavior: "smooth", block: "start" });
        const summary = $("summary", details);
        if (summary) summary.focus();
      }
      return;
    }
    const button = event.target.closest("[data-copy-target], [data-copy-text]");
    if (!button) return;
    const target = document.getElementById(button.dataset.copyTarget);
    const status = document.getElementById(button.dataset.copyStatus || "copy-status");
    const value = button.dataset.copyText || (target ? target.textContent.trim() : "");
    if (!value) return;
    try {
      await copyText(value);
      if (status) status.textContent = button.dataset.copySuccess || "클립보드에 복사했습니다.";
    } catch (_) {
      if (status) status.textContent = "클립보드 복사에 실패했습니다.";
      if (target) {
        const details = target.closest("details");
        if (details) details.open = true;
        target.focus();
      }
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      const accountMenu = $("[data-account-menu]");
      if (accountMenu && accountMenu.open) {
        accountMenu.removeAttribute("open");
        const summary = $("summary", accountMenu);
        if (summary) summary.focus();
      }
      setSidebar(false);
      closeEventDrawer();
    }
    if ((event.key === "Enter" || event.key === " ") && event.target.matches("[data-incident-id]")) {
      event.preventDefault();
      lastEventTrigger = event.target;
      openEventDrawer(event.target.dataset.incidentId);
    }
  });

  initializeOverview();
  initializeEvents();
  initializePolicyWizard();
  initializeSimplePolicyForm();
  initializeSystemPolicyWizard();
  initializeDesktopSidebar();
  initializeTaskDialogs();
  initializeLiveReload();
  initializeGlobalBusy();
  setRefreshState(false);
})();
