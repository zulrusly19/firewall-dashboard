/**
 * Minimalist Firewall Log Dashboard - Full Stack Controller
 * Features:
 * - 500 Records with 25-Per-Page Pagination
 * - Direct SQLite DB click-to-inspect
 * - Dedicated Analytics & Graphs Page with Chart.js
 * - Auth Gate (Login & Register)
 * - CSV Export
 */

(function () {
  'use strict';

  // --- State ---
  let allLogs = [];
  let filteredLogs = [];
  let currentPage = 1;
  const pageSize = 25;
  let activeFilter = 'ALL'; // 'ALL', 'Success', 'Failed'
  let searchKeyword = '';
  let activeChartFilter = null;
  let activeInvestigationFilter = 'ALL';
  let currentLogId = null;
  let usingLocalData = false;

  // Chart instances
  let chartStatusInstance = null;
  let chartServicesInstance = null;
  let chartProtocolsInstance = null;
  let chartAttacksInstance = null;

  // --- Screens & Views ---
  const authScreen = document.getElementById('authScreen');
  const dashboardScreen = document.getElementById('dashboardScreen');
  const viewLogs = document.getElementById('viewLogs');
  const viewAnalytics = document.getElementById('viewAnalytics');
  const viewInvestigations = document.getElementById('viewInvestigations');
  const navTabLogs = document.getElementById('navTabLogs');
  const navTabAnalytics = document.getElementById('navTabAnalytics');
  const navTabInvestigations = document.getElementById('navTabInvestigations');
  const btnOpenHelp = document.getElementById('btnOpenHelp');
  const helpModal = document.getElementById('helpModal');
  const btnCloseHelp = document.getElementById('btnCloseHelp');
  const helpTabInstructions = document.getElementById('helpTabInstructions');
  const helpTabApproach = document.getElementById('helpTabApproach');
  const helpInstructions = document.getElementById('helpInstructions');
  const helpApproach = document.getElementById('helpApproach');

  // --- Auth Elements ---
  const tabLogin = document.getElementById('tabLogin');
  const tabRegister = document.getElementById('tabRegister');
  const formLogin = document.getElementById('formLogin');
  const formRegister = document.getElementById('formRegister');
  const authAlert = document.getElementById('authAlert');
  const navUserName = document.getElementById('navUserName');
  const btnLogout = document.getElementById('btnLogout');

  // --- Dashboard Elements ---
  const tableBody = document.getElementById('tableBody');
  const searchInput = document.getElementById('searchInput');
  const btnExportCSV = document.getElementById('btnExportCSV');
  const kpiTotal = document.getElementById('kpiTotal');
  const kpiSuccess = document.getElementById('kpiSuccess');
  const kpiFailed = document.getElementById('kpiFailed');
  const kpiSuccessRate = document.getElementById('kpiSuccessRate');
  const kpiFailedRate = document.getElementById('kpiFailedRate');

  // Filter Buttons
  const filterAll = document.getElementById('filterAll');
  const filterSuccess = document.getElementById('filterSuccess');
  const filterFailed = document.getElementById('filterFailed');

  // Pagination Elements
  const paginationInfo = document.getElementById('paginationInfo');
  const pageIndicator = document.getElementById('pageIndicator');
  const btnFirstPage = document.getElementById('btnFirstPage');
  const btnPrevPage = document.getElementById('btnPrevPage');
  const btnNextPage = document.getElementById('btnNextPage');
  const btnLastPage = document.getElementById('btnLastPage');
  const chartFilterNotice = document.getElementById('chartFilterNotice');
  const chartFilterLabel = document.getElementById('chartFilterLabel');
  const btnClearChartFilter = document.getElementById('btnClearChartFilter');

  // Detail Modal
  const detailModal = document.getElementById('detailModal');
  const btnCloseDetail = document.getElementById('btnCloseDetail');
  const btnDismissDetail = document.getElementById('btnDismissDetail');
  const caseStatusInput = document.getElementById('caseStatusInput');
  const caseNotesInput = document.getElementById('caseNotesInput');
  const caseSaveMessage = document.getElementById('caseSaveMessage');
  const btnSaveInvestigation = document.getElementById('btnSaveInvestigation');
  const investigationTableBody = document.getElementById('investigationTableBody');
  const investigationTotal = document.getElementById('investigationTotal');
  const investigationNew = document.getElementById('investigationNew');
  const investigationInProgress = document.getElementById('investigationInProgress');
  const investigationResolved = document.getElementById('investigationResolved');
  const investigationFilterButtons = document.querySelectorAll('[data-investigation-filter]');

  // Toast
  const toast = document.getElementById('toast');

  // --- Initialization ---
  document.addEventListener('DOMContentLoaded', () => {
    checkAuthSession();
    setupEvents();
  });

  // --- Auth Session Check ---
  function checkAuthSession() {
    const user = getLoggedInUser();
    if (user) {
      showDashboard(user);
    } else {
      showAuthScreen();
    }
  }

  function matchesChartFilter(log, filter) {
    if (filter.field === 'servicePort') {
      return log.service === filter.service &&
        (filter.port == null || String(log.dst_port) === String(filter.port));
    }
    return String(log[filter.field] || '').toLowerCase() === String(filter.value).toLowerCase();
  }

  function setChartFilter(filter, label) {
    activeChartFilter = filter;
    chartFilterLabel.textContent = `Chart filter: ${label}`;
    chartFilterNotice.hidden = false;
    document.querySelectorAll('.filter-btn').forEach(button => button.classList.toggle('active', button === filterAll));
    activeFilter = 'ALL';
    navTabLogs.classList.add('active');
    navTabAnalytics.classList.remove('active');
    navTabInvestigations.classList.remove('active');
    viewLogs.style.display = 'flex';
    viewAnalytics.style.display = 'none';
    viewInvestigations.style.display = 'none';
    applyFilters();
  }

  function showView(view) {
    const views = [
      { element: viewLogs, tab: navTabLogs },
      { element: viewAnalytics, tab: navTabAnalytics },
      { element: viewInvestigations, tab: navTabInvestigations }
    ];
    views.forEach(item => {
      const isActive = item.element === view;
      item.element.style.display = isActive ? 'flex' : 'none';
      item.tab.classList.toggle('active', isActive);
    });
    if (view === viewAnalytics) loadAnalyticsGraphs();
    if (view === viewInvestigations) renderInvestigations();
  }

  function setHelpTab(activeTab) {
    const isInstructions = activeTab === helpTabInstructions;
    helpTabInstructions.classList.toggle('active', isInstructions);
    helpTabApproach.classList.toggle('active', !isInstructions);
    helpTabInstructions.setAttribute('aria-selected', String(isInstructions));
    helpTabApproach.setAttribute('aria-selected', String(!isInstructions));
    helpInstructions.hidden = !isInstructions;
    helpApproach.hidden = isInstructions;
  }

  function closeHelpModal() {
    helpModal.hidden = true;
    btnOpenHelp.focus();
  }

  function clearChartFilter() {
    activeChartFilter = null;
    chartFilterNotice.hidden = true;
    applyFilters();
  }

  function getLoggedInUser() {
    try {
      return JSON.parse(sessionStorage.getItem('current_user'));
    } catch {
      return null;
    }
  }

  function showAuthScreen() {
    authScreen.style.display = 'flex';
    dashboardScreen.style.display = 'none';
  }

  function showDashboard(user) {
    activeFilter = 'ALL';
    activeChartFilter = null;
    searchKeyword = '';
    searchInput.value = '';
    chartFilterNotice.hidden = true;
    document.querySelectorAll('.filter-btn').forEach(button => button.classList.toggle('active', button === filterAll));
    activeInvestigationFilter = 'ALL';
    investigationFilterButtons.forEach(button => {
      button.classList.toggle('active', button.dataset.investigationFilter === 'ALL');
    });
    showView(viewLogs);
    authAlert.textContent = '';
    authAlert.className = 'alert-box';
    authAlert.style.display = 'none';
    authScreen.style.display = 'none';
    dashboardScreen.style.display = 'block';
    navUserName.textContent = user.name || 'Analyst';
    loadLogsData();
  }

  function setLoggedInUser(user) {
    sessionStorage.setItem('current_user', JSON.stringify(user));
    showDashboard(user);
  }

  // --- Load Data (500 Records from SQLite Database) ---
  async function loadLogsData() {
    try {
      // Fetch full set from Node.js backend SQLite
      const res = await fetch('/api/logs?limit=500');
      if (res.ok) {
        const data = await res.json();
        usingLocalData = false;
        renderDashboard(data);
        return;
      }
      throw new Error(`Logs request failed with status ${res.status}`);
    } catch (err) {
      console.warn('Could not load logs from the API; trying bundled data.', err);
    }

    // Fallback to pre-bundled data if running as static file
    if (window.FIREWALL_DATA) {
      usingLocalData = true;
      renderDashboard(window.FIREWALL_DATA);
    } else {
      showToast('Could not load firewall logs');
    }
  }

  function renderDashboard(data) {
    const records = data.records || [];
    if (usingLocalData) {
      const savedCases = getLocalInvestigations();
      allLogs = records.map(log => ({ ...log, ...(savedCases[log.id] || {}) }));
    } else {
      allLogs = records;
    }
    renderInvestigations();
    filteredLogs = [...allLogs];

    // Compute metrics
    const total = allLogs.length;
    const successCount = allLogs.filter(item => item.status === 'Success').length;
    const failedCount = allLogs.filter(item => item.status === 'Failed').length;

    kpiTotal.textContent = total.toLocaleString();
    kpiSuccess.textContent = successCount.toLocaleString();
    kpiFailed.textContent = failedCount.toLocaleString();

    const successPct = total > 0 ? ((successCount / total) * 100).toFixed(1) : 0;
    const failedPct = total > 0 ? ((failedCount / total) * 100).toFixed(1) : 0;

    kpiSuccessRate.textContent = `${successPct}% Permitted Traffic`;
    kpiFailedRate.textContent = `${failedPct}% Denied or Dropped`;

    filterAll.textContent = `All Logs (${total})`;
    filterSuccess.textContent = `✅ Success (${successCount})`;
    filterFailed.textContent = `❌ Failed (${failedCount})`;

    applyFilters();
  }

  // --- Filtering & 25-Per-Page Pagination ---
  function applyFilters() {
    filteredLogs = allLogs.filter(item => {
      // Status filter
      if (activeFilter === 'Success' && item.status !== 'Success') return false;
      if (activeFilter === 'Failed' && item.status !== 'Failed') return false;

      // Keyword search
      if (searchKeyword) {
        const q = searchKeyword.toLowerCase();
        const match =
          (item.src_ip && item.src_ip.includes(q)) ||
            (item.src_port != null && String(item.src_port).includes(q)) ||
            (item.dst_ip && item.dst_ip.includes(q)) ||
            (item.dst_port != null && String(item.dst_port).includes(q)) ||
            (item.protocol && item.protocol.toLowerCase().includes(q)) ||
            (item.service && item.service.toLowerCase().includes(q)) ||
            (item.rule && item.rule.toLowerCase().includes(q)) ||
            (item.action && item.action.toLowerCase().includes(q)) ||
            (item.status && item.status.toLowerCase().includes(q)) ||
            (item.severity && item.severity.toLowerCase().includes(q)) ||
            (item.attack && item.attack.toLowerCase().includes(q)) ||
            (item.timestamp && item.timestamp.toLowerCase().includes(q)) ||
            (item.id && item.id.toLowerCase().includes(q));
          if (!match) return false;
        }

        if (activeChartFilter && !matchesChartFilter(item, activeChartFilter)) return false;
        return true;
    });

    currentPage = 1;
    renderTablePage();
  }

  // Renders exactly 25 records for the current page
  function renderTablePage() {
    const total = filteredLogs.length;
    const totalPages = Math.max(1, Math.ceil(total / pageSize));

    if (currentPage > totalPages) currentPage = totalPages;

    const startIndex = (currentPage - 1) * pageSize;
    const endIndex = Math.min(startIndex + pageSize, total);
    const pageRecords = filteredLogs.slice(startIndex, endIndex);

    tableBody.innerHTML = '';

    if (pageRecords.length === 0) {
      tableBody.innerHTML = `
        <tr>
          <td colspan="10" style="text-align: center; padding: 3rem; color: #94a3b8;">
            No logs found matching your filter criteria.
          </td>
        </tr>
      `;
      paginationInfo.textContent = 'Showing 0 records';
      pageIndicator.textContent = 'Page 0 of 0';
      btnFirstPage.disabled = true;
      btnPrevPage.disabled = true;
      btnNextPage.disabled = true;
      btnLastPage.disabled = true;
      return;
    }

    pageRecords.forEach(log => {
      const tr = document.createElement('tr');
      tr.className = 'table-row';

      const isSuccess = log.status === 'Success';
      const badgeClass = isSuccess ? 'badge success' : 'badge failed';
      const statusText = isSuccess ? 'SUCCESS' : 'FAILED';
      const knownInvestigationStatuses = ['New', 'Investigating', 'Resolved'];
      const investigationSaved = hasSavedInvestigation(log);
      const investigationStatus = investigationSaved && knownInvestigationStatuses.includes(log.investigation_status)
        ? log.investigation_status
        : investigationSaved ? 'New' : 'Not saved';
      const investigationBadgeClass = investigationSaved
        ? investigationStatus.toLowerCase()
        : 'not-saved';

      tr.innerHTML = `
        <td><strong>${log.id}</strong></td>
        <td style="color: #94a3b8;">${log.timestamp.substring(0, 19).replace('T', ' ')}</td>
        <td><span class="${badgeClass}">${statusText}</span></td>
        <td><code>${log.action}</code></td>
        <td class="endpoint">${log.src_ip}:${log.src_port}</td>
        <td class="endpoint">${log.dst_ip}:${log.dst_port}</td>
        <td>${log.protocol} / <strong>${log.service}</strong></td>
        <td style="color: #94a3b8; font-size: 0.75rem;">${log.rule}</td>
        <td><span class="investigation-badge ${investigationBadgeClass}">${investigationStatus}</span></td>
        <td style="text-align: right;">
          <button class="btn btn-sm btn-secondary">Details</button>
        </td>
      `;

      // Click to inspect row (queries database)
      tr.addEventListener('click', () => openDetailModal(log));
      tableBody.appendChild(tr);
    });

    // Pagination status
    paginationInfo.textContent = `Showing ${(startIndex + 1)} - ${endIndex} of ${total} records`;
    pageIndicator.textContent = `Page ${currentPage} of ${totalPages}`;

    btnFirstPage.disabled = currentPage <= 1;
    btnPrevPage.disabled = currentPage <= 1;
    btnNextPage.disabled = currentPage >= totalPages;
    btnLastPage.disabled = currentPage >= totalPages;
  }

  function renderInvestigations() {
    if (!investigationTableBody) return;
    const savedCases = allLogs
      .filter(hasSavedInvestigation)
      .filter(log => activeInvestigationFilter === 'ALL' || log.investigation_status === activeInvestigationFilter);
    const allSavedCases = allLogs.filter(hasSavedInvestigation);
    const counts = {
      New: allSavedCases.filter(log => log.investigation_status === 'New').length,
      Investigating: allSavedCases.filter(log => log.investigation_status === 'Investigating').length,
      Resolved: allSavedCases.filter(log => log.investigation_status === 'Resolved').length
    };

    investigationTotal.textContent = savedCases.length.toLocaleString();
    investigationNew.textContent = counts.New.toLocaleString();
    investigationInProgress.textContent = counts.Investigating.toLocaleString();
    investigationResolved.textContent = counts.Resolved.toLocaleString();
    investigationTableBody.innerHTML = '';

    if (savedCases.length === 0) {
      const emptyMessage = allSavedCases.length === 0
        ? 'No saved investigations yet. Open a log and save its investigation details to add it here.'
        : `No ${activeInvestigationFilter.toLowerCase()} investigations. Choose another status filter to see other cases.`;
      investigationTableBody.innerHTML = `<tr><td colspan="9" class="empty-investigations">${emptyMessage}</td></tr>`;
      return;
    }

    savedCases
      .sort((a, b) => (b.investigation_updated_at || '').localeCompare(a.investigation_updated_at || ''))
      .forEach(log => {
        const status = ['New', 'Investigating', 'Resolved'].includes(log.investigation_status)
          ? log.investigation_status
          : 'New';
        const row = document.createElement('tr');
        row.className = 'table-row';
        row.innerHTML = `
          <td><strong>${log.id}</strong></td>
          <td>${log.investigation_updated_at ? new Date(log.investigation_updated_at).toLocaleString() : '-'}</td>
          <td><span class="investigation-badge ${status.toLowerCase()}">${status}</span></td>
          <td>${log.action}</td>
          <td class="endpoint">${log.src_ip}:${log.src_port}</td>
          <td class="endpoint">${log.dst_ip}:${log.dst_port}</td>
          <td>${log.attack || 'No attack signature recorded'}</td>
          <td class="investigation-notes-cell"></td>
          <td><button class="btn btn-sm btn-secondary" type="button">Details</button></td>
        `;
        row.querySelector('.investigation-notes-cell').textContent = log.investigation_notes || 'No notes';
        row.addEventListener('click', () => openDetailModal(log));
        investigationTableBody.appendChild(row);
      });
  }

  function hasSavedInvestigation(log) {
      return Boolean(
        log.investigation_updated_at ||
        (typeof log.investigation_notes === 'string' && log.investigation_notes.trim()) ||
        ['Investigating', 'Resolved'].includes(log.investigation_status)
      );
  }

  // --- Click-to-Inspect Detail Modal (Queries SQLite DB) ---
  async function openDetailModal(log) {
    let logData = log;
    currentLogId = log.id;

    // Fetch directly from SQLite backend API by ID
    if (!usingLocalData) {
      try {
        const res = await fetch(`/api/logs/${log.id}`);
        if (!res.ok) throw new Error(`Log details request failed with status ${res.status}`);
        logData = await res.json();
      } catch (err) {
        console.error('Could not load log details from the API.', err);
        caseSaveMessage.textContent = 'Could not load the latest log details from the server.';
      }
    } else {
      const savedCases = getLocalInvestigations();
      logData = { ...logData, ...(savedCases[log.id] || {}) };
    }

    document.getElementById('modalLogId').textContent = logData.id;

    const isSuccess = logData.status === 'Success';
    const badge = document.getElementById('modalStatusBadge');
    badge.className = isSuccess ? 'badge success' : 'badge failed';
    badge.textContent = isSuccess ? 'SUCCESS [ALLOW]' : `FAILED [${logData.action}]`;

    document.getElementById('modalTime').textContent = logData.timestamp;
    document.getElementById('modalFirewall').textContent = logData.firewall || 'FW-EDGE-01';
    document.getElementById('modalSource').textContent = `${logData.src_ip} : ${logData.src_port} (${logData.src_zone || 'LAN'})`;
    document.getElementById('modalDest').textContent = `${logData.dst_ip} : ${logData.dst_port} (${logData.dst_zone || 'DMZ'})`;
    document.getElementById('modalProtoService').textContent = `${logData.protocol} / ${logData.service}`;
    document.getElementById('modalRule').textContent = logData.rule;
    document.getElementById('modalAction').textContent = logData.action;
    document.getElementById('modalAttack').textContent = logData.attack || 'No attack signature recorded';
    document.getElementById('modalVolume').textContent = `${logData.packets || 0} pkts / ${((logData.bytes || 0) / 1024).toFixed(1)} KB`;
    document.getElementById('modalZones').textContent = `${logData.src_zone || 'LAN'} ➔ ${logData.dst_zone || 'DMZ'}`;
    document.getElementById('modalRawLog').textContent = logData.raw_log || `${logData.timestamp} firewall=${logData.firewall} action=${logData.action}`;
    caseStatusInput.value = ['New', 'Investigating', 'Resolved'].includes(logData.investigation_status)
      ? logData.investigation_status
      : 'New';
    caseNotesInput.value = logData.investigation_notes || '';
    caseSaveMessage.textContent = '';

    detailModal.classList.add('active');
  }

  function getLocalInvestigations() {
    try {
      const investigations = JSON.parse(localStorage.getItem('firewall_investigations') || '{}');
      return investigations && typeof investigations === 'object' && !Array.isArray(investigations)
        ? investigations
        : {};
    } catch (err) {
      console.error('Could not read saved browser investigations.', err);
      return {};
    }
  }

  async function saveInvestigation() {
    if (!currentLogId) return;
    btnSaveInvestigation.disabled = true;
    caseSaveMessage.textContent = 'Saving...';

    const investigation = {
      investigation_status: caseStatusInput.value,
      investigation_notes: caseNotesInput.value.trim()
    };
    let savedInvestigation;

    try {
      if (usingLocalData) {
        const savedCases = getLocalInvestigations();
        savedCases[currentLogId] = {
          ...investigation,
          investigation_updated_at: new Date().toISOString()
        };
        localStorage.setItem('firewall_investigations', JSON.stringify(savedCases));
        savedInvestigation = savedCases[currentLogId];
      } else {
        const res = await fetch(`/api/logs/${currentLogId}/investigation`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: caseStatusInput.value, notes: caseNotesInput.value })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || `Save failed with status ${res.status}`);
        savedInvestigation = data;
      }

      const updatedLog = log => log.id === currentLogId ? { ...log, ...savedInvestigation } : log;
      allLogs = allLogs.map(updatedLog);
      filteredLogs = filteredLogs.map(updatedLog);
      renderTablePage();
      renderInvestigations();
      closeDetailModal();
      showToast(usingLocalData
        ? 'Investigation saved in this browser'
        : 'Investigation saved to SQLite');
    } catch (err) {
      console.error('Could not save investigation.', err);
      caseSaveMessage.textContent = err.message || 'Could not save investigation.';
    } finally {
      btnSaveInvestigation.disabled = false;
    }
  }

  function closeDetailModal() {
    detailModal.classList.remove('active');
  }

  // --- Analytics & Graphs View (Queries SQLite /api/analytics) ---
  async function loadAnalyticsGraphs() {
    if (typeof Chart === 'undefined') return;

    try {
      const res = await fetch('/api/analytics');
      if (res.ok) {
        const data = await res.json();
        renderCharts(data);
        return;
      }
    } catch {
      console.log('Using local fallback for charts');
    }

    // Fallback calculation from loaded logs
    const statusMap = { Success: 0, Failed: 0 };
    const serviceMap = {};
    const protoMap = {};
    const attackMap = {};

    allLogs.forEach(r => {
      statusMap[r.status] = (statusMap[r.status] || 0) + 1;
      const serviceKey = `${r.service}:${r.dst_port}`;
      serviceMap[serviceKey] = (serviceMap[serviceKey] || 0) + 1;
      protoMap[r.protocol] = (protoMap[r.protocol] || 0) + 1;
      if (r.attack) attackMap[r.attack] = (attackMap[r.attack] || 0) + 1;
    });

    renderCharts({
      status_distribution: Object.entries(statusMap).map(([status, count]) => ({ status, count })),
      top_services: Object.entries(serviceMap).sort((a,b) => b[1] - a[1]).slice(0, 8).map(([key, count]) => {
        const [service, port] = key.split(':');
        return { service, port, count };
      }),
      protocols: Object.entries(protoMap).map(([protocol, count]) => ({ protocol, count })),
      attacks: Object.entries(attackMap).sort((a,b) => b[1] - a[1]).slice(0, 8).map(([attack, count]) => ({ attack, count }))
    });
  }

  function renderCharts(data) {
    Chart.defaults.color = '#94a3b8';
    Chart.defaults.font.family = "'Inter', sans-serif";

    // Chart 1: Status Doughnut
    const statusCtx = document.getElementById('chartStatus').getContext('2d');
    if (chartStatusInstance) chartStatusInstance.destroy();

    // Explicitly order and color so Success is ALWAYS Green and Failed is ALWAYS Red
    const rawStatusList = data.status_distribution || [];
    const statusOrder = ['Success', 'Failed'];
    const statusLabels = [];
    const statusValues = [];
    const statusColors = [];

    statusOrder.forEach(name => {
      const found = rawStatusList.find(item => item.status.toLowerCase() === name.toLowerCase());
      if (found) {
        statusLabels.push(found.status);
        statusValues.push(found.count);
        statusColors.push(name === 'Success' ? '#10b981' : '#ef4444');
      }
    });

    chartStatusInstance = new Chart(statusCtx, {
      type: 'doughnut',
      data: {
        labels: statusLabels,
        datasets: [{
          data: statusValues,
          backgroundColor: statusColors,
          borderColor: '#131b2e',
          borderWidth: 3
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        onClick: (event, elements) => {
          if (elements.length) {
            const status = statusLabels[elements[0].index];
            setChartFilter({ field: 'status', value: status }, `Status is ${status}`);
          }
        },
        plugins: {
          legend: { position: 'bottom', labels: { color: '#cbd5e1', font: { weight: '600' } } }
        }
      }
    });

    // Chart 2: Top Services Bar
    const servCtx = document.getElementById('chartServices').getContext('2d');
    if (chartServicesInstance) chartServicesInstance.destroy();

    const serviceItems = (data.top_services || []).map(s => ({
      ...s,
      port: s.port ?? allLogs.find(log => log.service === s.service)?.dst_port
    }));
    const servLabels = serviceItems.map(s => s.port == null ? s.service : `${s.service} (${s.port})`);
    const servValues = serviceItems.map(s => s.count);

    chartServicesInstance = new Chart(servCtx, {
      type: 'bar',
      data: {
        labels: servLabels,
        datasets: [{
          label: 'Requests',
          data: servValues,
          backgroundColor: 'rgba(59, 130, 246, 0.75)',
          borderColor: '#3b82f6',
          borderWidth: 1.5,
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        onClick: (event, elements) => {
          if (elements.length) {
            const service = serviceItems[elements[0].index];
            setChartFilter(
              { field: 'servicePort', service: service.service, port: service.port },
              `${service.service} on port ${service.port}`
            );
          }
        },
        scales: {
          x: { grid: { display: false }, ticks: { color: '#cbd5e1' } },
          y: { grid: { color: 'rgba(255, 255, 255, 0.05)' }, ticks: { color: '#64748b' } }
        },
        plugins: { legend: { display: false } }
      }
    });

    // Chart 3: Protocol Telemetry
    const protoCtx = document.getElementById('chartProtocols').getContext('2d');
    if (chartProtocolsInstance) chartProtocolsInstance.destroy();

    const protoLabels = (data.protocols || []).map(p => p.protocol);
    const protoValues = (data.protocols || []).map(p => p.count);

    chartProtocolsInstance = new Chart(protoCtx, {
      type: 'pie',
      data: {
        labels: protoLabels,
        datasets: [{
          data: protoValues,
          backgroundColor: ['#06b6d4', '#8b5cf6', '#10b981'],
          borderColor: '#131b2e',
          borderWidth: 3
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        onClick: (event, elements) => {
          if (elements.length) {
            const protocol = protoLabels[elements[0].index];
            setChartFilter({ field: 'protocol', value: protocol }, `Protocol is ${protocol}`);
          }
        },
        plugins: {
          legend: { position: 'bottom', labels: { color: '#cbd5e1' } }
        }
      }
    });

    // Chart 4: Stored Attack Labels
    const attackCtx = document.getElementById('chartAttacks').getContext('2d');
    if (chartAttacksInstance) chartAttacksInstance.destroy();

    const attackLabels = (data.attacks || []).map(a => a.attack.replace(/_/g, ' '));
    const attackValues = (data.attacks || []).map(a => a.count);

    chartAttacksInstance = new Chart(attackCtx, {
      type: 'bar',
      data: {
        labels: attackLabels,
        datasets: [{
          label: 'Incidents',
          data: attackValues,
          backgroundColor: 'rgba(239, 68, 68, 0.75)',
          borderColor: '#ef4444',
          borderWidth: 1.5,
          borderRadius: 6
        }]
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        onClick: (event, elements) => {
          if (elements.length) {
            const attack = data.attacks[elements[0].index].attack;
            setChartFilter({ field: 'attack', value: attack }, `Attack label is ${attack.replace(/_/g, ' ')}`);
          }
        },
        scales: {
          x: { grid: { color: 'rgba(255, 255, 255, 0.05)' } },
          y: { grid: { display: false }, ticks: { color: '#cbd5e1', font: { size: 10 } } }
        },
        plugins: { legend: { display: false } }
      }
    });
  }

  // --- Export CSV ---
  function exportCSV() {
    if (filteredLogs.length === 0) {
      showToast('No records to export');
      return;
    }

    const headers = ['Log_ID', 'Timestamp', 'Status', 'Action', 'Src_IP', 'Src_Port', 'Dst_IP', 'Dst_Port', 'Protocol', 'Service', 'Rule', 'Severity', 'Attack_Label', 'Investigation_Status', 'Investigation_Notes'];
    const rows = filteredLogs.map(r => [
      r.id,
      r.timestamp,
      r.status,
      r.action,
      r.src_ip,
      r.src_port,
      r.dst_ip,
      r.dst_port,
      r.protocol,
      r.service,
      r.rule,
      r.severity,
      r.attack,
      r.investigation_status || 'New',
      r.investigation_notes
    ].map(value => `"${String(value ?? '').replace(/"/g, '""')}"`));

    const csvContent = [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `firewall_logs_${Date.now()}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    showToast(`Exported ${filteredLogs.length} records to CSV`);
  }

  // --- Toast ---
  let toastTimer;
  function showToast(msg) {
    toast.textContent = msg;
    toast.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove('show'), 2500);
  }

  // --- Event Listeners ---
  function setupEvents() {
    // Navigation Tabs (Logs Explorer vs Analytics & Graphs)
    navTabLogs.addEventListener('click', () => {
      showView(viewLogs);
    });

    navTabAnalytics.addEventListener('click', () => {
      showView(viewAnalytics);
    });

    navTabInvestigations.addEventListener('click', () => {
      showView(viewInvestigations);
    });

    investigationFilterButtons.forEach(button => {
      button.addEventListener('click', () => {
        activeInvestigationFilter = button.dataset.investigationFilter;
        investigationFilterButtons.forEach(filterButton => {
          filterButton.classList.toggle('active', filterButton === button);
        });
        renderInvestigations();
      });
    });

    btnClearChartFilter.addEventListener('click', clearChartFilter);
    btnSaveInvestigation.addEventListener('click', saveInvestigation);

    btnOpenHelp.addEventListener('click', () => {
      helpModal.hidden = false;
      btnCloseHelp.focus();
    });
    btnCloseHelp.addEventListener('click', closeHelpModal);
    helpModal.addEventListener('click', (e) => {
      if (e.target === helpModal) closeHelpModal();
    });
    helpTabInstructions.addEventListener('click', () => setHelpTab(helpTabInstructions));
    helpTabApproach.addEventListener('click', () => setHelpTab(helpTabApproach));
    document.querySelector('.help-tabs').addEventListener('keydown', (e) => {
      if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
        e.preventDefault();
        const nextTab = document.activeElement === helpTabInstructions
          ? helpTabApproach
          : helpTabInstructions;
        setHelpTab(nextTab);
        nextTab.focus();
      }
    });

    // Auth Tabs
    tabLogin.addEventListener('click', () => {
      tabLogin.classList.add('active');
      tabRegister.classList.remove('active');
      formLogin.style.display = 'flex';
      formRegister.style.display = 'none';
      authAlert.style.display = 'none';
    });

    tabRegister.addEventListener('click', () => {
      tabRegister.classList.add('active');
      tabLogin.classList.remove('active');
      formLogin.style.display = 'none';
      formRegister.style.display = 'flex';
      authAlert.style.display = 'none';
    });

    // Login Form Submit (Node.js & SQLite)
    formLogin.addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('loginEmail').value.trim();
      const password = document.getElementById('loginPass').value;

      try {
        const res = await fetch('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password })
        });
        const data = await res.json();
        if (res.ok) {
          setLoggedInUser(data.user);
          showToast(`Welcome back, ${data.user.name}`);
        } else {
          authAlert.textContent = data.error || 'Invalid credentials';
          authAlert.className = 'alert-box error';
          authAlert.style.display = 'block';
        }
      } catch (err) {
        authAlert.textContent = 'Could not sign in because the server is unavailable. Start the dashboard server and try again.';
        authAlert.className = 'alert-box error';
        authAlert.style.display = 'block';
        console.error('Login request failed.', err);
      }
    });

    // Register Form Submit (Node.js & SQLite)
    formRegister.addEventListener('submit', async (e) => {
      e.preventDefault();
      const name = document.getElementById('regName').value.trim();
      const email = document.getElementById('regEmail').value.trim();
      const password = document.getElementById('regPass').value;

      try {
        const res = await fetch('/api/auth/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, email, password })
        });
        const data = await res.json();
        if (res.ok) {
          document.getElementById('loginEmail').value = email;
          document.getElementById('loginPass').value = '';
          formRegister.reset();
          tabLogin.classList.add('active');
          tabRegister.classList.remove('active');
          formLogin.style.display = 'flex';
          formRegister.style.display = 'none';
          authAlert.textContent = 'Account successfully created. Please sign in.';
          authAlert.className = 'alert-box success';
          authAlert.style.display = 'block';
        } else {
          authAlert.textContent = data.error || 'Registration failed';
          authAlert.className = 'alert-box error';
          authAlert.style.display = 'block';
        }
      } catch (err) {
        authAlert.textContent = 'Could not create the account because the server is unavailable. Start the dashboard server and try again.';
        authAlert.className = 'alert-box error';
        authAlert.style.display = 'block';
        console.error('Registration request failed.', err);
      }
    });

    // Logout
    btnLogout.addEventListener('click', () => {
      sessionStorage.removeItem('current_user');
      authAlert.textContent = '';
      authAlert.className = 'alert-box';
      authAlert.style.display = 'none';
      showToast('Signed out successfully');
      showAuthScreen();
    });

    // Filter Buttons
    [filterAll, filterSuccess, filterFailed].forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        activeFilter = btn.getAttribute('data-filter');
        applyFilters();
      });
    });

    // Search Input
    searchInput.addEventListener('input', (e) => {
      searchKeyword = e.target.value.trim();
      applyFilters();
    });

    // Pagination Controls (25 records per page)
    btnFirstPage.addEventListener('click', () => {
      currentPage = 1;
      renderTablePage();
    });

    btnPrevPage.addEventListener('click', () => {
      if (currentPage > 1) {
        currentPage--;
        renderTablePage();
      }
    });

    btnNextPage.addEventListener('click', () => {
      const totalPages = Math.ceil(filteredLogs.length / pageSize);
      if (currentPage < totalPages) {
        currentPage++;
        renderTablePage();
      }
    });

    btnLastPage.addEventListener('click', () => {
      const totalPages = Math.ceil(filteredLogs.length / pageSize);
      currentPage = totalPages;
      renderTablePage();
    });

    // CSV Export
    btnExportCSV.addEventListener('click', exportCSV);

    // Detail Modal Close
    btnCloseDetail.addEventListener('click', closeDetailModal);
    btnDismissDetail.addEventListener('click', closeDetailModal);
    detailModal.addEventListener('click', (e) => {
      if (e.target === detailModal) closeDetailModal();
    });

    // ESC key closes modal
    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        closeDetailModal();
        if (!helpModal.hidden) closeHelpModal();
      }
    });
  }

})();
