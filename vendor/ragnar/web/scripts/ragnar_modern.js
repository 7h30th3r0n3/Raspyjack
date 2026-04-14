// Ragnar_modern.js - Enhanced Modern JavaScript for Ragnar web interface by Pierre Gode 2025

let socket;
let reconnectAttempts = 0;
const RECONNECT_WARNING_THRESHOLD = 5;
const RECONNECT_DELAY_MAX = 15000;
let currentTab = 'dashboard';
let autoRefreshIntervals = {};

let preloadedTabs = new Set();
let pendingFileHighlight = null;
let manualModeActive = false;
let manualDataPrimed = false;
let imagesLoaded = false;
const PWN_STATUS_POLL_INTERVAL = 15000;
const PWN_STATUS_FAST_INTERVAL = 4000;
const PWN_LOG_POLL_INTERVAL = 2500;
let pwnStatus = {
    state: 'not_installed',
    message: 'Waiting for status...',
    phase: 'idle',
    installed: false,
    installing: false,
    mode: 'ragnar',
    target_mode: 'ragnar',
    last_switch: '',
    service_active: false,
    service_enabled: false,
    timestamp: null,
    log_file: null
};
let lastPwnState = null;
let _pwnSwapRequestedThisSession = false;
let currentPwnStatusInterval = PWN_STATUS_POLL_INTERVAL;
let pwnLogCursor = 0;
let pwnLogStreamTimer = null;
let pwnLogStreaming = false;
let pwnLogStopTimeout = null;
let pwnLogActiveFile = null;
let pwnLogFetchInFlight = false;
let headlessMode = false;
const RELEASE_GATE_DEFAULT_MESSAGE = 'A controlled release is rolling out. Updating manually may cause instability.';
let releaseGateState = { enabled: false, message: RELEASE_GATE_DEFAULT_MESSAGE };
let releaseGateResolver = null;
let releaseGatePendingPromise = null;
let threatIntelStatusFilter = 'open';

// ── Credential Table state ──────────────────────────────────────
let credentialsCache = null;
let credServiceFilter = 'all';
let credIPSearch = '';
let credSortCol = 'ip';
let credSortAsc = true;

const CRED_SERVICE_PORTS = { ssh: 22, smb: 445, ftp: 21, telnet: 23, rdp: 3389, sql: 3306 };
const CRED_SERVICE_COLORS = {
    ssh:    'bg-blue-900 text-blue-300',
    smb:    'bg-purple-900 text-purple-300',
    ftp:    'bg-yellow-900 text-yellow-300',
    telnet: 'bg-orange-900 text-orange-300',
    rdp:    'bg-pink-900 text-pink-300',
    sql:    'bg-green-900 text-green-300',
};

async function loadCredentials(force = false) {
    if (!force && credentialsCache) { displayCredentials(credentialsCache); return; }
    try {
        const data = await fetchAPI('/api/credentials');
        // Flatten into unified array
        const flat = [];
        Object.entries(data).forEach(([svc, entries]) => {
            (entries || []).forEach(e => flat.push({ ...e, service: svc }));
        });
        credentialsCache = flat;
        displayCredentials(flat);
    } catch(err) {
        const tbody = document.getElementById('cred-table-body');
        if (tbody) tbody.innerHTML =
            `<tr><td colspan="6" class="py-8 text-center text-red-400">Error loading credentials: ${escapeHtml(err.message)}</td></tr>`;
    }
}

function onCredSearch(val) { credIPSearch = val.trim().toLowerCase(); displayCredentials(credentialsCache); }

function filterCredsByService(svc) {
    credServiceFilter = svc;
    document.querySelectorAll('.cred-svc-btn').forEach(b => {
        const active = b.getAttribute('data-svc') === svc;
        b.classList.toggle('bg-Ragnar-600', active);
        b.classList.toggle('bg-slate-700', !active);
        b.classList.toggle('hover:bg-slate-600', !active);
    });
    displayCredentials(credentialsCache);
}

function sortCredsBy(col) {
    if (credSortCol === col) { credSortAsc = !credSortAsc; } else { credSortCol = col; credSortAsc = true; }
    ['ip','service','username'].forEach(c => {
        const el = document.getElementById(`cred-sort-${c}`);
        if (el) el.textContent = c === credSortCol ? (credSortAsc ? '↑' : '↓') : '';
    });
    displayCredentials(credentialsCache);
}

function displayCredentials(data) {
    if (!data) return;
    const tbody = document.getElementById('cred-table-body');
    const statsEl = document.getElementById('cred-stats');
    const countEl = document.getElementById('cred-table-count');
    if (!tbody) return;

    // Build stats
    const svcCounts = {};
    data.forEach(c => { svcCounts[c.service] = (svcCounts[c.service] || 0) + 1; });
    const totalCreds = data.length;
    let statsHtml = `<div class="bg-slate-800 rounded-lg p-3 text-center"><div class="text-2xl font-bold">${totalCreds}</div><div class="text-xs text-gray-400 mt-1">Total</div></div>`;
    Object.entries(CRED_SERVICE_PORTS).forEach(([svc]) => {
        const count = svcCounts[svc] || 0;
        statsHtml += `<div class="bg-slate-800 rounded-lg p-3 text-center cursor-pointer hover:bg-slate-700 transition-colors" onclick="filterCredsByService('${svc}')">
            <div class="text-2xl font-bold ${count > 0 ? 'text-green-400' : 'text-gray-500'}">${count}</div>
            <div class="text-xs text-gray-400 mt-1 uppercase">${svc}</div>
        </div>`;
    });
    if (statsEl) statsEl.innerHTML = statsHtml;

    // Filter
    let rows = data;
    if (credServiceFilter !== 'all') rows = rows.filter(r => r.service === credServiceFilter);
    if (credIPSearch) rows = rows.filter(r => (r.ip || '').toLowerCase().includes(credIPSearch));

    // Sort
    rows = [...rows].sort((a, b) => {
        const av = (a[credSortCol] || '').toLowerCase();
        const bv = (b[credSortCol] || '').toLowerCase();
        return credSortAsc ? av.localeCompare(bv) : bv.localeCompare(av);
    });

    if (rows.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="py-8 text-center text-gray-400">No credentials match current filters</td></tr>`;
        if (countEl) countEl.textContent = '';
        return;
    }

    tbody.innerHTML = rows.map(r => {
        const port = CRED_SERVICE_PORTS[r.service] || '—';
        const badge = CRED_SERVICE_COLORS[r.service] || 'bg-slate-700 text-gray-300';
        const pwDisplay = r.password ? `<span class="font-mono">${escapeHtml(r.password)}</span>` : '<span class="text-gray-500 italic">none</span>';
        const safePw = r.password ? escapeHtml(r.password).replace(/'/g, '&#39;') : '';
        return `<tr class="border-b border-slate-800 hover:bg-slate-800 transition-colors">
            <td class="py-3 px-4 font-mono text-sm whitespace-nowrap">${escapeHtml(r.ip || '—')}</td>
            <td class="py-3 px-4 whitespace-nowrap"><span class="px-2 py-0.5 rounded text-xs font-semibold uppercase ${badge}">${escapeHtml(r.service)}</span></td>
            <td class="py-3 px-4 text-gray-400 whitespace-nowrap">${port}</td>
            <td class="py-3 px-4 font-mono whitespace-nowrap">${escapeHtml(r.username || '—')}</td>
            <td class="py-3 px-4 whitespace-nowrap">${pwDisplay}</td>
            <td class="py-3 px-4 whitespace-nowrap">
                ${r.password ? `<button onclick="copyCredToClipboard('${safePw}')" class="text-xs text-blue-400 hover:text-blue-300 px-2 py-1 rounded hover:bg-slate-700 transition-colors" title="Copy password">Copy</button>` : ''}
            </td>
        </tr>`;
    }).join('');

    if (countEl) countEl.textContent = `Showing ${rows.length} of ${data.length} credential${data.length !== 1 ? 's' : ''}`;
}

function copyCredToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        addConsoleMessage('Password copied to clipboard', 'success');
    }).catch(() => {
        addConsoleMessage('Copy failed — check browser permissions', 'warning');
    });
}

function exportCredentialsCSV() {
    if (!credentialsCache || credentialsCache.length === 0) {
        addConsoleMessage('No credentials to export', 'warning');
        return;
    }
    const csvRows = [['IP', 'Service', 'Port', 'Username', 'Password']];
    credentialsCache.forEach(r => {
        csvRows.push([r.ip || '', r.service || '', CRED_SERVICE_PORTS[r.service] || '', r.username || '', r.password || '']);
    });
    const csv = csvRows.map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ragnar_credentials_${new Date().toISOString().slice(0,10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
}

const configMetadata = {
    manual_mode: {
        label: "Pentest Mode",
        description: "Hold Ragnar in hands-on pentest control. Disable this to let the orchestrator continuously discover devices, run actions, and launch vulnerability scans automatically."
    },
    debug_mode: {
        label: "Debug Mode",
        description: "Enable verbose debug logging for deeper troubleshooting output."
    },
    scan_vuln_running: {
        label: "Vulnerability Scanning",
        description: "Enable automatic vulnerability scans on discovered hosts based on the configured interval."
    },
    scan_vuln_no_ports: {
        label: "Scan Hosts Without Ports",
        description: "When enabled, vulnerability scans will scan the top 50 common ports on hosts where no ports were discovered. When disabled, only hosts with discovered ports will be scanned."
    },
    enable_attacks: {
        label: "Enable Automatic Attacks",
        description: "Allow Ragnar to perform automated attacks (SSH, FTP, SMB, SQL, etc.) on discovered targets. Disable to only scan without attacking."
    },
    retry_success_actions: {
        label: "Retry Successful Actions",
        description: "Re-run actions that previously succeeded after the success retry delay to keep intelligence fresh."
    },
    retry_failed_actions: {
        label: "Retry Failed Actions",
        description: "Retry actions that failed after waiting the failed retry delay."
    },
    blacklistcheck: {
        label: "Honor Scan Blacklists",
        description: "Skip hosts or MAC addresses that appear in the scan blacklist lists when running automated actions."
    },
    displaying_csv: {
        label: "Display Scan CSV",
        description: "Push the most recent scan CSV results to the display after each network sweep."
    },
    log_debug: {
        label: "Log Debug Messages",
        description: "Include debug-level entries in Ragnar logs."
    },
    log_info: {
        label: "Log Info Messages",
        description: "Include informational entries in Ragnar logs."
    },
    log_warning: {
        label: "Log Warning Messages",
        description: "Include warning-level entries in Ragnar logs."
    },
    log_error: {
        label: "Log Error Messages",
        description: "Include error-level entries in Ragnar logs."
    },
    log_critical: {
        label: "Log Critical Messages",
        description: "Include critical-level entries in Ragnar logs."
    },
    startup_delay: {
        label: "Startup Delay (s)",
        description: "Seconds to wait after boot before the orchestrator begins automated activity."
    },
    web_delay: {
        label: "Web Update Delay (s)",
        description: "Seconds between refreshes of the web dashboards and API responses."
    },
    screen_delay: {
        label: "Screen Update Delay (s)",
        description: "Seconds between display refreshes."
    },
    comment_delaymin: {
        label: "Comment Delay Min (s)",
        description: "Minimum number of seconds between on-screen comment rotations."
    },
    comment_delaymax: {
        label: "Comment Delay Max (s)",
        description: "Maximum number of seconds between on-screen comment rotations."
    },
    livestatus_delay: {
        label: "Live Status Delay (s)",
        description: "Seconds between updates to the live status CSV that feeds dashboards."
    },
    image_display_delaymin: {
        label: "Image Display Min (s)",
        description: "Minimum time an image remains on the display."
    },
    image_display_delaymax: {
        label: "Image Display Max (s)",
        description: "Maximum time an image remains on the display."
    },
    scan_interval: {
        label: "Scan Interval (s)",
        description: "Seconds between full network discovery scans."
    },
    scan_vuln_interval: {
        label: "Vulnerability Scan Interval (s)",
        description: "Seconds between automated vulnerability scan cycles when enabled."
    },
    failed_retry_delay: {
        label: "Failed Retry Delay (s)",
        description: "Seconds to wait before retrying an action that previously failed."
    },
    success_retry_delay: {
        label: "Success Retry Delay (s)",
        description: "Seconds to wait before repeating an action that previously succeeded."
    },
    ref_width: {
        label: "Reference Width",
        description: "Reference pixel width used to scale drawings for the display."
    },
    ref_height: {
        label: "Reference Height",
        description: "Reference pixel height used to scale drawings for the display."
    },
    screen_reversed: {
        label: "Flip Display Output",
        description: "Rotate the display output. Use 180° when mounted upside down, or 90°/270° for portrait orientation."
    },
    epd_type: {
        label: "EPD Type",
        description: "Model identifier for the connected display."
    },
    gc9a01_mascot_color: {
        label: "GC9A01 Mascot Tint Color",
        description: "Tint color applied to the animated mascot on the GC9A01 1.28\" round TFT display. Only visible when GC9A01 is selected."
    },
    lcd1602_i2c_address: {
        label: "LCD1602 I2C Address",
        description: "I2C address of the PCF8574 backpack on the LCD1602 16×2 character display. Common values: 0x27 (most common) or 0x3F. Auto-detected if unreachable."
    },
    display_brightness: {
        label: "Display Brightness",
        description: "Brightness level for non-e-ink displays (SSD1306, GC9A01, MAX7219). Range 0–15. Default: 8."
    },
    spi_clock_mhz: {
        label: "SPI Clock Speed (MHz)",
        description: "SPI bus clock speed for the e-paper display in MHz. Lower values improve signal integrity when a PiSugar battery is stacked on the GPIO header. Default: 2 MHz. Try 1 MHz if you still see corrupted pixels."
    },
    max7219_spi_port: {
        label: "MAX7219 SPI Port",
        description: "SPI bus port for MAX7219 LED matrix (default: 0)"
    },
    max7219_spi_device: {
        label: "MAX7219 SPI Device",
        description: "SPI chip-enable pin for MAX7219 (0 = CE0, 1 = CE1, default: 0)"
    },
    max7219_block_orientation: {
        label: "MAX7219 Block Orientation",
        description: "Rotation of each 8×8 block (degrees). Try 0, 90, -90, or 180 if display looks wrong. Default: 0"
    },
    portlist: {
        label: "Additional Ports",
        description: "Comma separated list of extra ports to check on every host in addition to the sequential range."
    },
    mac_scan_blacklist: {
        label: "MAC Scan Blacklist",
        description: "Comma separated MAC addresses Ragnar should ignore during scans and automated actions."
    },
    ip_scan_blacklist: {
        label: "IP Scan Blacklist",
        description: "Comma separated IP addresses Ragnar should ignore during scans and automated actions."
    },
    steal_file_names: {
        label: "Target File Names",
        description: "Comma separated file name fragments that trigger file collection when encountered."
    },
    steal_file_extensions: {
        label: "Target File Extensions",
        description: "Comma separated file extensions that Ragnar should collect when found."
    },
    nmap_scan_aggressivity: {
        label: "Nmap Aggressiveness",
        description: "Timing template flag passed to nmap (for example -T2). Adjust to trade accuracy for speed."
    },
    portstart: {
        label: "Port Range Start",
        description: "First port in the sequential range scanned on every host."
    },
    portend: {
        label: "Port Range End",
        description: "Last port in the sequential range scanned on every host."
    },
    timewait_smb: {
        label: "SMB Retry Wait (s)",
        description: "Seconds to wait before retrying SMB actions against a host."
    },
    timewait_ssh: {
        label: "SSH Retry Wait (s)",
        description: "Seconds to wait before retrying SSH actions against a host."
    },
    timewait_telnet: {
        label: "Telnet Retry Wait (s)",
        description: "Seconds to wait before retrying Telnet actions against a host."
    },
    timewait_ftp: {
        label: "FTP Retry Wait (s)",
        description: "Seconds to wait before retrying FTP actions against a host."
    },
    timewait_sql: {
        label: "SQL Retry Wait (s)",
        description: "Seconds to wait before retrying SQL actions against a host."
    },
    timewait_rdp: {
        label: "RDP Retry Wait (s)",
        description: "Seconds to wait before retrying RDP actions against a host."
    },
    wifi_known_networks: {
        label: "Known Wi-Fi Networks",
        description: "Comma separated list of SSIDs Ragnar should automatically join when detected."
    },
    wifi_ap_ssid: {
        label: "AP SSID",
        description: "Network name broadcast when Ragnar creates its own access point."
    },
    wifi_ap_password: {
        label: "AP Password",
        description: "Password clients must use to join Ragnar's access point."
    },
    wifi_connection_timeout: {
        label: "Wi-Fi Connection Timeout (s)",
        description: "Seconds to wait for each Wi-Fi connection attempt before considering it failed."
    },
    wifi_max_attempts: {
        label: "Wi-Fi Max Attempts",
        description: "Number of Wi-Fi connection retries before giving up or falling back to AP mode."
    },
    wifi_scan_interval: {
        label: "Wi-Fi Scan Interval (s)",
        description: "Seconds between wireless network scans performed by the Wi-Fi manager."
    },
    wifi_monitor_enabled: {
        label: "Wi-Fi Monitor",
        description: "Keep the Wi-Fi manager running so connectivity issues are detected quickly."
    },
    wifi_auto_ap_fallback: {
        label: "Auto AP Fallback",
        description: "Automatically enable Ragnar's access point if normal Wi-Fi connectivity cannot be restored."
    },
    wifi_ap_timeout: {
        label: "AP Timeout (s)",
        description: "Maximum duration before an active Ragnar access point session shuts down automatically."
    },
    wifi_ap_idle_timeout: {
        label: "AP Idle Timeout (s)",
        description: "Seconds of inactivity allowed before shutting down the Ragnar access point."
    },
    wifi_reconnect_interval: {
        label: "Wi-Fi Reconnect Interval (s)",
        description: "Seconds between Wi-Fi reconnect attempts when the device is offline."
    },
    wifi_ap_cycle_enabled: {
        label: "AP Smart Cycling",
        description: "Periodically cycle the access point when active to limit exposure."
    },
    wifi_initial_connection_timeout: {
        label: "Initial Wi-Fi Timeout (s)",
        description: "Timeout for the very first Wi-Fi connection attempt during boot."
    },
    network_device_retention_days: {
        label: "Device Retention (days)",
        description: "Number of days to keep inactive devices in the network database before pruning them."
    },
    network_resolution_timeout: {
        label: "Resolution Timeout (s)",
        description: "Seconds to wait before re-resolving details for the same device."
    },
    network_confirmation_scans: {
        label: "Confirmation Scans",
        description: "Number of extra scans required to confirm a detected network change."
    },
    network_change_grace: {
        label: "Change Grace Period (s)",
        description: "Grace period after detecting a network change before automation responds."
    },
    network_intelligence_enabled: {
        label: "Network Intelligence",
        description: "Enable the network intelligence engine that tracks devices and their state changes."
    },
    network_auto_resolution: {
        label: "Automatic Resolution",
        description: "Automatically resolve and enrich newly discovered or changed devices."
    },
    network_max_failed_pings: {
        label: "Max Failed Pings Before Offline",
        description: "Number of consecutive failed ping/ARP checks before marking a host as offline (red dot). With ARP scans every 60s, setting this to 5 means ~5 minutes, 15 means ~15 minutes, 30 means ~30 minutes before offline status."
    },
    ai_enabled: {
        label: "Enable AI Insights",
        description: "Enable AI-powered network analysis and vulnerability insights using OpenAI GPT."
    },
    openai_api_token: {
        label: "OpenAI API Token",
        description: "Your OpenAI API key for AI-powered features. Keep this confidential."
    }
};

function getConfigLabel(key) {
    if (configMetadata[key] && configMetadata[key].label) {
        return configMetadata[key].label;
    }
    return key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
}

// Map installed driver names to display size keys for the dropdown
function epdTypeToSizeKey(epd_type) {
    if (!epd_type || epd_type === 'auto') return 'auto';
    if (epd_type.startsWith('epd2in13')) return '2in13';
    if (epd_type.startsWith('epd2in7')) return '2in7';
    if (epd_type.startsWith('epd2in9')) return '2in9';
    if (epd_type.startsWith('epd3in7')) return '3in7';
    if (epd_type.startsWith('epd4in26')) return '4in26';
    if (epd_type === 'gc9a01') return '1in28_tft';
    if (epd_type === 'ssd1306') return '0in96_oled';
    if (epd_type === 'lcd1602') return 'lcd1602';
    return epd_type; // fallback: return as-is
}

const displaySelectOptions = {
    epd_type: [
        { value: 'auto', label: 'Auto-detect' },
        { value: '2in13', label: '2.13" e-Paper (122x250)' },
        { value: '2in7', label: '2.7" e-Paper (176x264)' },
        { value: '2in9', label: '2.9" e-Paper (128x296)' },
        { value: '3in7', label: '3.7" e-Paper (280x480)' },
        { value: '4in26', label: '4.26" e-Paper (800x480)' },
        { value: '1in28_tft', label: '1.28" GC9A01 Round TFT (240x240)' },
        { value: '0in96_oled', label: '0.96" SSD1306 OLED (128x64)' },
        { value: 'lcd1602', label: '16×2 LCD1602 Character LCD (I2C)' },
        { value: 'max7219_8panel', label: 'MAX7219 8-panel LED Matrix (64×8)' },
        { value: 'max7219_4panel', label: 'MAX7219 4-panel LED Matrix (32×8)' }
    ],
    screen_reversed: [
        { value: '0', label: 'Normal (0°)' },
        { value: '90', label: 'Rotate 90°' },
        { value: '180', label: 'Rotate 180°' },
        { value: '270', label: 'Rotate 270°' }
    ]
};

function getConfigDescription(key) {
    if (configMetadata[key] && configMetadata[key].description) {
        return configMetadata[key].description;
    }
    return "No additional information available for this setting.";
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Escapes a value for safe embedding inside a single-quoted JS string
// that lives inside an HTML attribute (e.g. onclick="fn('VALUE')").
// escapeHtml alone does not escape single quotes.
function escapeAttr(str) {
    if (str == null) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/'/g, '&#39;')
        .replace(/"/g, '&quot;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/`/g, '&#96;');
}

function isValidIPv4(ip) {
    if (!ip) {
        return false;
    }
    const ipv4Pattern = /^(25[0-5]|2[0-4]\d|1?\d{1,2})(\.(25[0-5]|2[0-4]\d|1?\d{1,2})){3}$/;
    return ipv4Pattern.test(ip.trim());
}

document.addEventListener('DOMContentLoaded', function() {
    initializeSocket();
    initializeTabs();
    initializeMobileMenu();
    loadInitialData();
    setupAutoRefresh();
    setupEpaperAutoRefresh();
    setupEventListeners();
    initializeThreatIntelFilters();
    initializePwnUI();
    initializePwnagotchiVisibility();
    handleHeadlessMode();

});


function initializeSocket() {
    socket = io({
        reconnection: true,
        reconnectionDelay: 1000,
        reconnectionDelayMax: RECONNECT_DELAY_MAX
    });

    socket.on('connect', function() {
        console.log('Connected to Ragnar server');
        updateConnectionStatus(true);
        reconnectAttempts = 0;
        addConsoleMessage('Connected to Ragnar server', 'success');

        socket.emit('request_status');
        socket.emit('request_logs');
        refreshPwnagotchiStatus({ silent: true });
    });

    socket.on('connected', function(data) {
        // Server sends auth_configured flag on every socket connect
        if (data && typeof data.auth_configured !== 'undefined') {
            const show = data.auth_configured;
            const logoutBtn = document.getElementById('logout-btn');
            if (logoutBtn) logoutBtn.classList.toggle('hidden', !show);
            const mobileLogoutBtn = document.getElementById('mobile-logout-btn');
            if (mobileLogoutBtn) mobileLogoutBtn.classList.toggle('hidden', !show);
        }
    });

    socket.on('disconnect', function() {
        console.log('Disconnected from Ragnar server');
        updateConnectionStatus(false);
        addConsoleMessage('Disconnected from server', 'error');
        setTimeout(() => {
            if (socket && socket.disconnected) {
                console.log('Attempting manual socket reconnection');
                socket.connect();
            }
        }, 2000);
    });

    socket.on('status_update', function(data) {
        updateDashboardStatus(data);
    });

    socket.on('log_update', function(logs) {
        updateConsole(logs);
    });

    socket.on('pwnagotchi_status', function(statusPacket) {
        const previousState = pwnStatus.state;
        updatePwnagotchiUI(statusPacket);
        if (statusPacket && statusPacket.state && statusPacket.state !== previousState) {
            addConsoleMessage(`Pwnagotchi status changed: ${formatPwnStateLabel(statusPacket.state)}`, 'info');
        }
    });

    socket.on('network_update', function(data) {
        if (currentTab === 'network') {
            loadStableNetworkData();
        }
    });

    socket.on('credentials_update', function(data) {
        if (currentTab === 'discovered') {
            displayCredentialsTable(data);
        }
    });

    socket.on('loot_update', function(data) {
        if (currentTab === 'discovered') {
            displayLootTable(data);
        }
    });

    socket.on('config_updated', function(config) {
        addConsoleMessage('Configuration updated successfully', 'info');
        if (currentTab === 'config') {
            displayConfigForm(config);
        }
        updateAttackWarningBanner(Boolean(config && config.enable_attacks));
    });

    socket.on('scan_started', function(data) {
        handleScanStarted(data);
    });

    socket.on('scan_progress', function(data) {
        handleScanProgress(data);
    });

    socket.on('scan_host_update', function(data) {
        handleScanHostUpdate(data);
    });

    socket.on('scan_completed', function(data) {
        handleScanCompleted(data);
    });

    socket.on('scan_error', function(data) {
        handleScanError(data);
    });

    socket.on('deep_scan_update', function(data) {
        handleDeepScanUpdate(data);
    });

    socket.on('lynis_update', function(data) {
        handleLynisUpdate(data);
    });

    socket.on('manual_attack_update', function(data) {
        handleManualAttackUpdate(data);
    });

    socket.on('connect_error', function(error) {
        reconnectAttempts++;
        console.error('Connection error:', error);
        if (reconnectAttempts === RECONNECT_WARNING_THRESHOLD) {
            addConsoleMessage('Reconnecting to server… still attempting to reach backend', 'warning');
        } else if (reconnectAttempts > RECONNECT_WARNING_THRESHOLD && reconnectAttempts % RECONNECT_WARNING_THRESHOLD === 0) {
            addConsoleMessage(`Still reconnecting (attempt ${reconnectAttempts}). Will keep trying until successful.`, 'warning');
        }
    });
}

function updateConnectionStatus(connected) {
    const statusEl = document.getElementById('connection-status');
    if (statusEl) {
        if (connected) {
            statusEl.innerHTML = `
                <span class="w-2 h-2 bg-green-500 rounded-full pulse-glow"></span>
                <span class="text-xs text-gray-400">Connected</span>
            `;
        } else {
            statusEl.innerHTML = `
                <span class="w-2 h-2 bg-red-500 rounded-full"></span>
                <span class="text-xs text-gray-400">Disconnected</span>
            `;
        }
    }
}

function setupEventListeners() {
    document.querySelectorAll('[data-tab]').forEach(button => {
        button.addEventListener('click', function() {
            const tabName = this.getAttribute('data-tab');
            showTab(tabName);
        });
    });

    document.addEventListener('click', function(e) {
        if (e.target.classList.contains('refresh-btn')) {
            refreshCurrentTab();
        }
    });

    const clearBtn = document.getElementById('clear-console');
    if (clearBtn) {
        clearBtn.addEventListener('click', clearConsole);
    }

    const customScanBtn = document.getElementById('custom-deep-scan-btn');
    if (customScanBtn) {
        customScanBtn.addEventListener('click', handleCustomDeepScanRequest);
    }

    const customScanInput = document.getElementById('custom-deep-scan-ip');
    if (customScanInput) {
        customScanInput.addEventListener('keydown', function(event) {
            if (event.key === 'Enter') {
                event.preventDefault();
                handleCustomDeepScanRequest();
            }
        });
    }

    const manualPortDropdown = document.getElementById('manual-port-dropdown');
    if (manualPortDropdown) {
        manualPortDropdown.addEventListener('change', () => {
            updateManualActions();
        });
    }

    const manualActionDropdown = document.getElementById('manual-action-dropdown');
    if (manualActionDropdown) {
        manualActionDropdown.addEventListener('change', () => {
            window.manualActionPreference = manualActionDropdown.value;
        });
    }

    const automationToggleBtn = document.getElementById('automation-toggle-btn');
    if (automationToggleBtn) {
        automationToggleBtn.addEventListener('click', handleAutomationToggle);
    }
}

function initializeTabs() {
    showTab('dashboard');
}

function showTab(tabName) {
    currentTab = tabName;

    if (systemMonitoringInterval && tabName !== 'system') {
        clearInterval(systemMonitoringInterval);
        systemMonitoringInterval = null;
    }
    
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.add('hidden');
    });
    
    document.querySelectorAll('.nav-btn, [data-tab]').forEach(btn => {
        btn.classList.remove('bg-Ragnar-600');
        btn.classList.add('text-gray-300', 'hover:text-white', 'hover:bg-gray-700');
    });
    
    const selectedTab = document.getElementById(`${tabName}-tab`);
    if (selectedTab) {
        selectedTab.classList.remove('hidden');
    }
    
    const selectedBtn = document.querySelector(`[data-tab="${tabName}"]`);
    if (selectedBtn) {
        selectedBtn.classList.add('bg-Ragnar-600');
        selectedBtn.classList.remove('text-gray-300', 'hover:text-white', 'hover:bg-gray-700');
    }
    
    loadTabData(tabName);
    
    const mobileMenu = document.getElementById('mobile-menu');
    if (mobileMenu) {
        mobileMenu.classList.add('hidden');
    }
}

function refreshCurrentTab() {
    loadTabData(currentTab);
    addConsoleMessage(`Refreshed ${currentTab} data`, 'info');
}

function setupAutoRefresh() {

    autoRefreshIntervals.network = setInterval(() => {
        if (currentTab === 'network' && socket && socket.connected) {
            socket.emit('request_network');
        }
    }, 10000); // Every 10 seconds

    autoRefreshIntervals.connect = setInterval(() => {
        if (currentTab === 'connect') {
            refreshWifiStatus();
        }
        if (currentTab === 'pentest' && manualModeActive) {
            refreshBluetoothStatus();
        }
    }, 15000); // Every 15 seconds

    autoRefreshIntervals.discovered = setInterval(() => {
        if (currentTab === 'discovered' && socket && socket.connected) {
            socket.emit('request_credentials');
            socket.emit('request_loot');
            loadAttackLogs(); // Also refresh attack logs
            // Don't auto-refresh vulnerability intel to prevent card reset
        }
    }, 20000); // Every 20 seconds
    
    // OPTIMIZATION: Reduce console log polling frequency (was 5s, now 10s)
    // Console logs are not critical and 5s polling adds unnecessary load on Pi Zero
    autoRefreshIntervals.console = setInterval(() => {
        if (currentTab === 'dashboard') {
            loadConsoleLogs();
        }
    }, 10000); // Every 10 seconds when on dashboard (reduced from 5s)
    
    // OPTIMIZATION: Reduce dashboard refresh frequency (was 15s, now 20s)
    // Background sync runs every 15s, so 20s refresh is sufficient
    autoRefreshIntervals.dashboard = setInterval(() => {
        if (currentTab === 'dashboard') {
            loadDashboardData();
        }
    }, 20000); // Every 20 seconds when on dashboard (reduced from 15s)
    
    // Set up periodic update checking
    autoRefreshIntervals.updates = setInterval(() => {
        checkForUpdatesQuiet();
    }, 300000); // Every 5 minutes
    
    // OPTIMIZATION: Defer initial update check (was 5s, now 30s)
    // Not critical for initial dashboard load
    setTimeout(() => {
        checkForUpdatesQuiet();
    }, 30000); // Check 30 seconds after page load (deferred from 5s)

    setPwnStatusPollInterval(PWN_STATUS_POLL_INTERVAL);
}

function initializeMobileMenu() {
    const menuBtn = document.getElementById('mobile-menu-btn');
    const mobileMenu = document.getElementById('mobile-menu');
    
    if (menuBtn && mobileMenu) {
        menuBtn.addEventListener('click', () => {
            mobileMenu.classList.toggle('hidden');
        });
    }

    // Auto-collapse: switch between desktop nav and hamburger based on overflow
    const desktopNav = document.getElementById('desktop-nav');
    if (!desktopNav || !menuBtn) return;

    function updateNavMode() {
        // Temporarily show desktop nav offscreen to measure natural width
        desktopNav.style.position = 'absolute';
        desktopNav.style.visibility = 'hidden';
        desktopNav.style.whiteSpace = 'nowrap';
        desktopNav.classList.remove('hidden');
        desktopNav.classList.add('flex');

        // Sum widths of visible buttons
        let totalWidth = 0;
        const gap = 4; // gap-1 = 0.25rem = 4px
        let visibleCount = 0;
        for (const btn of desktopNav.children) {
            if (!btn.classList.contains('hidden')) {
                totalWidth += btn.scrollWidth;
                visibleCount++;
            }
        }
        totalWidth += Math.max(0, visibleCount - 1) * gap;

        // Reset temp styles
        desktopNav.style.position = '';
        desktopNav.style.visibility = '';
        desktopNav.style.whiteSpace = '';

        // Available space = parent width minus logo area
        const parent = desktopNav.parentElement;
        const logo = parent ? parent.querySelector('.flex.items-center.space-x-3') : null;
        const logoWidth = logo ? logo.offsetWidth + 24 : 200; // 24px gap
        const available = (parent ? parent.offsetWidth : window.innerWidth) - logoWidth - 48; // 48px for hamburger btn

        if (totalWidth > available) {
            // Too wide — show hamburger
            desktopNav.classList.add('hidden');
            desktopNav.classList.remove('flex');
            menuBtn.classList.remove('hidden');
        } else {
            // Fits — show desktop nav
            desktopNav.classList.remove('hidden');
            desktopNav.classList.add('flex');
            menuBtn.classList.add('hidden');
            if (mobileMenu) mobileMenu.classList.add('hidden');
        }
    }

    // Run on load, resize, and expose globally for dynamic item visibility changes
    updateNavMode();
    window.addEventListener('resize', updateNavMode);
    window._updateNavMode = updateNavMode;
}

function initializeThreatIntelFilters() {
    const buttons = document.querySelectorAll('.threat-intel-filter-btn');
    if (!buttons || buttons.length === 0) {
        return;
    }

    buttons.forEach(btn => {
        btn.addEventListener('click', () => {
            const status = btn.getAttribute('data-status');
            setThreatIntelFilter(status);
        });
    });

    // Ensure initial visual state matches default filter without reloading data
    setThreatIntelFilter(threatIntelStatusFilter, { skipReload: true });
}

// ============================================================================
// DATA LOADING
// ============================================================================

async function loadInitialData() {
    try {
        // Check auth status to show/hide logout button and wait for DB if needed
        try {
            const authStatus = await fetchAPI('/api/auth/status');
            const logoutBtn = document.getElementById('logout-btn');
            if (logoutBtn) logoutBtn.classList.toggle('hidden', !authStatus.configured);
            const mobileLogoutBtn = document.getElementById('mobile-logout-btn');
            if (mobileLogoutBtn) mobileLogoutBtn.classList.toggle('hidden', !authStatus.configured);

        } catch (e) { /* ignore - auth check is non-critical */ }

        // OPTIMIZATION: Use combined /api/dashboard/quick endpoint for fast loading
        // This eliminates multiple API calls and reduces load time from 5-10s to <2s on Pi Zero

        // Load critical dashboard data using optimized combined endpoint
        const quickData = await fetchAPI('/api/dashboard/quick');
        if (quickData) {
            // Update both stats and status from single response
            updateDashboardStats(quickData);
            updateDashboardStatus(quickData);
        }
        
        // OPTIMIZATION: Defer WiFi + LAN status to after dashboard is visible
        setTimeout(() => {
            refreshWifiStatus().catch(err => console.warn('WiFi status load failed:', err));
            refreshEthernetStatus().catch(err => console.warn('LAN status load failed:', err));
        }, 200);
        
        // OPTIMIZATION: Defer console logs to much later (lowest priority)
        setTimeout(() => {
            loadConsoleLogs().then(() => {
                addConsoleMessage('Ragnar Modern Web Interface Initialized', 'success');
                addConsoleMessage('Dashboard loaded successfully', 'info');
            }).catch(err => {
                console.warn('Console logs load failed:', err);
                addConsoleMessage('Error loading console logs', 'warning');
            });
        }, 1000);
        
        // OPTIMIZATION: Completely defer tab preloading until user interacts or 10s passes
        // This prevents overwhelming the Pi Zero during initial page load
        let preloadTriggered = false;
        
        // Trigger preload on first user interaction (hover, click, scroll)
        const triggerPreload = () => {
            if (!preloadTriggered) {
                preloadTriggered = true;
                console.log('User interaction detected - starting background tab preload');
                setTimeout(() => preloadAllTabs(), 100);
            }
        };
        
        // Listen for user interactions
        document.addEventListener('mousemove', triggerPreload, { once: true });
        document.addEventListener('click', triggerPreload, { once: true });
        document.addEventListener('scroll', triggerPreload, { once: true });
        document.addEventListener('touchstart', triggerPreload, { once: true });
        
        // Fallback: preload after 10 seconds if no user interaction
        setTimeout(() => {
            if (!preloadTriggered) {
                preloadTriggered = true;
                console.log('Auto-starting background tab preload after timeout');
                preloadAllTabs();
            }
        }, 10000);
        
    } catch (error) {
        console.error('Error loading initial data:', error);
        addConsoleMessage('Error loading critical dashboard data', 'error');
    }
}

// OPTIMIZATION: Lazy preload tabs only when needed, with longer delays to reduce Pi Zero load
async function preloadAllTabs() {
    console.log('Starting background preload of all tabs...');
    
    try {
        // Preload in batches with longer delays to avoid overwhelming Pi Zero
        
        // Batch 1: Network tab (most frequently accessed after dashboard)
        await loadNetworkData().catch(err => console.warn('Network preload failed:', err));
        preloadedTabs.add('network');
        
        // Longer delay between batches (500ms instead of 200ms)
        await new Promise(resolve => setTimeout(resolve, 500));
        
        // Batch 2: Discovered tab (credentials, loot, attacks, vulnerabilities)
        await Promise.all([
            loadCredentialsData().catch(err => console.warn('Credentials preload failed:', err)),
            loadLootData().catch(err => console.warn('Loot preload failed:', err)),
            loadAttackLogs().catch(err => console.warn('Attack logs preload failed:', err)),
            loadVulnerabilityIntel().catch(err => console.warn('Vulnerability intel preload failed:', err))
        ]);
        preloadedTabs.add('discovered');
        
        await new Promise(resolve => setTimeout(resolve, 500));
        
        // Batch 3: Threat Intel tab
        await loadThreatIntelData().catch(err => console.warn('Threat intel preload failed:', err));
        preloadedTabs.add('threat-intel');
        
        await new Promise(resolve => setTimeout(resolve, 500));
        
        // Batch 4: Connect tab
        await loadConnectData().catch(err => console.warn('Connect preload failed:', err));
        preloadedTabs.add('connect');
        
        await new Promise(resolve => setTimeout(resolve, 500));
        
        // Batch 5: E-Paper tab
        await loadEpaperDisplay().catch(err => console.warn('E-Paper preload failed:', err));
        preloadedTabs.add('epaper');
        
        await new Promise(resolve => setTimeout(resolve, 500));
        
        // Batch 6: Files and Config (lower priority)
        await Promise.all([
            loadFilesData().catch(err => console.warn('Files preload failed:', err)),
            loadConfigData().catch(err => console.warn('Config preload failed:', err))
        ]);
        preloadedTabs.add('files');
        preloadedTabs.add('config');
        
        // Batch 7: Traffic Analysis and Advanced Vulnerability scanning (server mode only)
        if (serverModeEnabled) {
            await new Promise(resolve => setTimeout(resolve, 500));
            await Promise.all([
                loadTrafficAnalysisData().catch(err => console.warn('Traffic preload failed:', err)),
                loadAdvancedVulnData().catch(err => console.warn('Adv vuln preload failed:', err))
            ]);
            preloadedTabs.add('traffic');
            preloadedTabs.add('adv-vuln');
        }

        // System and NetKB tabs load on-demand (they use different patterns)

        console.log('Background tab preload completed');
        addConsoleMessage('All tabs preloaded and ready', 'success');
        
    } catch (error) {
        console.error('Error during tab preloading:', error);
    }
}

async function loadTabData(tabName) {
    // If tab was already preloaded, skip reloading unless it's a dynamic tab
    // System and netkb always load (they use polling/intervals)
    // Network and threat-intel always refresh for up-to-date data
    const alreadyPreloaded = preloadedTabs.has(tabName);
    
    switch(tabName) {
        case 'dashboard':
            // Load dashboard stats immediately, defer console logs
            await loadDashboardData();
            setTimeout(() => loadConsoleLogs(), 50);
            break;
        case 'network':
            // Always refresh network data when switching to this tab
            await loadNetworkData();
            break;
        case 'networks':
            if (!alreadyPreloaded) {
                await loadAllNetworksData();
            }
            break;
        case 'connect':
            if (!alreadyPreloaded) {
                await loadConnectData();
            } else {
                await refreshWifiStatus().catch(err => console.warn('WiFi refresh failed:', err));
                await refreshEthernetStatus().catch(err => console.warn('LAN refresh failed:', err));
                await refreshBluetoothStatus().catch(err => console.warn('Bluetooth refresh failed:', err));
            }
            break;
        case 'pentest':
            if (manualModeActive) {
                await loadPentestData();
                checkAirSnitchInstalled();
                populateAirSnitchInterfaceDropdowns();
                refreshAirSnitchResults();
            } else {
                addConsoleMessage('Enable Pentest Mode to access the Pentest tab', 'warning');
                showTab('dashboard');
            }
            break;
        case 'discovered':
            if (!alreadyPreloaded) {
                await Promise.all([
                    loadCredentialsData(),
                    loadLootData(),
                    loadAttackLogs(),
                    loadVulnerabilityIntel()
                ]);
            }
            await refreshPwnagotchiStatus({ silent: true });
            break;
        case 'threat-intel':
            // Always refresh threat intel data when switching to this tab
            await loadThreatIntelData();
            break;
        case 'files':
            if (!alreadyPreloaded) {
                await loadFilesData();
                // Images are not auto-loaded to save processing power
                // User must click "Load Images" button to load them
            }
            break;
        case 'system':
            // Always load system (uses intervals)
            loadSystemData();
            break;
        case 'netkb':
            // Always load netkb
            loadNetkbData();
            break;
        case 'epaper':
            if (!alreadyPreloaded) {
                await loadEpaperDisplay();
            }
            break;
        case 'config':
            if (!alreadyPreloaded) {
                await loadConfigData();
            } else {
                await refreshPwnagotchiStatus({ silent: true });
            }
            break;
        case 'traffic':
            loadTrafficAnalysisData(); // Non-blocking - tab shows immediately, data fills in
            break;
        case 'adv-vuln':
            loadAdvancedVulnData(); // Non-blocking - tab shows immediately, data fills in
            break;
        case 'network-map':
            if (!_mapInitialized) { loadNetworkMap(); }
            break;
        case 'credentials':
            loadCredentials();
            break;
    }
}

async function loadDashboardData() {
    try {
        // OPTIMIZATION: Show loading state with pulse animation
        const statsElements = [
            'target-count', 'target-total-count', 'target-inactive-count',
            'port-count', 'vuln-count', 'cred-count', 'level-count', 'scanned-network-count', 'points-count'
        ];
        
        // Add subtle pulse animation to show loading
        statsElements.forEach(id => {
            const el = document.getElementById(id);
            if (el) el.classList.add('animate-pulse');
        });
        
        // OPTIMIZATION: Use combined quick endpoint for faster loading
        const data = await fetchAPI('/api/dashboard/quick');
        
        // Remove pulse animation
        statsElements.forEach(id => {
            const el = document.getElementById(id);
            if (el) el.classList.remove('animate-pulse');
        });
        
        if (data) {
            // Update status block immediately
            updateDashboardStatus(data);
            // Only fetch network-specific stats if a specific network is selected;
            // otherwise /api/dashboard/quick already has the correct data (instant).
            const { network } = getSelectedDashboardNetworkKey();
            if (network) {
                await refreshDashboardStatsForCurrentSelection({ forceRefresh: true, fallbackData: data });
            } else {
                updateDashboardStats(data);
            }
        }
        
        // Load AI insights if configured
        await loadAIInsights();
    } catch (error) {
        console.error('Error loading dashboard data:', error);
        // Remove pulse animation on error too
        const statsElements = [
            'target-count', 'target-total-count', 'target-inactive-count',
            'port-count', 'vuln-count', 'cred-count', 'level-count', 'scanned-network-count', 'points-count'
        ];
        statsElements.forEach(id => {
            const el = document.getElementById(id);
            if (el) el.classList.remove('animate-pulse');
        });
    }
}

function toNumber(value, fallback = 0) {
    const numeric = Number(value);
    return Number.isFinite(numeric) ? numeric : fallback;
}

function formatRelativeTime(seconds) {
    if (!Number.isFinite(seconds)) {
        return null;
    }

    let remaining = Math.max(0, Math.floor(seconds));
    const units = [
        { label: 'd', value: 86400 },
        { label: 'h', value: 3600 },
        { label: 'm', value: 60 },
        { label: 's', value: 1 }
    ];

    const parts = [];
    for (const unit of units) {
        if (remaining >= unit.value || (unit.label === 's' && parts.length === 0)) {
            const amount = Math.floor(remaining / unit.value);
            if (amount > 0 || unit.label === 's') {
                parts.push(`${amount}${unit.label}`);
            }
            remaining -= amount * unit.value;
        }
        if (parts.length >= 2) {
            break;
        }
    }

    return parts.length > 0 ? parts.join(' ') : '0s';
}

function buildLastSyncDisplay(stats) {
    if (!stats) {
        return 'Sync pending…';
    }

    const ageSeconds = toNumber(stats.last_sync_age_seconds, NaN);
    const hasAge = Number.isFinite(ageSeconds);
    const relative = hasAge ? `${formatRelativeTime(ageSeconds)} ago` : '';

    let timestampSource = stats.last_sync_iso ?? stats.last_sync_time ?? stats.last_sync_timestamp;
    let isoValue = null;

    if (typeof timestampSource === 'number') {
        isoValue = new Date(timestampSource * 1000).toISOString();
    } else if (typeof timestampSource === 'string' && timestampSource) {
        isoValue = timestampSource;
    }

    let absolute = '';
    if (isoValue) {
        const parsed = new Date(isoValue);
        if (!Number.isNaN(parsed.getTime())) {
            absolute = parsed.toLocaleString();
        }
    }

    if (relative && absolute) {
        return `${relative} (${absolute})`;
    }

    if (relative) {
        return relative;
    }

    if (absolute) {
        return absolute;
    }

    return 'Sync pending…';
}

function updateDashboardStats(stats) {
    if (!stats || typeof stats !== 'object') {
        return;
    }

    const activeTargets = toNumber(stats.active_target_count ?? stats.target_count, 0);
    const inactiveTargets = toNumber(stats.inactive_target_count ?? stats.offline_target_count, 0);
    const totalTargets = toNumber(stats.total_target_count ?? activeTargets + inactiveTargets, activeTargets + inactiveTargets);

    const newTargetList = Array.isArray(stats.new_target_ips) ? stats.new_target_ips :
        (Array.isArray(stats.new_targets) ? stats.new_targets : []);
    const lostTargetList = Array.isArray(stats.lost_target_ips) ? stats.lost_target_ips :
        (Array.isArray(stats.lost_targets) ? stats.lost_targets : []);

    const newTargets = toNumber(stats.new_target_count ?? stats.new_targets ?? newTargetList.length, newTargetList.length);
    const lostTargets = toNumber(stats.lost_target_count ?? stats.lost_targets ?? lostTargetList.length, lostTargetList.length);

    const portCount = toNumber(stats.port_count ?? stats.open_port_count, 0);
    const vulnCount = toNumber(stats.vulnerability_count ?? stats.vuln_count, 0);
    const vulnerableHostsCount = toNumber(stats.vulnerable_hosts_count ?? stats.vulnerable_host_count ?? 0, 0);
    const credCount = toNumber(stats.credential_count ?? stats.cred_count, 0);
    const level = toNumber(stats.level ?? stats.levelnbr, 0);
    const points = toNumber(stats.points ?? stats.coins, 0);
    const scannedNetworks = Math.max(0, toNumber(stats.scanned_network_count ?? stats.networks_scanned, 0));

    updateElement('target-count', activeTargets);
    scaleStatNumber('target-count', activeTargets);
    updateElement('target-total-count', totalTargets);
    updateElement('target-inactive-count', inactiveTargets);
    updateElement('target-new-count', newTargets);
    updateElement('target-lost-count', lostTargets);

    const newCountElement = document.getElementById('target-new-count');
    if (newCountElement) {
        newCountElement.title = newTargetList.length > 0 ? newTargetList.join(', ') : 'No recent additions';
    }

    const lostCountElement = document.getElementById('target-lost-count');
    if (lostCountElement) {
        lostCountElement.title = lostTargetList.length > 0 ? lostTargetList.join(', ') : 'No recent drops';
    }

    updateElement('port-count', portCount);
    scaleStatNumber('port-count', portCount);
    updateElement('vuln-count', vulnCount);
    scaleStatNumber('vuln-count', vulnCount);
    updateElement('dashboard-vulnerable-hosts-count', vulnerableHostsCount);
    updateElement('cred-count', credCount);
    scaleStatNumber('cred-count', credCount);
    updateElement('level-count', level);
    scaleStatNumber('level-count', level);
    updateElement('scanned-network-count', scannedNetworks);
    scaleStatNumber('scanned-network-count', scannedNetworks);
    updateElement('dashboard-scanned-network-count', scannedNetworks);
    scaleStatNumber('dashboard-scanned-network-count', scannedNetworks);
    updateElement('points-count', points);

    const activeSummary = totalTargets > 0 ? `${activeTargets}/${totalTargets} active` : `${activeTargets} active`;
    const newSummary = newTargets > 0 ? `${newTargets} new` : 'No new targets';
    const lostSummary = lostTargets > 0 ? `${lostTargets} lost` : 'No targets lost';

    updateElement('active-target-summary', activeSummary);
    updateElement('new-target-summary', newSummary);
    updateElement('lost-target-summary', lostSummary);
    updateElement('last-sync-display', buildLastSyncDisplay(stats));
}

async function loadNetworkData() {
    try {
        // Use the new stable network data endpoint
        await loadStableNetworkData();
        
        // Update the status detection info banner with current config
        updateNetworkStatusBanner();
    } catch (error) {
        console.error('Error loading network data:', error);
        addConsoleMessage('Failed to load network data', 'error');
    }
}

async function loadNetworkData() {
    try {
        // Use the new stable network data endpoint
        await loadStableNetworkData();
        
        // Update the status detection info banner with current config
        updateNetworkStatusBanner();
    } catch (error) {
        console.error('Error loading network data:', error);
        addConsoleMessage('Failed to load network data', 'error');
    }
}

// ============================================================================
// ALL SCANNED NETWORKS TAB (PR 3)
// ============================================================================

async function loadAllNetworksData() {
    const container = document.getElementById('networks-list-container');
    if (!container) return;

    container.innerHTML = `
        <div class="text-center text-gray-400 py-12">
            <svg class="w-8 h-8 inline animate-spin mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
            </svg>
            <p>Loading AP Archive…</p>
        </div>`;

    try {
        const data = await fetchAPI('/api/networks/all');
        displayAllNetworks(data);
        preloadedTabs.add('networks');
    } catch (error) {
        console.error('Error loading all networks:', error);
        container.innerHTML = `
            <div class="text-center text-red-400 py-12">
                <p class="text-sm">Failed to load AP Archive: ${escapeHtml(error.message)}</p>
            </div>`;
    }
}

function displayAllNetworks(data) {
    const container = document.getElementById('networks-list-container');
    if (!container) return;

    const networks = data.networks || [];

    if (networks.length === 0) {
        container.innerHTML = `
            <div class="text-center text-gray-400 py-16">
                <svg class="w-16 h-16 mx-auto mb-4 opacity-30" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071c3.904-3.905 10.236-3.905 14.14 0M1.394 9.393c5.857-5.857 15.355-5.857 21.213 0"></path>
                </svg>
                <p class="text-lg font-medium">No access points recorded yet</p>
                <p class="text-sm text-gray-500 mt-2">Networks will appear here after Ragnar connects and scans them.</p>
            </div>`;
        return;
    }

    let html = `<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">`;

    networks.forEach(net => {
        const ssid = escapeHtml(net.ssid || net.slug);
        const lastSeen = escapeHtml(net.last_seen || 'Unknown');
        const fileCount = net.file_count || 0;

        const badges = [];
        if (net.has_loot)  badges.push('<span class="px-2 py-0.5 rounded text-xs bg-yellow-500 bg-opacity-20 text-yellow-300">Loot</span>');
        if (net.has_creds) badges.push('<span class="px-2 py-0.5 rounded text-xs bg-green-500 bg-opacity-20 text-green-300">Creds</span>');
        if (net.has_vulns) badges.push('<span class="px-2 py-0.5 rounded text-xs bg-red-500 bg-opacity-20 text-red-300">Vulns</span>');
        if (net.has_scans) badges.push('<span class="px-2 py-0.5 rounded text-xs bg-blue-500 bg-opacity-20 text-blue-300">Scans</span>');

        html += `
            <button type="button"
                    onclick="openNetworkFilePanel(${JSON.stringify(net.slug).replace(/"/g, '&quot;')}, ${JSON.stringify(net.ssid || net.slug).replace(/"/g, '&quot;')})"
                    class="text-left bg-gray-800 hover:bg-gray-700 rounded-xl p-5 transition-colors border border-gray-700 hover:border-Ragnar-500 focus:outline-none focus:ring-2 focus:ring-Ragnar-500">
                <div class="flex items-start justify-between mb-3">
                    <div class="flex items-center gap-2 min-w-0">
                        <svg class="w-5 h-5 text-cyan-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071c3.904-3.905 10.236-3.905 14.14 0M1.394 9.393c5.857-5.857 15.355-5.857 21.213 0"></path>
                        </svg>
                        <span class="font-semibold text-white truncate" title="${ssid}">${ssid}</span>
                    </div>
                    <svg class="w-4 h-4 text-gray-500 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
                    </svg>
                </div>
                <div class="text-xs text-gray-400 mb-3">
                    <span>${fileCount} file${fileCount !== 1 ? 's' : ''}</span>
                    ${lastSeen ? `<span class="mx-1">·</span><span>${lastSeen}</span>` : ''}
                </div>
                <div class="flex flex-wrap gap-1.5">
                    ${badges.length ? badges.join('') : '<span class="text-xs text-gray-600">No data yet</span>'}
                </div>
            </button>`;
    });

    html += '</div>';
    container.innerHTML = html;
}

async function openNetworkFilePanel(slug, ssid) {
    const panel = document.getElementById('networks-file-panel');
    const listContainer = document.getElementById('networks-list-container');
    const title = document.getElementById('networks-file-panel-title');
    const fileContainer = document.getElementById('networks-file-list-container');

    if (!panel || !title || !fileContainer) return;

    title.textContent = ssid;
    listContainer.classList.add('hidden');
    panel.classList.remove('hidden');

    fileContainer.innerHTML = `
        <div class="text-center text-gray-400 py-8">
            <svg class="w-6 h-6 inline animate-spin mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
            </svg>
            <p>Loading files…</p>
        </div>`;

    try {
        const data = await fetchAPI(`/api/networks/${encodeURIComponent(slug)}/files`);
        displayNetworkFiles(data);
    } catch (error) {
        fileContainer.innerHTML = `
            <div class="text-center text-red-400 py-8">
                <p class="text-sm">Failed to load files: ${escapeHtml(error.message)}</p>
            </div>`;
    }
}

function closeNetworkFilePanel() {
    const panel = document.getElementById('networks-file-panel');
    const listContainer = document.getElementById('networks-list-container');
    if (panel) panel.classList.add('hidden');
    if (listContainer) listContainer.classList.remove('hidden');
}

const NETWORK_FILE_CATEGORY_LABELS = {
    data_stolen:    { label: 'Loot',             color: 'text-yellow-300' },
    credentials:    { label: 'Credentials',      color: 'text-green-300'  },
    vulnerabilities:{ label: 'Vulnerabilities',  color: 'text-red-300'    },
    scan_results:   { label: 'Scan Results',     color: 'text-blue-300'   },
};

function displayNetworkFiles(data) {
    const container = document.getElementById('networks-file-list-container');
    if (!container) return;

    const files = data.files || [];

    if (files.length === 0) {
        container.innerHTML = `
            <div class="text-center text-gray-400 py-12">
                <svg class="w-12 h-12 mx-auto mb-3 opacity-30" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 13h6m-3-3v6m-9 1V7a2 2 0 012-2h6l2 2h4a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2z"></path>
                </svg>
                <p>No files collected for this network yet.</p>
            </div>`;
        return;
    }

    // Group by category
    const grouped = {};
    files.forEach(f => {
        if (!grouped[f.category]) grouped[f.category] = [];
        grouped[f.category].push(f);
    });

    let html = '';
    const categoryOrder = ['data_stolen', 'credentials', 'vulnerabilities', 'scan_results'];

    categoryOrder.forEach(cat => {
        if (!grouped[cat] || grouped[cat].length === 0) return;
        const meta = NETWORK_FILE_CATEGORY_LABELS[cat] || { label: cat, color: 'text-gray-300' };

        html += `
            <div class="mb-6">
                <h4 class="text-sm font-semibold uppercase tracking-wider ${meta.color} mb-3">${meta.label} (${grouped[cat].length})</h4>
                <div class="space-y-2">`;

        grouped[cat].forEach(file => {
            const fname = escapeHtml(file.filename);
            const size  = escapeHtml(file.size || '');
            const mod   = escapeHtml(file.modified || '');
            const vpath = file.virtual_path ? encodeURIComponent(file.virtual_path) : '';
            const clickable = !!vpath;

            html += `
                <div class="flex items-center justify-between bg-gray-800 rounded-lg px-4 py-3 ${clickable ? 'hover:bg-gray-700 cursor-pointer' : ''} transition-colors"
                     ${clickable ? `onclick="openLootFile('${escapeAttr(vpath)}')"` : ''}>
                    <div class="flex items-center gap-3 min-w-0">
                        <svg class="w-4 h-4 text-gray-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                        </svg>
                        <span class="text-sm text-white truncate" title="${fname}">${fname}</span>
                    </div>
                    <div class="flex items-center gap-4 text-xs text-gray-400 flex-shrink-0 ml-4">
                        ${size ? `<span>${size}</span>` : ''}
                        ${mod  ? `<span class="hidden sm:inline">${mod}</span>` : ''}
                        ${clickable ? `<svg class="w-4 h-4 text-Ragnar-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path></svg>` : ''}
                    </div>
                </div>`;
        });

        html += `</div></div>`;
    });

    container.innerHTML = html;
}


async function updateNetworkStatusBanner() {
    try {
        const configResponse = await fetchAPI('/api/config');
        if (configResponse && configResponse.success) {
            const maxFailedPings = configResponse.config.network_max_failed_pings || 15;
            const offlineMinutes = Math.round((maxFailedPings * 60) / 60); // 60 second ARP scans
            
            const failedPingsEl = document.getElementById('network-status-failed-pings');
            const offlineTimeEl = document.getElementById('network-status-offline-time');
            
            if (failedPingsEl) {
                failedPingsEl.textContent = maxFailedPings;
            }
            if (offlineTimeEl) {
                offlineTimeEl.textContent = `${offlineMinutes} minutes`;
            }
        }
    } catch (error) {
        console.debug('Could not update network status banner:', error);
    }
}

// ============================================================================
// STABLE NETWORK DATA FUNCTIONS
// ============================================================================

async function loadStableNetworkData() {
    try {
        const { network } = getSelectedDashboardNetworkKey() || {};
        const query = network ? `/api/network/stable?network=${encodeURIComponent(network)}` : '/api/network/stable';
        const data = await fetchAPI(query);
        
        if (data.success) {
            displayStableNetworkTable(data);
            addConsoleMessage(`Network data loaded: ${data.count} hosts`, 'info');
        } else {
            addConsoleMessage(`Failed to load network data: ${data.error}`, 'error');
        }
    } catch (error) {
        console.error('Error loading stable network data:', error);
        addConsoleMessage(`Network data error: ${error.message}`, 'error');
    }
}

function displayStableNetworkTable(data) {
    const tableBody = document.getElementById('network-hosts-table');
    const hostCountSpan = document.getElementById('host-count');
    
    if (!tableBody) return;
    
    // Save all existing deep scan button states before clearing table
    const existingRows = tableBody.querySelectorAll('tr[data-ip]');
    existingRows.forEach(row => {
        const ip = row.getAttribute('data-ip');
        if (ip) {
            saveDeepScanButtonState(ip);
        }
    });
    
    tableBody.innerHTML = '';
    
    if (!data.hosts || data.hosts.length === 0) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="8" class="text-center py-8 text-gray-400">
                    No hosts discovered yet. Network scanning is running in the background.
                </td>
            </tr>
        `;
        if (hostCountSpan) hostCountSpan.textContent = '0 hosts';
        return;
    }
    
    // Use DocumentFragment for better performance
    const fragment = document.createDocumentFragment();
    
    data.hosts.forEach((host, index) => {
        // DEBUG: Log first few host objects to see structure
        if (index < 5) {
            console.log(`🔍 Host ${index}:`, host);
            console.log(`   IP field:`, host.ip, typeof host.ip);
            console.log(`   All fields:`, Object.keys(host));
        }
        
        const row = document.createElement('tr');
        row.className = 'border-b border-slate-700 hover:bg-slate-700/50 transition-colors';
        
        // Status indicator
        const statusIcon = host.status === 'up' ? 
            '<span class="flex items-center"><div class="w-2 h-2 bg-green-500 rounded-full mr-2"></div>Online</span>' :
            '<span class="flex items-center"><div class="w-2 h-2 bg-gray-500 rounded-full mr-2"></div>Unknown</span>';
        
        // Format MAC address
        let macDisplay = host.mac === 'Unknown' ? 
            '<span class="text-gray-500">Unknown</span>' : 
            `<span class="font-mono text-xs">${host.mac}</span>`;
        
        // Format ports
        let portsDisplay = host.ports === 'Unknown' || host.ports === 'Scanning...' ? 
            '<span class="text-gray-500">Unknown</span>' : 
            `<span class="text-xs">${host.ports}</span>`;
        
        // Format vulnerabilities
        let vulnDisplay = host.vulnerabilities === '0' ? 
            '<span class="text-gray-500">None</span>' : 
            `<span class="text-orange-400">${host.vulnerabilities}</span>`;
        
        // Format last scan
        let lastScanDisplay = host.last_scan === 'Never' || host.last_scan === 'Unknown' ? 
            '<span class="text-gray-500">Never</span>' : 
            `<span class="text-xs">${formatTimeAgo(host.last_scan)}</span>`;
        
        row.innerHTML = `
            <td class="py-3 px-4">${statusIcon}</td>
            <td class="py-3 px-4 font-mono text-sm">${host.ip}</td>
            <td class="py-3 px-4">${host.hostname === 'Unknown' ? '<span class="text-gray-500">Unknown</span>' : host.hostname}</td>
            <td class="py-3 px-4">${macDisplay}</td>
            <td class="py-3 px-4">${portsDisplay}</td>
            <td class="py-3 px-4">${vulnDisplay}</td>
            <td class="py-3 px-4">${lastScanDisplay}</td>
            <td class="py-3 px-4">
                <button onclick="triggerDeepScan('${host.ip}', { mode: 'full' })" 
                        id="deep-scan-btn-${host.ip.replace(/\./g, '-')}"
                        data-scan-status="idle"
                        class="deep-scan-button bg-purple-600 hover:bg-purple-700 text-white text-xs px-3 py-1 rounded transition-all duration-300"
                        title="Scan all 65535 ports with TCP connect (-sT). IP: ${host.ip}">
                    Deep Scan
                </button>
            </td>
        `;
        
        // Set data-ip attribute for state management
        row.setAttribute('data-ip', host.ip);
        
        fragment.appendChild(row);
        
        // Restore deep scan button state after adding to fragment
        // (will be applied after fragment is appended to DOM)
    });
    
    // Append all rows at once for better performance
    tableBody.appendChild(fragment);
    
    // Now restore button states after DOM is updated
    data.hosts.forEach(host => {
        restoreDeepScanButtonState(host.ip);
    });
    
    // Update host count
    if (hostCountSpan) {
        hostCountSpan.textContent = `${data.hosts.length} hosts`;
    }
    
    // Cleanup old button states for removed hosts
    cleanupOldDeepScanStates();
}

function formatTimeAgo(timeString) {
    try {
        if (!timeString || timeString === 'Never' || timeString === 'Unknown') {
            return 'Never';
        }
        
        // If it's already a relative time string, return as is
        if (timeString.includes('ago') || timeString.includes('Recently')) {
            return timeString;
        }
        
        const date = new Date(timeString);
        if (isNaN(date.getTime())) {
            return timeString; // Return original if can't parse
        }
        
        const now = new Date();
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / (1000 * 60));
        const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
        const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
        
        if (diffMins < 1) return 'Just now';
        if (diffMins < 60) return `${diffMins}m ago`;
        if (diffHours < 24) return `${diffHours}h ago`;
        if (diffDays < 7) return `${diffDays}d ago`;
        
        return date.toLocaleDateString();
    } catch (error) {
        return timeString;
    }
}

// Real-time scanning variables
let currentScanState = {
    isScanning: false,
    totalHosts: 0,
    scannedHosts: 0,
    currentTarget: '',
    startTime: null
};

// Deep scan button state management
let deepScanButtonStates = new Map(); // Map<IP, {status, text, classes, disabled}>

function saveDeepScanButtonState(ip) {
    const buttonId = `deep-scan-btn-${ip.replace(/\./g, '-')}`;
    const button = document.getElementById(buttonId);
    
    if (button) {
        const state = {
            status: button.dataset.scanStatus || 'idle',
            text: button.textContent,
            classes: button.className,
            disabled: button.disabled,
            title: button.title
        };
        deepScanButtonStates.set(ip, state);
        console.log(`💾 Saved deep scan button state for ${ip}:`, state);
    }
}

function restoreDeepScanButtonState(ip) {
    const buttonId = `deep-scan-btn-${ip.replace(/\./g, '-')}`;
    const button = document.getElementById(buttonId);
    const state = deepScanButtonStates.get(ip);
    
    if (button && state) {
        button.textContent = state.text;
        button.className = state.classes;
        button.disabled = state.disabled;
        button.title = state.title;
        button.dataset.scanStatus = state.status;
        console.log(`🔄 Restored deep scan button state for ${ip}:`, state);
    } else if (button && !state) {
        console.log(`⚠️ No saved state found for ${ip}, keeping default button state`);
    }
}

function clearDeepScanButtonState(ip) {
    if (deepScanButtonStates.has(ip)) {
        deepScanButtonStates.delete(ip);
        console.log(`🗑️ Cleared deep scan button state for ${ip}`);
    }
}

function cleanupOldDeepScanStates() {
    // Remove states for IPs that no longer have buttons in the DOM
    let cleanedCount = 0;
    for (const [ip] of deepScanButtonStates) {
        const buttonId = `deep-scan-btn-${ip.replace(/\./g, '-')}`;
        if (!document.getElementById(buttonId)) {
            deepScanButtonStates.delete(ip);
            cleanedCount++;
        }
    }
    if (cleanedCount > 0) {
        console.log(`🧹 Cleaned up ${cleanedCount} old deep scan button states`);
    }
}

// Real-time scanning control functions
async function startRealtimeScan() {
    const startBtn = document.getElementById('start-network-scan');
    const stopBtn = document.getElementById('stop-network-scan');
    
    try {
        startBtn.disabled = true;
        startBtn.innerHTML = '⏳ Starting...';
        
        const response = await networkAwareFetch('/api/scan/start-realtime', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            }
        });
        
        if (response.ok) {
            currentScanState.isScanning = true;
            currentScanState.startTime = new Date();
            stopBtn.disabled = false;
            startBtn.innerHTML = '⏳ Scanning...';
            
            // Show progress section
            document.getElementById('scan-progress').classList.remove('hidden');
            
            addConsoleMessage('Real-time network scan started', 'info');
        } else {
            throw new Error('Failed to start scan');
        }
    } catch (error) {
        console.error('Error starting scan:', error);
        addConsoleMessage('Failed to start network scan: ' + error.message, 'error');
        resetScanButtons();
    }
}

async function stopRealtimeScan() {
    const stopBtn = document.getElementById('stop-network-scan');
    
    try {
        stopBtn.disabled = true;
        stopBtn.innerHTML = '⏳ Stopping...';
        
        // Emit stop scan event via WebSocket
        socket.emit('stop_scan');
        
        addConsoleMessage('Stopping network scan...', 'info');
    } catch (error) {
        console.error('Error stopping scan:', error);
        addConsoleMessage('Failed to stop network scan: ' + error.message, 'error');
        stopBtn.disabled = false;
        stopBtn.innerHTML = '⏹️ Stop Scan';
    }
}

function resetScanButtons() {
    const startBtn = document.getElementById('start-network-scan');
    const stopBtn = document.getElementById('stop-network-scan');
    
    startBtn.disabled = false;
    startBtn.innerHTML = '<span class="group-disabled:hidden">🔍</span> Start Full Scan';
    stopBtn.disabled = true;
    stopBtn.innerHTML = '⏹️ Stop Scan';
    
    currentScanState.isScanning = false;
    document.getElementById('scan-progress').classList.add('hidden');
}

// WebSocket event handlers for real-time scanning
function handleScanStarted(data) {
    currentScanState.totalHosts = data.total_hosts || 0;
    currentScanState.scannedHosts = 0;
    
    updateScanProgress();
    addConsoleMessage(`Started scanning ${currentScanState.totalHosts} hosts`, 'info');
}

function handleScanProgress(data) {
    currentScanState.scannedHosts = data.completed || 0;
    currentScanState.currentTarget = data.current_target || '';
    
    updateScanProgress();
}

function handleScanHostUpdate(data) {
    if (!data) {
        return;
    }

    const eventType = data.type || data.event || 'host_update';

    if (eventType === 'sep_scan_output') {
        if (data.message) {
            const prefix = data.ip ? `[sep-scan ${data.ip}]` : '[sep-scan]';
            addConsoleMessage(`${prefix} ${data.message}`, 'info');
        }
        return;
    }

    if (eventType === 'sep_scan_error') {
        const prefix = data.ip ? `sep-scan error for ${data.ip}` : 'sep-scan error';
        addConsoleMessage(`${prefix}: ${data.message || 'Unknown error'}`, 'error');
        return;
    }

    if (eventType === 'sep_scan_completed') {
        const ipLabel = data.ip || 'target';
        const statusLabel = data.status === 'success' ? 'successfully' : 'with issues';
        const level = data.status === 'success' ? 'success' : 'warning';
        addConsoleMessage(`sep-scan completed for ${ipLabel} ${statusLabel}`, level);

        if (currentTab === 'network') {
            loadNetworkData();
        }
        return;
    }

    // Update the network table with new host data
    if (eventType === 'host_updated' || data.ip || data.IPs) {
        if (currentTab === 'network') {
            updateHostInTable(data);
        }

        // Update threat intelligence and NetKB if vulnerabilities found
        if (data.vulnerabilities && data.vulnerabilities.length > 0) {
            if (currentTab === 'threat-intel') {
                loadThreatIntelData();
            }
            if (currentTab === 'netkb') {
                loadNetkbData();
            }
        }
        return;
    }
}

function handleScanCompleted(data) {
    addConsoleMessage(`Network scan completed. Found ${data.hosts_discovered || 0} hosts, ${data.vulnerabilities_found || 0} vulnerabilities`, 'success');
    resetScanButtons();
    
    // Refresh all relevant tabs
    if (currentTab === 'network') {
        loadNetworkData();
    }
}

function handleScanError(data) {
    addConsoleMessage(`Scan error: ${data.error}`, 'error');
    resetScanButtons();
}

// ============================================================================
// DEEP SCAN FUNCTIONS
// ============================================================================

async function handleCustomDeepScanRequest() {
    const inputEl = document.getElementById('custom-deep-scan-ip');
    const statusEl = document.getElementById('custom-deep-scan-status');
    const buttonEl = document.getElementById('custom-deep-scan-btn');
    if (!inputEl || !statusEl || !buttonEl) {
        return;
    }

    const ip = inputEl.value.trim();
    if (!ip) {
        statusEl.textContent = 'Enter a target IP address before scanning.';
        addConsoleMessage('Manual deep scan aborted: no IP provided', 'warning');
        return;
    }
    if (!isValidIPv4(ip)) {
        statusEl.textContent = 'Please enter a valid IPv4 address (e.g., 192.168.1.192).';
        addConsoleMessage(`Manual deep scan aborted: invalid IPv4 (${ip})`, 'error');
        return;
    }

    const originalText = buttonEl.dataset.defaultText || buttonEl.textContent;
    buttonEl.dataset.defaultText = originalText;
    buttonEl.disabled = true;
    buttonEl.classList.add('cursor-wait', 'opacity-80');
    buttonEl.textContent = 'Starting...';

    statusEl.dataset.currentIp = ip;
    statusEl.textContent = `Launching custom scan for ${ip} (top 3000 ports)...`;

    addConsoleMessage(`Manual deep scan request queued for ${ip} (top 3000 ports)`, 'info');

    try {
        const success = await triggerDeepScan(ip, { mode: 'top3000', source: 'custom' });
        if (success) {
            statusEl.textContent = `Scan running on ${ip}. Watch the console for live updates.`;
        } else {
            statusEl.textContent = `Failed to start scan for ${ip}. See console for details.`;
            statusEl.dataset.currentIp = '';
        }
    } catch (error) {
        statusEl.textContent = `Unexpected error starting scan: ${error.message}`;
        statusEl.dataset.currentIp = '';
    } finally {
        buttonEl.disabled = false;
        buttonEl.classList.remove('cursor-wait', 'opacity-80');
        buttonEl.textContent = buttonEl.dataset.defaultText;
    }
}

// TEST FUNCTION - Direct deep scan test
function testDeepScan() {
    console.log('🧪 Testing deep scan with hardcoded IP...');
    triggerDeepScan('192.168.1.211');
}

async function triggerDeepScan(ip, options = {}) {
    try {
        // EXPLICIT DEBUG: Log what we received
        console.log('🔍 triggerDeepScan CALLED');
        console.log('   Received IP parameter:', ip);
        console.log('   IP type:', typeof ip);
        console.log('   IP length:', ip ? ip.length : 'null/undefined');
        
        if (!ip) {
            console.error('❌ IP parameter is empty in triggerDeepScan!');
            addConsoleMessage('Error: No IP address provided for deep scan', 'error');
            return;
        }

        const mode = (options.mode || 'full').toLowerCase();
        const portstart = Number.isInteger(options.portstart) ? options.portstart : undefined;
        const portend = Number.isInteger(options.portend) ? options.portend : undefined;
        const modeDescription = mode === 'top3000' ? 'top 3000 ports' : 'all 65535 ports';
        
        // Update button immediately to show scan is starting
        const buttonId = `deep-scan-btn-${ip.replace(/\./g, '-')}`;
        const button = document.getElementById(buttonId);
        if (button) {
            button.classList.remove('bg-purple-600', 'hover:bg-purple-700');
            button.classList.add('bg-blue-600', 'cursor-wait');
            button.disabled = true;
            button.textContent = 'Initiating...';
            button.dataset.scanStatus = 'initiating';
            // Save the updated state
            saveDeepScanButtonState(ip);
        }
        
        addConsoleMessage(`Starting deep scan on ${ip} (${modeDescription})...`, 'info');
        
        console.log('📤 Sending POST request to /api/scan/deep');
        const requestBody = { ip: ip };
        if (mode) {
            requestBody.mode = mode;
        }
        if (portstart !== undefined) {
            requestBody.portstart = portstart;
        }
        if (portend !== undefined) {
            requestBody.portend = portend;
        }
        console.log('   Request body:', JSON.stringify(requestBody));
        
        const response = await networkAwareFetch('/api/scan/deep', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(requestBody)
        });
        
        console.log('📥 Response received, status:', response.status);
        
        const data = await response.json();
        console.log('📋 Response data:', data);
        
        if (data.status === 'success') {
            addConsoleMessage(`Deep scan initiated for ${ip} - scanning ${modeDescription}`, 'success');
            return true;
        } else {
            addConsoleMessage(`Failed to start deep scan: ${data.message}`, 'error');
            // Reset button on failure
            if (button) {
                button.classList.remove('bg-blue-600', 'cursor-wait');
                button.classList.add('bg-purple-600', 'hover:bg-purple-700');
                button.disabled = false;
                button.textContent = 'Deep Scan';
                button.dataset.scanStatus = 'idle';
                clearDeepScanButtonState(ip);
            }
            return false;
        }
    } catch (error) {
        console.error('Error triggering deep scan:', error);
        addConsoleMessage(`Error starting deep scan: ${error.message}`, 'error');
        
        // Reset button on error
        const buttonId = `deep-scan-btn-${ip.replace(/\./g, '-')}`;
        const button = document.getElementById(buttonId);
        if (button) {
            button.classList.remove('bg-blue-600', 'cursor-wait');
            button.classList.add('bg-purple-600', 'hover:bg-purple-700');
            button.disabled = false;
            button.textContent = 'Deep Scan';
            button.dataset.scanStatus = 'idle';
            clearDeepScanButtonState(ip);
        }
        return false;
    }
}

function handleLynisUpdate(data) {
    const { type, ip, message, stage, details } = data;
    
    // Get Lynis UI elements
    const lynisButton = document.getElementById('manual-lynis-btn');
    const lynisStatus = document.getElementById('lynis-audit-status');
    
    switch (type) {
        case 'lynis_started':
            addConsoleMessage(`🔐 ${message}`, 'info');
            if (lynisButton) {
                lynisButton.classList.remove('bg-red-600', 'hover:bg-red-700');
                lynisButton.classList.add('bg-blue-600', 'cursor-wait');
                lynisButton.disabled = true;
                lynisButton.textContent = 'Audit started';
            }
            if (lynisStatus) {
                lynisStatus.textContent = message;
                lynisStatus.className = 'text-sm text-blue-600 mt-2';
            }
            break;
            
        case 'lynis_progress':
            // Update button with progress messages
            if (lynisButton) {
                const event = data.event;
                if (event === 'connecting') {
                    lynisButton.textContent = 'Connecting...';
                } else if (event === 'connected') {
                    lynisButton.textContent = 'Connected';
                } else if (event === 'installing') {
                    lynisButton.textContent = 'Installing Lynis...';
                } else if (event === 'lynis_found') {
                    lynisButton.textContent = 'Lynis ready';
                } else if (event === 'audit_starting') {
                    lynisButton.textContent = 'Running audit...';
                } else if (event === 'processing') {
                    lynisButton.textContent = 'Processing results...';
                }
            }
            if (lynisStatus && message) {
                lynisStatus.textContent = message;
                if (details) {
                    lynisStatus.textContent += ` (${details})`;
                }
            }
            // Add console message for major stage changes
            if (stage && ['connection', 'setup', 'audit', 'processing'].includes(stage)) {
                addConsoleMessage(`   ${message}`, 'info');
            }
            break;
            
        case 'lynis_completed':
            addConsoleMessage(`✅ ${message}`, 'success');
            
            // Update button to show completion
            if (lynisButton) {
                lynisButton.classList.remove('bg-blue-600', 'cursor-wait');
                lynisButton.classList.add('bg-green-600');
                lynisButton.textContent = '✅ Audit complete';
                lynisButton.disabled = true;
                
                // Reset button after 3 seconds
                setTimeout(() => {
                    if (lynisButton) {
                        lynisButton.classList.remove('bg-green-600');
                        lynisButton.classList.add('bg-red-600', 'hover:bg-red-700');
                        lynisButton.textContent = 'Run Lynis Audit';
                        lynisButton.disabled = false;
                    }
                }, 3000);
            }
            if (lynisStatus) {
                lynisStatus.textContent = `Audit completed for ${ip}. Check vulnerabilities directory for results.`;
                lynisStatus.className = 'text-sm text-green-600 mt-2';
            }
            break;
            
        case 'lynis_error':
            addConsoleMessage(`❌ ${message}`, 'error');
            
            // Update button to show error
            if (lynisButton) {
                lynisButton.classList.remove('bg-blue-600', 'cursor-wait');
                lynisButton.classList.add('bg-red-600');
                lynisButton.textContent = '❌ Audit failed';
                lynisButton.disabled = true;
                
                // Reset button after 3 seconds
                setTimeout(() => {
                    if (lynisButton) {
                        lynisButton.classList.remove('bg-red-600');
                        lynisButton.classList.add('bg-red-600', 'hover:bg-red-700');
                        lynisButton.textContent = 'Run Lynis Audit';
                        lynisButton.disabled = false;
                    }
                }, 3000);
            }
            if (lynisStatus) {
                lynisStatus.textContent = message;
                lynisStatus.className = 'text-sm text-red-600 mt-2';
            }
            break;
    }
}

function handleDeepScanUpdate(data) {
    const { type, ip, message } = data;
    
    // Get the button for this IP
    const buttonId = `deep-scan-btn-${ip.replace(/\./g, '-')}`;
    const button = document.getElementById(buttonId);
    const customStatusEl = document.getElementById('custom-deep-scan-status');
    const updateCustomStatus = customStatusEl && customStatusEl.dataset.currentIp === ip;
    
    switch (type) {
        case 'deep_scan_started':
            addConsoleMessage(`🔍 ${message}`, 'info');
            if (button) {
                button.classList.remove('bg-purple-600', 'hover:bg-purple-700');
                button.classList.add('bg-blue-600', 'cursor-wait');
                button.disabled = true;
                button.textContent = 'Scan started';
                button.dataset.scanStatus = 'scanning';
                // Save the updated state
                saveDeepScanButtonState(ip);
            }
            if (updateCustomStatus && message) {
                customStatusEl.textContent = message;
            }
            break;
        
        case 'deep_scan_progress':
            // Update button with short progress messages
            if (button) {
                const event = data.event;
                if (event === 'scanning') {
                    button.textContent = 'Scanning...';
                } else if (event === 'hostname') {
                    // Extract short hostname (max 20 chars already in message)
                    button.textContent = message;
                } else if (event === 'port_found') {
                    const port = data.port;
                    const service = data.service;
                    button.textContent = `Port ${port} found`;
                }
                button.dataset.scanStatus = 'scanning';
                // Save the updated state
                saveDeepScanButtonState(ip);
            }
            if (updateCustomStatus && message) {
                customStatusEl.textContent = message;
            }
            break;
            
        case 'deep_scan_completed':
            const portCount = data.open_ports ? data.open_ports.length : 0;
            const duration = data.scan_duration ? data.scan_duration.toFixed(2) : 'unknown';
            addConsoleMessage(`✅ Deep scan of ${ip} complete: ${portCount} ports found in ${duration}s`, 'success');
            
            // Show detailed port information
            if (data.open_ports && data.open_ports.length > 0) {
                const portList = data.open_ports.slice(0, 10).join(', ');
                const moreText = data.open_ports.length > 10 ? ` (+${data.open_ports.length - 10} more)` : '';
                addConsoleMessage(`   Open ports: ${portList}${moreText}`, 'info');
            }
            
            // Update button to show completion
            if (button) {
                button.classList.remove('bg-blue-600', 'cursor-wait');
                button.classList.add('bg-green-600');
                button.textContent = `✅ ${portCount} ports`;
                button.disabled = true;
                button.dataset.scanStatus = 'completed';
                // Save the updated state
                saveDeepScanButtonState(ip);
                
                // Reset button after 3 seconds
                setTimeout(() => {
                    if (document.getElementById(buttonId)) {
                        button.classList.remove('bg-green-600');
                        button.classList.add('bg-purple-600', 'hover:bg-purple-700');
                        button.textContent = 'Deep Scan';
                        button.disabled = false;
                        button.dataset.scanStatus = 'idle';
                        // Clear the saved state since it's back to default
                        clearDeepScanButtonState(ip);
                    }
                }, 3000);
            }

            if (updateCustomStatus) {
                customStatusEl.textContent = `Scan complete for ${ip}: ${portCount} open ports found.`;
                customStatusEl.dataset.currentIp = '';
            }
            
            // Refresh network table to show updated port information
            if (currentTab === 'network') {
                loadNetworkData();
            }
            break;
            
        case 'deep_scan_error':
            addConsoleMessage(`❌ Deep scan error for ${ip}: ${message}`, 'error');
            
            // Update button to show error
            if (button) {
                button.classList.remove('bg-blue-600', 'cursor-wait');
                button.classList.add('bg-red-600');
                button.textContent = '❌ Error';
                button.disabled = true;
                button.dataset.scanStatus = 'error';
                // Save the updated state
                saveDeepScanButtonState(ip);
                
                // Reset button after 3 seconds
                setTimeout(() => {
                    if (document.getElementById(buttonId)) {
                        button.classList.remove('bg-red-600');
                        button.classList.add('bg-purple-600', 'hover:bg-purple-700');
                        button.textContent = 'Deep Scan';
                        button.disabled = false;
                        button.dataset.scanStatus = 'idle';
                        // Clear the saved state since it's back to default
                        clearDeepScanButtonState(ip);
                    }
                }, 3000);
            }

            if (updateCustomStatus) {
                customStatusEl.textContent = message || `Scan error for ${ip}.`;
                customStatusEl.dataset.currentIp = '';
            }
            break;
            
        default:
            addConsoleMessage(`Deep scan update: ${message}`, 'info');
            if (updateCustomStatus && message) {
                customStatusEl.textContent = message;
            }
    }
}

// ============================================================================
// ENHANCED NETWORK SCANNING WITH ARP/NMAP
// ============================================================================

// Network scanning variables for enhanced scanning
let enhancedNetworkScanInterval = null;
let isEnhancedRealTimeScanning = false;

async function startEnhancedRealTimeScan() {
    const startBtn = document.getElementById('start-network-scan');
    const stopBtn = document.getElementById('stop-network-scan');
    
    if (!startBtn || !stopBtn) return;
    
    try {
        addConsoleMessage('Starting enhanced real-time network scanning (ARP + Nmap)...', 'info');
        startBtn.disabled = true;
        stopBtn.disabled = false;
        isEnhancedRealTimeScanning = true;
        
        // Show progress section
        document.getElementById('scan-progress').classList.remove('hidden');
        
        // Start immediate scan
        await performCombinedNetworkScan();
        
        // Set up interval for continuous scanning
        enhancedNetworkScanInterval = setInterval(async () => {
            if (isEnhancedRealTimeScanning) {
                await performCombinedNetworkScan();
            }
        }, 15000); // Scan every 15 seconds (ARP background scanning is every 10 seconds)
        
        addConsoleMessage('Enhanced real-time network scanning started', 'info');
        
    } catch (error) {
        console.error('Error starting enhanced real-time scan:', error);
        addConsoleMessage('Failed to start network scan: ' + error.message, 'error');
        resetEnhancedScanButtons();
    }
}

async function stopEnhancedRealTimeScan() {
    const stopBtn = document.getElementById('stop-network-scan');
    const startBtn = document.getElementById('start-network-scan');
    
    if (enhancedNetworkScanInterval) {
        clearInterval(enhancedNetworkScanInterval);
        enhancedNetworkScanInterval = null;
    }
    
    isEnhancedRealTimeScanning = false;
    
    if (stopBtn && startBtn) {
        addConsoleMessage('Stopping enhanced network scan...', 'info');
        resetEnhancedScanButtons();
    }
}

function resetEnhancedScanButtons() {
    const startBtn = document.getElementById('start-network-scan');
    const stopBtn = document.getElementById('stop-network-scan');
    
    if (startBtn && stopBtn) {
        startBtn.disabled = false;
        stopBtn.disabled = true;
        isEnhancedRealTimeScanning = false;
        document.getElementById('scan-progress').classList.add('hidden');
    }
}

async function performCombinedNetworkScan() {
    try {
        const data = await fetchAPI('/api/scan/combined-network');
        
        if (data.success) {
            updateNetworkTableWithScanData(data);
            addConsoleMessage(`Network scan found ${data.count} hosts (ARP: ${data.arp_count}, Nmap: ${data.nmap_count})`, 'success');
        } else {
            addConsoleMessage(`Network scan failed: ${data.error}`, 'error');
        }
    } catch (error) {
        console.error('Error performing network scan:', error);
        addConsoleMessage(`Network scan error: ${error.message}`, 'error');
    }
}

function updateNetworkTableWithScanData(data) {
    const tableBody = document.getElementById('network-hosts-table');
    const hostCountSpan = document.getElementById('host-count');
    
    if (!tableBody) return;
    
    tableBody.innerHTML = '';
    
    if (!data.hosts || Object.keys(data.hosts).length === 0) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="8" class="text-center py-8 text-gray-400">
                    No hosts discovered. Check network connectivity and try again.
                </td>
            </tr>
        `;
        if (hostCountSpan) hostCountSpan.textContent = '0 hosts';
        return;
    }
    
    // Convert hosts object to array for easier processing
    const hostArray = Object.values(data.hosts);
    
    // Use DocumentFragment for better performance
    const fragment = document.createDocumentFragment();
    
    hostArray.forEach(host => {
        const row = document.createElement('tr');
        row.className = 'border-b border-slate-700 hover:bg-slate-700/50 transition-colors';
        
        // Determine status indicator
        const statusIcon = host.status === 'up' ? 
            '<span class="flex items-center"><div class="w-2 h-2 bg-green-500 rounded-full mr-2"></div>Online</span>' :
            '<span class="flex items-center"><div class="w-2 h-2 bg-red-500 rounded-full mr-2"></div>Offline</span>';
        
        // Format MAC address with vendor info
        let macDisplay = host.mac || 'Unknown';
        if (host.vendor) {
            macDisplay += `<br><span class="text-xs text-gray-400">${host.vendor}</span>`;
        }
        
        // Get source indicator
        const sourceIcon = {
            'arp': '<span class="text-xs px-2 py-1 bg-blue-600 rounded">ARP</span>',
            'nmap': '<span class="text-xs px-2 py-1 bg-purple-600 rounded">NMAP</span>',
            'arp+nmap': '<span class="text-xs px-2 py-1 bg-green-600 rounded">ARP+NMAP</span>'
        }[host.source] || '';
        
        row.innerHTML = `
            <td class="py-3 px-4">${statusIcon}</td>
            <td class="py-3 px-4 font-mono text-sm">${host.ip}</td>
            <td class="py-3 px-4">${host.hostname || 'Unknown'}</td>
            <td class="py-3 px-4 font-mono text-xs">${macDisplay}</td>
            <td class="py-3 px-4">
                <span class="text-xs px-2 py-1 bg-gray-600 rounded">Scanning...</span>
            </td>
            <td class="py-3 px-4">
                <span class="text-xs px-2 py-1 bg-gray-600 rounded">Checking...</span>
            </td>
            <td class="py-3 px-4 text-sm text-gray-400">${new Date().toLocaleTimeString()}</td>
            <td class="py-3 px-4">
                <div class="flex space-x-2">
                    ${sourceIcon}
                    <button onclick="scanSingleHostEnhanced('${host.ip}')" 
                            class="text-xs px-2 py-1 bg-Ragnar-600 hover:bg-Ragnar-700 rounded transition-colors">
                        Scan
                    </button>
                </div>
            </td>
        `;
        
        tableBody.appendChild(row);
    });
    
    // Update host count
    if (hostCountSpan) {
        hostCountSpan.textContent = `${hostArray.length} hosts`;
    }
}

async function scanSingleHostEnhanced(ip) {
    try {
        addConsoleMessage(`Scanning host ${ip}...`, 'info');
        
        const data = await postAPI('/api/scan/host', { 
            ip: ip,
            scan_type: 'full'
        });
        
        if (data.success) {
            addConsoleMessage(`Host ${ip} scan completed`, 'success');
            // Refresh the network table to show updated data
            await performCombinedNetworkScan();
        } else {
            addConsoleMessage(`Host ${ip} scan failed: ${data.error}`, 'error');
        }
    } catch (error) {
        console.error('Error scanning host:', error);
        addConsoleMessage(`Host scan error: ${error.message}`, 'error');
    }
}

function updateScanProgress() {
    const progressText = document.getElementById('scan-progress-text');
    const progressBar = document.getElementById('scan-progress-bar');
    const currentTarget = document.getElementById('current-scan-target');

    const percentage = currentScanState.totalHosts > 0 ?
        (currentScanState.scannedHosts / currentScanState.totalHosts) * 100 : 0;

    if (progressText) {
        progressText.textContent = `${currentScanState.scannedHosts}/${currentScanState.totalHosts} hosts`;
    }

    if (progressBar) {
        progressBar.style.width = `${percentage}%`;
    }

    if (currentTarget) {
        currentTarget.textContent = currentScanState.currentTarget ?
            `Currently scanning: ${currentScanState.currentTarget}` : '';
    }
}

function escapeSelector(value) {
    if (window.CSS && typeof CSS.escape === 'function') {
        return CSS.escape(value);
    }
    return value.replace(/([ #;?%&,.+*~\':"!^$\[\]()=>|\/])/g, '\\$1');
}

function parseCompactTimestamp(value) {
    if (!value) {
        return null;
    }
    const digits = value.replace(/[^0-9]/g, '');
    if (digits.length < 8) {
        return null;
    }

    const year = Number(digits.slice(0, 4));
    const month = Number(digits.slice(4, 6)) - 1;
    const day = Number(digits.slice(6, 8));
    const hour = digits.length >= 10 ? Number(digits.slice(8, 10)) : 0;
    const minute = digits.length >= 12 ? Number(digits.slice(10, 12)) : 0;
    const second = digits.length >= 14 ? Number(digits.slice(12, 14)) : 0;

    const date = new Date(year, month, day, hour, minute, second);
    return Number.isNaN(date.getTime()) ? null : date;
}

function buildLastScanInfo(rawStatus, isoTimestamp) {
    const info = {
        label: 'Never',
        className: 'text-gray-400',
        timestampText: '',
        tooltip: '',
        rawStatus: rawStatus || '',
        rawTimestamp: isoTimestamp || ''
    };

    let statusPart = (rawStatus || '').toString().trim();
    let timestamp = null;

    if (statusPart.includes('_')) {
        const parts = statusPart.split('_');
        statusPart = parts[0];
        const timestampCandidate = parts.slice(1).join('_');
        timestamp = parseCompactTimestamp(timestampCandidate);
    }

    if (!timestamp && isoTimestamp) {
        const parsed = new Date(isoTimestamp);
        if (!Number.isNaN(parsed.getTime())) {
            timestamp = parsed;
        }
    }

    if (!timestamp && rawStatus) {
        const digits = rawStatus.replace(/[^0-9]/g, '');
        if (digits.length >= 8) {
            const parsedDigits = parseCompactTimestamp(digits);
            if (parsedDigits) {
                timestamp = parsedDigits;
            }
        }
    }

    const lowerStatus = statusPart.toLowerCase();
    if (!statusPart) {
        if (timestamp) {
            info.label = 'Completed';
            info.className = 'text-blue-400';
        } else {
            info.label = 'Never';
            info.className = 'text-gray-400';
        }
    } else if (lowerStatus.startsWith('success')) {
        info.label = 'Success';
        info.className = 'text-green-400';
    } else if (lowerStatus.startsWith('failed')) {
        info.label = 'Failed';
        info.className = 'text-red-400';
    } else if (['running', 'scanning', 'pending', 'inprogress', 'in_progress'].includes(lowerStatus)) {
        info.label = statusPart.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
        info.className = 'text-yellow-400';
    } else {
        info.label = statusPart.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
        info.className = 'text-slate-300';
    }

    if (timestamp) {
        info.timestampText = timestamp.toLocaleString();
    }

    const tooltipParts = [];
    if (info.rawStatus) {
        tooltipParts.push(`Status: ${info.rawStatus}`);
    }
    if (info.timestampText) {
        tooltipParts.push(`Completed: ${info.timestampText}`);
    }
    if (info.rawTimestamp && !info.timestampText) {
        tooltipParts.push(`Reported: ${info.rawTimestamp}`);
    }
    info.tooltip = tooltipParts.join('\n');

    return info;
}

function normalizeHostRecord(hostData) {
    if (!hostData) {
        return null;
    }

    const ip = hostData.IPs || hostData.ip || hostData.address || hostData.target || '';
    if (!ip) {
        return null;
    }

    const hostname = hostData.Hostnames || hostData.Hostname || hostData.hostname || hostData.name || '';
    const mac = hostData['MAC Address'] || hostData.MAC || hostData.mac || '';

    const aliveValue = hostData.Alive ?? hostData.alive ?? hostData.Status ?? hostData.status ?? '';
    const aliveString = aliveValue === undefined || aliveValue === null ? '' : String(aliveValue).trim();
    const aliveLower = aliveString.toLowerCase();
    const isActive = ['1', 'true', 'online', 'up', 'active', 'success'].includes(aliveLower);
    const isInactive = ['0', 'false', 'offline', 'down', 'inactive', 'failed'].includes(aliveLower);

    let statusText = 'Unknown';
    if (isActive) {
        statusText = 'Active';
    } else if (isInactive) {
        statusText = 'Inactive';
    } else if (aliveString) {
        statusText = aliveString.charAt(0).toUpperCase() + aliveString.slice(1);
    }

    const statusClass = isActive ? 'text-green-400' : (isInactive ? 'text-red-400' : 'text-yellow-400');

    const rawPorts = hostData.Ports ?? hostData.ports ?? hostData.port_list ?? hostData.open_ports;
    let ports = [];
    if (Array.isArray(rawPorts)) {
        ports = rawPorts.map(port => String(port).trim()).filter(Boolean);
    } else if (typeof rawPorts === 'string') {
        ports = rawPorts.split(/[,;\s]+/).map(port => port.trim()).filter(Boolean);
    } else if (rawPorts) {
        ports = [String(rawPorts).trim()];
    }

    const vulnObjects = Array.isArray(hostData.vulnerabilities) ? hostData.vulnerabilities : [];
    const normalizedVulnObjects = vulnObjects.map(vuln => {
        if (typeof vuln === 'string') {
            return vuln;
        }
        if (vuln && typeof vuln === 'object') {
            return vuln.vulnerability || vuln.raw_output || vuln.description || vuln.id || '';
        }
        return '';
    }).filter(Boolean);

    let vulnSummary = hostData['Nmap Vulnerabilities'] || hostData['nmap_vulnerabilities'] || hostData.vulnerability_summary || '';
    if (!vulnSummary && typeof hostData.NmapVulnerabilities === 'string') {
        vulnSummary = hostData.NmapVulnerabilities;
    }
    const summaryEntries = (typeof vulnSummary === 'string' && vulnSummary.trim())
        ? vulnSummary.split(';').map(entry => entry.trim()).filter(Boolean)
        : [];

    const combinedVulns = [...normalizedVulnObjects, ...summaryEntries];
    const uniqueVulns = [];
    const seenVulns = new Set();
    combinedVulns.forEach(entry => {
        const key = entry.toLowerCase();
        if (!seenVulns.has(key)) {
            seenVulns.add(key);
            uniqueVulns.push(entry);
        }
    });

    const rawScanStatus = hostData['NmapVulnScanner'] || hostData['nmap_vuln_scanner'] || hostData.scan_status || '';
    const lastScanIso = hostData.last_scan || hostData.LastScan || hostData.last_vuln_scan || '';
    const lastScan = buildLastScanInfo(rawScanStatus, lastScanIso);

    return {
        ip: String(ip).trim(),
        hostname: hostname || '',
        mac: mac || '',
        ports,
        statusText,
        statusClass,
        vulnerabilityCount: uniqueVulns.length,
        vulnerabilityPreview: uniqueVulns.slice(0, 2).join('; '),
        vulnerabilityFull: uniqueVulns.join('; '),
        lastScan,
        raw: hostData
    };
}

function formatPortsCell(ports) {
    if (!ports || ports.length === 0) {
        return '<span class="text-gray-400">None</span>';
    }
    const displayPorts = ports.slice(0, 5);
    const displayText = escapeHtml(displayPorts.join(', '));
    const ellipsis = ports.length > 5 ? '…' : '';
    const tooltip = escapeHtml(ports.join(', '));
    return `<span title="${tooltip}">${displayText}${ellipsis}</span>`;
}

function formatVulnerabilityCell(normalized) {
    if (!normalized || normalized.vulnerabilityCount === 0) {
        return '<span class="text-gray-400">None</span>';
    }

    const countText = `${normalized.vulnerabilityCount} ${normalized.vulnerabilityCount === 1 ? 'issue' : 'issues'}`;
    const tooltipSource = normalized.vulnerabilityFull || normalized.vulnerabilityPreview || countText;
    const tooltip = escapeHtml(tooltipSource);
    const preview = normalized.vulnerabilityPreview
        ? `<div class="text-xs text-slate-300 truncate max-w-xs" title="${tooltip}">${escapeHtml(normalized.vulnerabilityPreview)}</div>`
        : '';

    return `<span class="text-red-400 font-medium" title="${tooltip}">${countText}</span>${preview}`;
}

function formatLastScanCell(info) {
    if (!info) {
        return '<span class="text-gray-400">Never</span>';
    }

    const tooltip = info.tooltip ? ` title="${escapeHtml(info.tooltip)}"` : '';
    const timestampLine = info.timestampText
        ? `<div class="text-xs text-gray-400">${escapeHtml(info.timestampText)}</div>`
        : '';

    return `<div${tooltip}><span class="${info.className}">${escapeHtml(info.label)}</span>${timestampLine}</div>`;
}

function renderHostRow(normalized) {
    const hostname = normalized.hostname ? escapeHtml(normalized.hostname) : 'Unknown';
    const mac = normalized.mac ? escapeHtml(normalized.mac) : 'Unknown';
    const ip = escapeHtml(normalized.ip);
    
    // Add a visual status dot indicator
    const isActive = normalized.statusClass.includes('green');
    const isInactive = normalized.statusClass.includes('red');
    const dotColor = isActive ? 'bg-green-500' : (isInactive ? 'bg-red-500' : 'bg-yellow-500');
    const statusDot = `<span class="inline-block w-2 h-2 rounded-full ${dotColor} mr-1"></span>`;

    return `
        <td class="py-3 px-4" data-label="Status">
            <span class="px-2 py-1 rounded text-xs ${normalized.statusClass} flex items-center">
                ${statusDot}${escapeHtml(normalized.statusText)}
            </span>
        </td>
        <td class="py-3 px-4 font-mono" data-label="IP Address">${ip}</td>
        <td class="py-3 px-4" data-label="Hostname">${hostname || 'Unknown'}</td>
        <td class="py-3 px-4 font-mono text-sm" data-label="MAC Address">${mac || 'Unknown'}</td>
        <td class="py-3 px-4 text-sm" data-label="Open Ports">${formatPortsCell(normalized.ports)}</td>
        <td class="py-3 px-4 text-sm" data-label="Vulnerabilities">${formatVulnerabilityCell(normalized)}</td>
        <td class="py-3 px-4 text-sm" data-label="Last Scan">${formatLastScanCell(normalized.lastScan)}</td>
        <td class="py-3 px-4" data-label="Actions">
                <button onclick="triggerDeepScan('${normalized.ip}', { mode: 'full' })"
                    id="deep-scan-btn-${normalized.ip.replace(/\./g, '-')}"
                    data-scan-status="idle"
                    class="deep-scan-button bg-purple-600 hover:bg-purple-700 text-white text-xs px-3 py-1 rounded transition-all duration-300"
                    title="Scan all 65535 ports with TCP connect (-sT). IP: ${normalized.ip}">
                Deep Scan
            </button>
            <button onclick="openHostPanel('${normalized.ip}')" class="bg-slate-600 hover:bg-slate-500 text-white text-xs px-3 py-1 rounded transition-colors ml-1" title="View host details">
                Details
            </button>
        </td>
    `;
}

// ── Host Detail Panel ───────────────────────────────────────────
function openHostPanel(ip) {
    const panel = document.getElementById('host-detail-panel');
    const overlay = document.getElementById('host-detail-overlay');
    if (!panel || !overlay) return;

    // Show panel immediately with loading state
    document.getElementById('hdp-ip').textContent = ip;
    document.getElementById('hdp-hostname').textContent = 'Loading...';
    document.getElementById('hdp-status').textContent = '—';
    document.getElementById('hdp-mac').textContent = '—';
    document.getElementById('hdp-lastseen').textContent = '—';
    document.getElementById('hdp-portcount').textContent = '—';
    document.getElementById('hdp-ports').innerHTML = '<span class="text-gray-400 text-sm">Loading...</span>';
    document.getElementById('hdp-creds').innerHTML = '<p class="text-gray-400 text-sm">Loading...</p>';
    document.getElementById('hdp-attacks').innerHTML = '<p class="text-gray-400 text-sm">Loading...</p>';
    document.getElementById('hdp-vuln-section').classList.add('hidden');

    overlay.classList.remove('hidden');
    panel.classList.remove('translate-x-full');

    networkAwareFetch(`/api/host/${encodeURIComponent(ip)}`)
        .then(r => r.json())
        .then(data => renderHostPanel(data))
        .catch(err => {
            document.getElementById('hdp-hostname').textContent = 'Error loading data';
        });
}

function closeHostPanel() {
    const panel = document.getElementById('host-detail-panel');
    const overlay = document.getElementById('host-detail-overlay');
    if (panel) panel.classList.add('translate-x-full');
    if (overlay) overlay.classList.add('hidden');
}

function renderHostPanel(data) {
    const statusColors = { alive: 'text-green-400', degraded: 'text-yellow-400', unknown: 'text-gray-400' };

    document.getElementById('hdp-ip').textContent = data.ip || '—';
    document.getElementById('hdp-hostname').textContent = data.hostname || 'No hostname';
    document.getElementById('hdp-status').innerHTML = `<span class="${statusColors[data.status] || 'text-gray-400'}">${escapeHtml(data.status || 'unknown')}</span>`;
    document.getElementById('hdp-mac').textContent = data.mac || '—';
    document.getElementById('hdp-lastseen').textContent = data.last_seen || '—';
    document.getElementById('hdp-portcount').textContent = `${(data.ports || []).length} port${(data.ports||[]).length !== 1 ? 's' : ''}`;

    // Ports
    const portsEl = document.getElementById('hdp-ports');
    if (data.ports && data.ports.length > 0) {
        portsEl.innerHTML = data.ports.map(p =>
            `<span class="px-2 py-1 bg-slate-700 rounded text-xs font-mono">${escapeHtml(p)}</span>`
        ).join('');
    } else {
        portsEl.innerHTML = '<span class="text-gray-500 text-sm">None detected</span>';
    }

    // Credentials
    const credsEl = document.getElementById('hdp-creds');
    if (data.credentials && data.credentials.length > 0) {
        const svcColors = { ssh:'bg-blue-900 text-blue-300', smb:'bg-purple-900 text-purple-300', ftp:'bg-yellow-900 text-yellow-300', telnet:'bg-orange-900 text-orange-300', rdp:'bg-pink-900 text-pink-300', sql:'bg-green-900 text-green-300' };
        credsEl.innerHTML = data.credentials.map(c => `
            <div class="flex items-center justify-between bg-slate-800 rounded-lg px-3 py-2">
                <div class="flex items-center gap-2">
                    <span class="px-1.5 py-0.5 rounded text-xs font-semibold uppercase ${svcColors[c.service] || 'bg-slate-700 text-gray-300'}">${c.service}</span>
                    <span class="font-mono text-sm">${escapeHtml(c.username || '—')}</span>
                    <span class="text-gray-500">:</span>
                    <span class="font-mono text-sm text-green-300">${escapeHtml(c.password || '—')}</span>
                </div>
            </div>`).join('');
    } else {
        credsEl.innerHTML = '<p class="text-gray-500 text-sm">No credentials found</p>';
    }

    // Attack logs
    const attacksEl = document.getElementById('hdp-attacks');
    if (data.attack_logs && data.attack_logs.length > 0) {
        const statusC = { success:'text-green-400', failed:'text-red-400', timeout:'text-yellow-400' };
        attacksEl.innerHTML = data.attack_logs.map(a => `
            <div class="bg-slate-800 rounded-lg px-3 py-2 text-xs">
                <div class="flex items-center justify-between mb-1">
                    <span class="font-semibold ${statusC[a.status] || 'text-gray-400'}">${a.attack_type}</span>
                    <span class="text-gray-500">${a.timestamp}</span>
                </div>
                ${a.message ? `<p class="text-gray-300">${escapeHtml(a.message)}</p>` : ''}
            </div>`).join('');
    } else {
        attacksEl.innerHTML = '<p class="text-gray-500 text-sm">No attack history</p>';
    }

    // Vuln summary
    const vulnSection = document.getElementById('hdp-vuln-section');
    const vulnEl = document.getElementById('hdp-vuln');
    if (data.vuln_summary) {
        vulnEl.textContent = data.vuln_summary;
        vulnSection.classList.remove('hidden');
    } else {
        vulnSection.classList.add('hidden');
    }
}

function updateHostCountDisplay() {
    const tableBody = document.getElementById('network-hosts-table');
    const hostCount = document.getElementById('host-count');
    if (!tableBody || !hostCount) {
        return;
    }

    const totalHosts = tableBody.querySelectorAll('tr[data-ip]').length;
    hostCount.textContent = `${totalHosts} host${totalHosts !== 1 ? 's' : ''}`;
}

function updateHostInTable(hostData) {
    const tableBody = document.getElementById('network-hosts-table');
    if (!tableBody) {
        return;
    }

    const normalized = normalizeHostRecord(hostData);
    if (!normalized) {
        return;
    }

    const noDataRow = tableBody.querySelector('td[colspan="8"]');
    if (noDataRow) {
        noDataRow.parentElement.remove();
    }

    const selector = `tr[data-ip="${escapeSelector(normalized.ip)}"]`;
    let row = tableBody.querySelector(selector);
    
    // Save deep scan button state before updating row
    if (row) {
        saveDeepScanButtonState(normalized.ip);
    }
    
    if (!row) {
        row = document.createElement('tr');
        row.setAttribute('data-ip', normalized.ip);
        row.className = 'border-b border-slate-700 hover:bg-slate-700/50 transition-colors';
        tableBody.appendChild(row);
    }

    row.innerHTML = renderHostRow(normalized);
    
    // Restore deep scan button state after updating row
    restoreDeepScanButtonState(normalized.ip);
    
    updateHostCountDisplay();
}

async function scanSingleHost(ip) {
    try {
        const response = await networkAwareFetch('/api/scan/host', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ ip: ip })
        });
        
        if (response.ok) {
            addConsoleMessage(`Started scan of ${ip}`, 'info');
        } else {
            throw new Error('Failed to start host scan');
        }
    } catch (error) {
        console.error('Error scanning host:', error);
        addConsoleMessage(`Failed to scan ${ip}: ${error.message}`, 'error');
    }
}

async function loadCredentialsData() {
    try {
        const data = await fetchAPI('/api/credentials');
        displayCredentialsTable(data);
    } catch (error) {
        console.error('Error loading credentials:', error);
    }
}

async function loadLootData() {
    try {
        const data = await fetchAPI('/api/loot');
        displayLootTable(data);
    } catch (error) {
        console.error('Error loading loot data:', error);
    }
}

// Attack Logs Functions
let currentAttackFilter = 'all';
let currentAttackGroupBy = 'ip';
let currentAttackNetworkFilter = 'all';
let currentAttackIPSearch = '';
let attackLogsCache = null;
let attackLogsETag = null;
let attackLogsInFlight = null;

async function loadAttackLogs(options = {}) {
    const { force = false } = options;

    if (attackLogsInFlight) {
        return attackLogsInFlight;
    }

    const headers = {};
    if (!force && attackLogsETag) {
        headers['If-None-Match'] = attackLogsETag;
    }

    if (!attackLogsCache) {
        document.getElementById('attack-logs-container').innerHTML = `
            <div class="text-center text-gray-400 py-8">
                <svg class="w-8 h-8 inline animate-spin mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                </svg>
                <p>Loading attack logs...</p>
            </div>
        `;
    }

    attackLogsInFlight = (async () => {
        try {
            const response = await networkAwareFetch('/api/attack?limit=200&days=7', { headers });

            if (response.status === 304) {
                console.debug('Attack logs unchanged; skipping DOM update');
                return attackLogsCache;
            }

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            attackLogsCache = data;
            attackLogsETag = response.headers.get('ETag') || attackLogsETag;
            displayAttackLogs(data);
            return data;
        } catch (error) {
            console.error('Error loading attack logs:', error);

            if (!attackLogsCache) {
                document.getElementById('attack-logs-container').innerHTML = `
                    <div class="text-center text-red-400 py-8">
                        <svg class="w-12 h-12 mx-auto mb-3 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                        </svg>
                        <p>Error loading attack logs</p>
                        <p class="text-sm text-gray-500 mt-2">${error.message}</p>
                    </div>
                `;
            }

            return attackLogsCache;
        } finally {
            attackLogsInFlight = null;
        }
    })();

    return attackLogsInFlight;
}

function filterAttackLogs(status) {
    currentAttackFilter = status;
    
    // Update filter button styles
    document.querySelectorAll('.attack-filter-btn').forEach(btn => {
        if (btn.getAttribute('data-filter') === status) {
            btn.classList.add('ring-2', 'ring-white');
        } else {
            btn.classList.remove('ring-2', 'ring-white');
        }
    });
    
    // Re-display with filter
    if (attackLogsCache) {
        displayAttackLogs(attackLogsCache);
    }
}

async function refreshAttackLogs() {
    await loadAttackLogs({ force: true });
}

function setAttackGroupBy(groupBy) {
    currentAttackGroupBy = groupBy;
    document.querySelectorAll('.attack-groupby-btn').forEach(btn => {
        const isActive = btn.getAttribute('data-groupby') === groupBy;
        btn.classList.toggle('bg-Ragnar-600', isActive);
        btn.classList.toggle('text-white', isActive);
        btn.classList.toggle('text-gray-400', !isActive);
        btn.classList.toggle('hover:text-white', !isActive);
    });
    if (attackLogsCache) displayAttackLogs(attackLogsCache);
}

function filterAttackByNetwork(network) {
    currentAttackNetworkFilter = network;
    if (attackLogsCache) displayAttackLogs(attackLogsCache);
}

function onAttackIPSearch(value) {
    currentAttackIPSearch = value.trim().toLowerCase();
    if (attackLogsCache) displayAttackLogs(attackLogsCache);
}

function _updateAttackNetworkDropdown(networks) {
    const select = document.getElementById('attack-network-filter');
    if (!select) return;
    const current = select.value;
    // Rebuild options preserving selection
    select.innerHTML = '<option value="all">All Networks</option>';
    (networks || []).forEach(n => {
        const opt = document.createElement('option');
        opt.value = n;
        opt.textContent = n === 'unknown' ? 'Unknown Network' : n;
        if (n === current) opt.selected = true;
        select.appendChild(opt);
    });
}

function _buildAttackHostBlock(ip, hostLogs) {
    const successCount = hostLogs.filter(l => l.status === 'success').length;
    const failedCount  = hostLogs.filter(l => l.status === 'failed').length;
    const timeoutCount = hostLogs.filter(l => l.status === 'timeout').length;
    const safeId = ip.replace(/[^a-zA-Z0-9]/g, '-');

    let html = `
        <div class="bg-slate-800 bg-opacity-50 rounded-lg border border-slate-700 overflow-hidden">
            <div class="px-4 py-3 bg-slate-900 bg-opacity-50 flex items-center justify-between cursor-pointer hover:bg-opacity-70 transition-colors" onclick="toggleAttackHost('${safeId}')">
                <div class="flex items-center space-x-3">
                    <svg class="w-5 h-5 text-Ragnar-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z"></path>
                    </svg>
                    <span class="font-semibold text-lg">${ip}</span>
                    <span class="text-sm text-gray-400">(${hostLogs.length} attacks)</span>
                </div>
                <div class="flex items-center space-x-4">
                    <span class="text-sm text-green-400">✓ ${successCount}</span>
                    <span class="text-sm text-red-400">✗ ${failedCount}</span>
                    <span class="text-sm text-yellow-400">⏱ ${timeoutCount}</span>
                    <svg id="attack-chevron-${safeId}" class="w-5 h-5 text-gray-400 transform transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
                    </svg>
                </div>
            </div>
            <div id="attack-host-${safeId}" class="hidden px-4 py-3 space-y-2">
    `;

    hostLogs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    hostLogs.forEach(log => {
        const statusColors = {
            'success': 'bg-green-900 bg-opacity-30 border-green-500',
            'failed':  'bg-red-900 bg-opacity-30 border-red-500',
            'timeout': 'bg-yellow-900 bg-opacity-30 border-yellow-500'
        };
        const statusIcons      = { 'success': '✓', 'failed': '✗', 'timeout': '⏱' };
        const statusTextColors = { 'success': 'text-green-400', 'failed': 'text-red-400', 'timeout': 'text-yellow-400' };

        const colorClass = statusColors[log.status]     || 'bg-gray-900 bg-opacity-30 border-gray-500';
        const icon       = statusIcons[log.status]      || '•';
        const textColor  = statusTextColors[log.status] || 'text-gray-400';

        html += `
            <div class="border-l-4 ${colorClass} p-3 rounded-r-lg">
                <div class="flex items-start justify-between">
                    <div class="flex-1">
                        <div class="flex items-center space-x-2 mb-1">
                            <span class="font-semibold ${textColor}">${icon} ${log.attack_type}</span>
                            ${log.target_port ? `<span class="text-xs text-gray-400">Port ${log.target_port}</span>` : ''}
                            <span class="text-xs text-gray-500">${log.timestamp}</span>
                        </div>
                        ${log.message ? `<p class="text-sm text-gray-300 mb-2">${escapeHtml(log.message)}</p>` : ''}
                        ${Object.keys(log.details || {}).length > 0 ? `
                            <div class="text-xs space-y-1 mt-2">
                                ${Object.entries(log.details).map(([key, value]) => `
                                    <div class="flex items-center space-x-2">
                                        <span class="text-gray-500">${key}:</span>
                                        <span class="text-gray-300 font-mono">${escapeHtml(String(value))}</span>
                                    </div>
                                `).join('')}
                            </div>
                        ` : ''}
                    </div>
                </div>
            </div>
        `;
    });

    html += `</div></div>`;
    return html;
}

function displayAttackLogs(data) {
    if (!data || !data.attack_logs) {
        document.getElementById('attack-logs-container').innerHTML = `
            <div class="text-center text-gray-400 py-8">
                <svg class="w-12 h-12 mx-auto mb-3 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                </svg>
                <p>No attack logs found</p>
            </div>
        `;
        return;
    }

    // Update statistics
    document.getElementById('attack-stat-total').textContent = data.total_count || 0;
    document.getElementById('attack-stat-success').textContent = data.success_count || 0;
    document.getElementById('attack-stat-failed').textContent = data.failed_count || 0;
    const timeoutCount = data.attack_logs.filter(log => log.status === 'timeout').length;
    document.getElementById('attack-stat-timeout').textContent = timeoutCount;

    // Populate network dropdown from available_networks returned by the API
    _updateAttackNetworkDropdown(data.available_networks || []);

    // Apply status filter
    let logs = data.attack_logs;
    if (currentAttackFilter !== 'all') {
        logs = logs.filter(log => log.status === currentAttackFilter);
    }

    // Apply network filter
    if (currentAttackNetworkFilter !== 'all') {
        logs = logs.filter(log => (log.network_ssid || 'unknown') === currentAttackNetworkFilter);
    }

    // Apply IP search filter
    if (currentAttackIPSearch) {
        logs = logs.filter(log => (log.target_ip || '').toLowerCase().includes(currentAttackIPSearch));
    }

    if (logs.length === 0) {
        document.getElementById('attack-logs-container').innerHTML = `
            <div class="text-center text-gray-400 py-8">
                <svg class="w-12 h-12 mx-auto mb-3 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"></path>
                </svg>
                <p>No attacks match the current filters</p>
            </div>
        `;
        return;
    }

    let html = '<div class="space-y-4">';

    if (currentAttackGroupBy === 'network') {
        // --- Group by Network (SSID), then sub-group by IP ---
        const logsByNetwork = {};
        logs.forEach(log => {
            const net = log.network_ssid || 'unknown';
            if (!logsByNetwork[net]) logsByNetwork[net] = {};
            const ip = log.target_ip || 'Unknown';
            if (!logsByNetwork[net][ip]) logsByNetwork[net][ip] = [];
            logsByNetwork[net][ip].push(log);
        });

        Object.keys(logsByNetwork).sort().forEach(net => {
            const netId = net.replace(/[^a-zA-Z0-9]/g, '-');
            const netLogs = Object.values(logsByNetwork[net]).flat();
            const netSuccess = netLogs.filter(l => l.status === 'success').length;
            const netFailed  = netLogs.filter(l => l.status === 'failed').length;
            const netTimeout = netLogs.filter(l => l.status === 'timeout').length;
            const ipCount = Object.keys(logsByNetwork[net]).length;

            html += `
                <div class="bg-slate-900 bg-opacity-60 rounded-xl border border-slate-600 overflow-hidden">
                    <div class="px-4 py-3 bg-slate-900 flex items-center justify-between cursor-pointer hover:bg-slate-800 transition-colors" onclick="toggleAttackHost('net-${netId}')">
                        <div class="flex items-center space-x-3">
                            <svg class="w-5 h-5 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071c3.904-3.905 10.236-3.905 14.141 0M1.394 9.393c5.857-5.857 15.355-5.857 21.213 0"></path>
                            </svg>
                            <span class="font-bold text-blue-300">${escapeHtml(net === 'unknown' ? 'Unknown Network' : net)}</span>
                            <span class="text-sm text-gray-400">${ipCount} host${ipCount !== 1 ? 's' : ''} · ${netLogs.length} attack${netLogs.length !== 1 ? 's' : ''}</span>
                        </div>
                        <div class="flex items-center space-x-4">
                            <span class="text-sm text-green-400">✓ ${netSuccess}</span>
                            <span class="text-sm text-red-400">✗ ${netFailed}</span>
                            <span class="text-sm text-yellow-400">⏱ ${netTimeout}</span>
                            <svg id="attack-chevron-net-${netId}" class="w-5 h-5 text-gray-400 transform transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
                            </svg>
                        </div>
                    </div>
                    <div id="attack-host-net-${netId}" class="hidden px-4 py-3 space-y-3">
            `;

            Object.keys(logsByNetwork[net]).sort().forEach(ip => {
                html += _buildAttackHostBlock(ip, logsByNetwork[net][ip]);
            });

            html += `</div></div>`;
        });

    } else {
        // --- Default: Group by IP ---
        const logsByIP = {};
        logs.forEach(log => {
            const ip = log.target_ip || 'Unknown';
            if (!logsByIP[ip]) logsByIP[ip] = [];
            logsByIP[ip].push(log);
        });

        Object.keys(logsByIP).sort().forEach(ip => {
            html += _buildAttackHostBlock(ip, logsByIP[ip]);
        });
    }

    html += '</div>';
    document.getElementById('attack-logs-container').innerHTML = html;
}

function toggleAttackHost(safeId) {
    const container = document.getElementById(`attack-host-${safeId}`);
    const chevron   = document.getElementById(`attack-chevron-${safeId}`);
    if (!container || !chevron) return;
    if (container.classList.contains('hidden')) {
        container.classList.remove('hidden');
        chevron.classList.add('rotate-180');
    } else {
        container.classList.add('hidden');
        chevron.classList.remove('rotate-180');
    }
}

// ============================================================================
// VULNERABILITY INTELLIGENCE FUNCTIONS
// ============================================================================

async function loadVulnerabilityIntel() {
    try {
        const container = document.getElementById('vulnerability-intel-container');
        
        // Show loading state
        container.innerHTML = `
            <div class="text-center text-gray-400 py-8">
                <svg class="w-8 h-8 inline animate-spin mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                </svg>
                <p>Loading service intelligence...</p>
            </div>
        `;
        
        const data = await fetchAPI('/api/vulnerability-intel');
        
        if (!data) {
            container.innerHTML = `
                <div class="text-center text-red-400 py-8">
                    <p>Error loading service intelligence</p>
                </div>
            `;
            return;
        }
        
        // Update statistics
        document.getElementById('intel-stat-scanned').textContent = data.statistics.total_scanned || 0;
        document.getElementById('intel-stat-interesting').textContent = data.statistics.interesting_hosts || 0;
        document.getElementById('intel-stat-services').textContent = data.statistics.services_with_intel || 0;
        document.getElementById('intel-stat-scripts').textContent = data.statistics.script_outputs || 0;
        
        displayVulnerabilityIntel(data.scans);
    } catch (error) {
        console.error('Error loading vulnerability intelligence:', error);
        const container = document.getElementById('vulnerability-intel-container');
        container.innerHTML = `
            <div class="text-center text-red-400 py-8">
                <svg class="w-12 h-12 mx-auto mb-3 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                </svg>
                <p>Error loading service intelligence</p>
                <p class="text-sm text-gray-500 mt-2">${error.message}</p>
            </div>
        `;
    }
}

function displayVulnerabilityIntel(scans) {
    const container = document.getElementById('vulnerability-intel-container');
    
    if (!scans || scans.length === 0) {
        container.innerHTML = `
            <div class="text-center text-gray-400 py-8">
                <svg class="w-12 h-12 mx-auto mb-3 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
                </svg>
                <p>No interesting intelligence found</p>
                <p class="text-sm text-gray-500 mt-2">Scanned hosts without interesting data are filtered out</p>
            </div>
        `;
        return;
    }
    
    let html = '<div class="space-y-4">';
    
    scans.forEach(scan => {
        const serviceCount = scan.total_services || 0;
        const scriptCount = scan.services.reduce((sum, svc) => sum + (svc.scripts?.length || 0), 0);
        
        html += `
            <div class="bg-slate-800 bg-opacity-50 rounded-lg border border-slate-700 overflow-hidden">
                <div class="px-4 py-3 bg-slate-900 bg-opacity-50 flex items-center justify-between cursor-pointer hover:bg-opacity-70 transition-colors" onclick="toggleVulnHost('${scan.ip}')">
                    <div class="flex items-center space-x-3">
                        <svg class="w-5 h-5 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                        </svg>
                        <div>
                            <div class="font-semibold text-lg">${escapeHtml(scan.hostname)}</div>
                            <div class="text-sm text-gray-400">${escapeHtml(scan.ip)}</div>
                        </div>
                    </div>
                    <div class="flex items-center space-x-4">
                        ${scan.download_url ? `
                            <a href="${scan.download_url}" target="_blank" rel="noopener noreferrer"
                               class="text-xs px-3 py-1 rounded-full bg-cyan-900/60 text-cyan-200 border border-cyan-500/40 hover:bg-cyan-800/80 transition">
                                ${scan.scan_type === 'lynis' ? 'Download full report' : 'View full report'}
                            </a>
                        ` : ''}
                        ${(scan.log_url && scan.log_url !== scan.download_url) ? `
                            <a href="${scan.log_url}" target="_blank" rel="noopener noreferrer"
                               class="text-xs px-3 py-1 rounded-full bg-slate-900/60 text-slate-200 border border-slate-500/40 hover:bg-slate-800/80 transition">
                                View audit log
                            </a>
                        ` : ''}
                        <span class="text-sm text-cyan-400">📡 ${serviceCount} services</span>
                        ${scriptCount > 0 ? `<span class="text-sm text-purple-400">📜 ${scriptCount} scripts</span>` : ''}
                        <span class="text-xs text-gray-500">${scan.scan_date}</span>
                        <svg id="vuln-chevron-${scan.ip.replace(/\./g, '-')}" class="w-5 h-5 text-gray-400 transform transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
                        </svg>
                    </div>
                </div>
                
                <div id="vuln-host-${scan.ip.replace(/\./g, '-')}" class="hidden px-4 py-3 border-t border-slate-700">
                    <div class="space-y-3">
                        ${scan.services
                            .sort((a, b) => {
                                // Sort so Lynis pentest (system info) appears before ports
                                const aIsSystem = a.port === 'system' || a.service === 'lynis pentest';
                                const bIsSystem = b.port === 'system' || b.service === 'lynis pentest';
                                
                                if (aIsSystem && !bIsSystem) return -1;  // System first
                                if (!aIsSystem && bIsSystem) return 1;   // System first
                                
                                // For non-system services, sort by port number
                                if (!aIsSystem && !bIsSystem) {
                                    const portA = parseInt(a.port) || 99999;
                                    const portB = parseInt(b.port) || 99999;
                                    return portA - portB;
                                }
                                
                                return 0;  // Keep original order for same type
                            })
                            .map(service => {
                            const hasScripts = service.scripts && service.scripts.length > 0;
                            const isSystemInfo = service.port === 'system' || service.service === 'lynis pentest';
                            
                            return `
                                <div class="${isSystemInfo ? 'bg-blue-900 bg-opacity-30 border border-blue-500/30' : 'bg-slate-700 bg-opacity-50'} rounded-lg p-4">
                                    <div class="flex items-start justify-between mb-2">
                                        <div class="flex-1">
                                            <div class="flex items-center space-x-2 mb-1">
                                                ${isSystemInfo ? 
                                                    `<svg class="w-4 h-4 text-blue-400 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path>
                                                    </svg>
                                                    <span class="font-semibold text-blue-200">🖥️ System Audit</span>` : 
                                                    `<span class="font-semibold text-white">${escapeHtml(service.port)}</span>`
                                                }
                                                <span class="text-sm ${isSystemInfo ? 'text-blue-300' : 'text-gray-400'}">${escapeHtml(service.service)}</span>
                                            </div>
                                            ${service.version ? `
                                                <div class="text-sm text-cyan-300 font-mono bg-slate-900 bg-opacity-50 px-2 py-1 rounded inline-block">
                                                    ${escapeHtml(service.version)}
                                                </div>
                                            ` : ''}
                                        </div>
                                    </div>
                                    
                                    ${hasScripts ? `
                                        <div class="mt-3 space-y-2">
                                            ${service.scripts.map(script => `
                                                <div class="bg-slate-900 bg-opacity-50 rounded p-3">
                                                    <div class="text-sm font-semibold text-purple-400 mb-2">
                                                        📜 ${escapeHtml(script.name)}
                                                    </div>
                                                    <pre class="text-xs text-gray-300 font-mono whitespace-pre-wrap overflow-x-auto max-h-96 scrollbar-thin">${escapeHtml(script.output)}</pre>
                                                </div>
                                            `).join('')}
                                        </div>
                                    ` : ''}
                                </div>
                            `;
                        }).join('')}
                    </div>
                </div>
            </div>
        `;
    });
    
    html += '</div>';
    container.innerHTML = html;
}

function toggleVulnHost(ip) {
    const containerId = `vuln-host-${ip.replace(/\./g, '-')}`;
    const chevronId = `vuln-chevron-${ip.replace(/\./g, '-')}`;
    const container = document.getElementById(containerId);
    const chevron = document.getElementById(chevronId);
    
    if (container.classList.contains('hidden')) {
        container.classList.remove('hidden');
        chevron.classList.add('rotate-180');
    } else {
        container.classList.add('hidden');
        chevron.classList.remove('rotate-180');
    }
}

async function refreshVulnerabilityIntel() {
    showNotification('Refreshing service intelligence...', 'info');
    await loadVulnerabilityIntel();
}

// ============================================================================
// CREDENTIALS AND LOOT FUNCTIONS  
// ============================================================================

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

async function loadConfigData() {
    try {
        const config = await fetchAPI('/api/config');
        displayConfigForm(config);

        // Load AI configuration
        loadAIConfiguration(config);

        // Load Pushover configuration
        loadPushoverConfiguration(config);

        // Load hardware profiles
        await loadHardwareProfiles();

        // Display current profile if set
        displayCurrentProfile(config);

        // Update vulnerability count in data management card
        updateVulnerabilityCount();
        await refreshPwnagotchiStatus({ silent: true });

        // Also check for updates when loading config tab
        checkForUpdates();

        // Load security configuration
        await loadSecurityConfig();
    } catch (error) {
        console.error('Error loading config:', error);
    }
}

// ============================================================================
// SECURITY / AUTHENTICATION CONFIG
// ============================================================================

let _securityExpanded = false;

function toggleSecuritySection() {
    _securityExpanded = !_securityExpanded;
    const content = document.getElementById('security-config-content');
    const summary = document.getElementById('security-summary');
    const chevron = document.getElementById('security-chevron');
    if (_securityExpanded) {
        content.classList.remove('hidden');
        summary.classList.add('hidden');
        chevron.style.transform = 'rotate(90deg)';
    } else {
        content.classList.add('hidden');
        summary.classList.remove('hidden');
        chevron.style.transform = 'rotate(0deg)';
    }
}

async function loadSecurityConfig() {
    try {
        const status = await fetchAPI('/api/auth/status');
        const container = document.getElementById('security-config-content');
        const summary = document.getElementById('security-summary');
        const badge = document.getElementById('security-badge');
        if (!container) return;

        // Show/hide logout buttons in nav (desktop + mobile)
        const logoutBtn = document.getElementById('logout-btn');
        if (logoutBtn) {
            logoutBtn.classList.toggle('hidden', !status.configured);
        }
        const mobileLogoutBtn = document.getElementById('mobile-logout-btn');
        if (mobileLogoutBtn) {
            mobileLogoutBtn.classList.toggle('hidden', !status.configured);
        }

        // Update summary and badge based on status
        if (status.configured) {
            if (badge) { badge.classList.remove('hidden'); }
            if (summary) {
                summary.innerHTML = '<p class="text-sm text-green-400">Authentication is enabled. Database is encrypted and hardware-bound. Expand to manage.</p>';
            }
        } else {
            if (badge) { badge.classList.add('hidden'); }
            if (summary) {
                summary.innerHTML = '<p class="text-sm text-red-400">Set up authentication to protect your Ragnar instance. Once enabled, all access will require login. The database will be encrypted and bound to this hardware.</p>';
            }
        }

        if (!status.configured) {
            // Show setup form
            container.innerHTML = `
                <div class="mb-4">
                    <div class="p-3 rounded-lg bg-yellow-900/30 border border-yellow-700 text-sm text-yellow-300 mb-4">
                        Warning: Once authentication is enabled, you will need your password or recovery codes to access Ragnar.
                        Make sure to save your recovery codes in a safe place.
                    </div>
                </div>
                <form id="auth-setup-form" onsubmit="handleAuthSetup(event)" class="space-y-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-300 mb-2">Username</label>
                        <input type="text" id="setup-username" required autocomplete="username"
                               class="w-full px-4 py-2 rounded-lg bg-slate-700 border border-slate-600 text-white placeholder-gray-400 focus:ring-2 focus:ring-sky-500 focus:border-transparent outline-none"
                               placeholder="Choose a username">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-300 mb-2">Password</label>
                        <input type="password" id="setup-password" required minlength="8" autocomplete="new-password"
                               class="w-full px-4 py-2 rounded-lg bg-slate-700 border border-slate-600 text-white placeholder-gray-400 focus:ring-2 focus:ring-sky-500 focus:border-transparent outline-none"
                               placeholder="Minimum 8 characters">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-300 mb-2">Confirm Password</label>
                        <input type="password" id="setup-confirm-password" required minlength="8" autocomplete="new-password"
                               class="w-full px-4 py-2 rounded-lg bg-slate-700 border border-slate-600 text-white placeholder-gray-400 focus:ring-2 focus:ring-sky-500 focus:border-transparent outline-none"
                               placeholder="Confirm password">
                    </div>
                    <div id="setup-status" class="hidden p-3 rounded-lg text-sm"></div>
                    <button type="submit" id="setup-btn"
                            class="w-full bg-sky-600 hover:bg-sky-700 text-white font-semibold py-2 px-4 rounded-lg transition-colors">
                        Enable Authentication
                    </button>
                </form>
            `;
        } else {
            // Show management panel
            let hwBadge = status.hw_match
                ? '<span class="text-green-400 text-xs">Hardware matched</span>'
                : '<span class="text-red-400 text-xs">Hardware mismatch!</span>';

            container.innerHTML = `
                <div class="space-y-4">
                    <div class="flex items-center justify-between">
                        <div>
                            <span class="text-green-400 font-medium">Authentication Enabled</span>
                            <span class="mx-2 text-gray-500">|</span>
                            ${hwBadge}
                            <span class="mx-2 text-gray-500">|</span>
                            <span class="text-gray-400 text-xs">${status.recovery_codes_remaining} recovery codes remaining</span>
                        </div>
                    </div>

                    <!-- Change Password -->
                    <div class="glass rounded-lg p-4">
                        <h4 class="font-medium mb-3">Change Password</h4>
                        <form id="change-pw-form" onsubmit="handleChangePassword(event)" class="space-y-3">
                            <input type="password" id="current-password" required autocomplete="current-password"
                                   class="w-full px-3 py-2 rounded-lg bg-slate-700 border border-slate-600 text-white placeholder-gray-400 focus:ring-2 focus:ring-sky-500 outline-none"
                                   placeholder="Current password">
                            <input type="password" id="new-password" required minlength="8" autocomplete="new-password"
                                   class="w-full px-3 py-2 rounded-lg bg-slate-700 border border-slate-600 text-white placeholder-gray-400 focus:ring-2 focus:ring-sky-500 outline-none"
                                   placeholder="New password (min 8 chars)">
                            <input type="password" id="confirm-new-password" required minlength="8" autocomplete="new-password"
                                   class="w-full px-3 py-2 rounded-lg bg-slate-700 border border-slate-600 text-white placeholder-gray-400 focus:ring-2 focus:ring-sky-500 outline-none"
                                   placeholder="Confirm new password">
                            <div id="change-pw-status" class="hidden p-3 rounded-lg text-sm"></div>
                            <button type="submit"
                                    class="bg-sky-600 hover:bg-sky-700 text-white px-4 py-2 rounded-lg transition-colors text-sm">
                                Change Password
                            </button>
                        </form>
                    </div>

                    <!-- Recovery Codes -->
                    <div class="glass rounded-lg p-4">
                        <h4 class="font-medium mb-3">Recovery Codes</h4>
                        <p class="text-gray-400 text-sm mb-3">
                            ${status.recovery_codes_remaining} of 10 codes remaining.
                            Regenerate to get 10 new codes (old codes will be invalidated).
                        </p>
                        <div id="regen-codes-display" class="hidden mb-3"></div>
                        <div id="regen-status" class="hidden p-3 rounded-lg text-sm mb-3"></div>
                        <button onclick="handleRegenRecovery()"
                                class="bg-yellow-600 hover:bg-yellow-700 text-white px-4 py-2 rounded-lg transition-colors text-sm">
                            Regenerate Recovery Codes
                        </button>
                    </div>

                    <!-- Logout -->
                    <div class="glass rounded-lg p-4">
                        <h4 class="font-medium mb-3">Session</h4>
                        <button onclick="handleLogout()"
                                class="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg transition-colors text-sm">
                            Logout
                        </button>
                    </div>
                </div>
            `;
        }
    } catch (error) {
        console.error('Error loading security config:', error);
    }
}

async function handleAuthSetup(event) {
    event.preventDefault();
    const statusEl = document.getElementById('setup-status');
    const btn = document.getElementById('setup-btn');

    const username = document.getElementById('setup-username').value.trim();
    const password = document.getElementById('setup-password').value;
    const confirm = document.getElementById('setup-confirm-password').value;

    if (password !== confirm) {
        statusEl.className = 'p-3 rounded-lg text-sm bg-red-900/30 border border-red-700 text-red-300';
        statusEl.textContent = 'Passwords do not match';
        statusEl.classList.remove('hidden');
        return;
    }

    btn.disabled = true;
    btn.textContent = 'Setting up...';

    try {
        const result = await postAPI('/api/auth/setup', {
            username, password, confirm_password: confirm
        });

        if (result.success) {
            // Show recovery codes in a prominent way
            statusEl.className = 'p-3 rounded-lg text-sm bg-green-900/30 border border-green-700 text-green-300';
            statusEl.innerHTML = 'Authentication enabled! Save your recovery codes below.';
            statusEl.classList.remove('hidden');

            const container = document.getElementById('security-config-content');
            container.innerHTML = `
                <div class="p-4 rounded-lg bg-green-900/20 border border-green-700 mb-4">
                    <h4 class="font-bold text-green-400 mb-2">Authentication Enabled Successfully!</h4>
                    <p class="text-sm text-gray-300 mb-3">
                        Save these recovery codes in a safe place. Each code can only be used once.
                        You will need them if you forget your password.
                    </p>
                    <p class="text-sm text-yellow-300 mb-4">
                        The database will be encrypted automatically when you log out or when Ragnar shuts down.
                        From the next start, a login will be required.
                    </p>
                    <div class="grid grid-cols-2 gap-2 mb-4">
                        ${result.recovery_codes.map(code =>
                            `<div class="font-mono text-sm bg-slate-800 border border-sky-700 rounded px-3 py-2 text-center text-sky-300 select-all">${code}</div>`
                        ).join('')}
                    </div>
                    <button onclick="copyRecoveryCodes()" id="copy-codes-btn"
                            class="bg-sky-600 hover:bg-sky-700 text-white px-4 py-2 rounded-lg transition-colors text-sm mr-2">
                        Copy All Codes
                    </button>
                    <button onclick="loadSecurityConfig()"
                            class="bg-slate-600 hover:bg-slate-700 text-white px-4 py-2 rounded-lg transition-colors text-sm">
                        Done
                    </button>
                </div>
            `;

            // Store codes temporarily for copy function
            window._tempRecoveryCodes = result.recovery_codes;

            addConsoleMessage('Authentication enabled - database encrypted', 'success');
        } else {
            statusEl.className = 'p-3 rounded-lg text-sm bg-red-900/30 border border-red-700 text-red-300';
            statusEl.textContent = result.error || 'Setup failed';
            statusEl.classList.remove('hidden');
            btn.disabled = false;
            btn.textContent = 'Enable Authentication';
        }
    } catch (error) {
        statusEl.className = 'p-3 rounded-lg text-sm bg-red-900/30 border border-red-700 text-red-300';
        statusEl.textContent = 'Setup failed: ' + (error.message || 'Unknown error');
        statusEl.classList.remove('hidden');
        btn.disabled = false;
        btn.textContent = 'Enable Authentication';
    }
}

function copyRecoveryCodes() {
    if (window._tempRecoveryCodes) {
        const text = window._tempRecoveryCodes.join('\n');
        navigator.clipboard.writeText(text).then(() => {
            const btn = document.getElementById('copy-codes-btn');
            btn.textContent = 'Copied!';
            setTimeout(() => { btn.textContent = 'Copy All Codes'; }, 2000);
        }).catch(() => {
            addConsoleMessage('Failed to copy - please select and copy manually', 'warning');
        });
    }
}

async function handleChangePassword(event) {
    event.preventDefault();
    const statusEl = document.getElementById('change-pw-status');

    const currentPw = document.getElementById('current-password').value;
    const newPw = document.getElementById('new-password').value;
    const confirmPw = document.getElementById('confirm-new-password').value;

    if (newPw !== confirmPw) {
        statusEl.className = 'p-3 rounded-lg text-sm bg-red-900/30 border border-red-700 text-red-300';
        statusEl.textContent = 'New passwords do not match';
        statusEl.classList.remove('hidden');
        return;
    }

    try {
        const result = await postAPI('/api/auth/change-password', {
            current_password: currentPw,
            new_password: newPw
        });
        if (result.success) {
            statusEl.className = 'p-3 rounded-lg text-sm bg-green-900/30 border border-green-700 text-green-300';
            statusEl.textContent = 'Password changed successfully';
            statusEl.classList.remove('hidden');
            document.getElementById('change-pw-form').reset();
            addConsoleMessage('Password changed successfully', 'success');
        } else {
            statusEl.className = 'p-3 rounded-lg text-sm bg-red-900/30 border border-red-700 text-red-300';
            statusEl.textContent = result.error || 'Failed to change password';
            statusEl.classList.remove('hidden');
        }
    } catch (error) {
        statusEl.className = 'p-3 rounded-lg text-sm bg-red-900/30 border border-red-700 text-red-300';
        statusEl.textContent = 'Error: ' + (error.message || 'Unknown error');
        statusEl.classList.remove('hidden');
    }
}

async function handleRegenRecovery() {
    const password = prompt('Enter your current password to regenerate recovery codes:');
    if (!password) return;

    const statusEl = document.getElementById('regen-status');
    const displayEl = document.getElementById('regen-codes-display');

    try {
        const result = await postAPI('/api/auth/regenerate-recovery', { password });
        if (result.success) {
            displayEl.innerHTML = `
                <div class="p-3 rounded-lg bg-slate-800 border border-sky-700">
                    <p class="text-sm text-gray-300 mb-2">New recovery codes (save these!):</p>
                    <div class="grid grid-cols-2 gap-2">
                        ${result.recovery_codes.map(code =>
                            `<div class="font-mono text-sm bg-slate-900 rounded px-2 py-1 text-center text-sky-300 select-all">${code}</div>`
                        ).join('')}
                    </div>
                </div>
            `;
            displayEl.classList.remove('hidden');

            statusEl.className = 'p-3 rounded-lg text-sm bg-green-900/30 border border-green-700 text-green-300';
            statusEl.textContent = 'Recovery codes regenerated. Save them securely!';
            statusEl.classList.remove('hidden');

            window._tempRecoveryCodes = result.recovery_codes;
            addConsoleMessage('Recovery codes regenerated', 'success');
        } else {
            statusEl.className = 'p-3 rounded-lg text-sm bg-red-900/30 border border-red-700 text-red-300';
            statusEl.textContent = result.error || 'Failed to regenerate codes';
            statusEl.classList.remove('hidden');
        }
    } catch (error) {
        statusEl.className = 'p-3 rounded-lg text-sm bg-red-900/30 border border-red-700 text-red-300';
        statusEl.textContent = 'Error: ' + (error.message || 'Unknown error');
        statusEl.classList.remove('hidden');
    }
}

async function handleLogout() {
    // Disconnect socket first to prevent reconnect loops
    if (socket) socket.disconnect();
    try {
        await postAPI('/api/auth/logout', {});
    } catch (e) {
        // Ignore - we're redirecting anyway
    }
    // Replace so back button can't return to the dashboard
    window.location.replace('/login');
}



function setPwnStatusPollInterval(intervalMs = PWN_STATUS_POLL_INTERVAL) {
    const normalized = Math.max(2000, intervalMs || PWN_STATUS_POLL_INTERVAL);

    if (currentPwnStatusInterval === normalized && autoRefreshIntervals.pwn) {
        return;
    }

    if (autoRefreshIntervals.pwn) {
        clearInterval(autoRefreshIntervals.pwn);
    }

    currentPwnStatusInterval = normalized;
    autoRefreshIntervals.pwn = setInterval(() => {
        if (currentTab === 'config' || currentTab === 'discovered') {
            refreshPwnagotchiStatus({ silent: true });
        }
    }, normalized);
}

function initializePwnUI() {
    const badge = document.getElementById('pwn-status-badge');
    if (!badge) {
        return;
    }

    const installBtn = document.getElementById('pwn-install-btn');
    if (installBtn) {
        installBtn.addEventListener('click', handlePwnInstallClick);
    }

    const swapToPwnBtn = document.getElementById('pwn-swap-to-pwn-btn');
    if (swapToPwnBtn) {
        swapToPwnBtn.addEventListener('click', () => handlePwnSwap('pwnagotchi'));
    }

    const refreshBtn = document.getElementById('pwn-refresh-btn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', () => refreshPwnagotchiStatus());
    }

    const logRefreshBtn = document.getElementById('pwn-log-refresh-btn');
    if (logRefreshBtn) {
        logRefreshBtn.addEventListener('click', () => fetchPwnLogs({ initial: pwnLogCursor === 0 }));
    }

    updatePwnButtons();
    resetPwnLogState();
    refreshPwnagotchiStatus({ silent: true });

    // Pwnagotchi config card buttons
    const cfgReloadBtn = document.getElementById('pwn-config-reload-btn');
    if (cfgReloadBtn) {
        cfgReloadBtn.addEventListener('click', () => loadPwnConfig());
    }
    const cfgSaveBtn = document.getElementById('pwn-config-save-btn');
    if (cfgSaveBtn) {
        cfgSaveBtn.addEventListener('click', () => savePwnConfig());
    }
}

async function refreshPwnagotchiStatus(options = {}) {
    const silent = Boolean(options && options.silent);
    try {
        const response = await fetchAPI('/api/pwnagotchi/status');
        if (response && response.success && response.status) {
            updatePwnagotchiUI(response.status);
            return response.status;
        }
        if (!silent) {
            addConsoleMessage('Unable to load Pwnagotchi status', 'warning');
        }
    } catch (error) {
        console.error('Error refreshing Pwnagotchi status:', error);
        if (!silent) {
            addConsoleMessage(`Pwnagotchi status error: ${error.message}`, 'error');
        }
    }
    return null;
}

function updatePwnagotchiUI(status = {}) {
    if (!status || typeof status !== 'object') {
        return;
    }

    const wasInstalling = Boolean(pwnStatus.installing);

    pwnStatus = {
        ...pwnStatus,
        ...status
    };
    pwnStatus.installing = Boolean(pwnStatus.installing);

    const visuals = getPwnStateVisuals(pwnStatus);

    const badge = document.getElementById('pwn-status-badge');
    if (badge) {
        badge.textContent = visuals.badgeText;
        badge.className = `text-xs font-semibold uppercase tracking-wide px-3 py-1 rounded-full ${visuals.badgeClass}`;
    }

    updateElement('pwn-status-message', pwnStatus.message || 'Waiting for status...');

    const modeLabel = formatPwnModeLabel(pwnStatus.mode);
    updateElement('pwn-mode-value', modeLabel);
    const modeElement = document.getElementById('pwn-mode-value');
    if (modeElement) {
        modeElement.className = `font-semibold ${pwnStatus.mode === 'pwnagotchi' ? 'text-fuchsia-300' : 'text-green-400'}`;
    }

    updateElement('pwn-target-value', formatPwnModeLabel(pwnStatus.target_mode));
    updateElement('pwn-phase-value', formatPwnPhaseLabel(pwnStatus.phase));

    updateElement('pwn-service-state', pwnStatus.service_active ? 'Running' : 'Stopped');
    const serviceStateElement = document.getElementById('pwn-service-state');
    if (serviceStateElement) {
        serviceStateElement.className = `font-semibold ${pwnStatus.service_active ? 'text-green-400' : 'text-slate-200'}`;
    }

    updateElement('pwn-service-enabled', pwnStatus.service_enabled ? 'Enabled' : 'Disabled');
    const serviceEnabledElement = document.getElementById('pwn-service-enabled');
    if (serviceEnabledElement) {
        serviceEnabledElement.className = `font-semibold ${pwnStatus.service_enabled ? 'text-green-300' : 'text-slate-200'}`;
    }

    updateElement('pwn-last-switch-value', pwnStatus.last_switch ? formatTimestamp(pwnStatus.last_switch) : 'Never');
    updateElement('pwn-last-updated', pwnStatus.timestamp ? formatTimestamp(pwnStatus.timestamp) : new Date().toLocaleString());

    const alertBox = document.getElementById('pwn-status-alert');
    if (alertBox) {
        if (pwnStatus.message) {
            alertBox.className = `mt-4 p-4 rounded-lg border text-sm text-gray-200 ${visuals.alertClass}`;
            alertBox.innerHTML = `
                <div class="flex items-start gap-3">
                    <div class="text-xl">${visuals.icon}</div>
                    <div>
                        <p class="font-semibold">${escapeHtml(pwnStatus.message)}</p>
                        <p class="text-xs text-gray-300 mt-1">Phase: ${formatPwnPhaseLabel(pwnStatus.phase)} | Mode: ${modeLabel}</p>
                    </div>
                </div>
            `;
            alertBox.classList.remove('hidden');
        } else {
            alertBox.classList.add('hidden');
        }
    }

    updatePwnDiscoveredCard(pwnStatus, visuals);
    updatePwnButtons();
    if (pwnStatus.installing && !wasInstalling) {
        resetPwnLogState('Installer output will stream here during installation.');
    }
    ensurePwnLogStreamingForStatus(pwnStatus);
    lastPwnState = pwnStatus.state;
}

function updatePwnButtons() {
    // Show install card only when not installed, swap card only when installed
    const installCard = document.getElementById('pwn-install-card');
    if (installCard) {
        installCard.style.display = pwnStatus.installed ? 'none' : '';
    }
    const swapCard = document.getElementById('pwn-swap-card');
    if (swapCard) {
        swapCard.style.display = pwnStatus.installed ? '' : 'none';
    }
    // Show config card only when installed
    const configCard = document.getElementById('pwn-config-card');
    if (configCard) {
        const wasHidden = configCard.style.display === 'none';
        configCard.style.display = pwnStatus.installed ? '' : 'none';
        if (wasHidden && pwnStatus.installed && !configCard._loaded) {
            configCard._loaded = true;
            loadPwnConfig();
        }
    }

    const installBtn = document.getElementById('pwn-install-btn');
    if (installBtn) {
        installBtn.textContent = pwnStatus.installing ? 'Installing...' : 'Install Pwnagotchi';
        installBtn.disabled = pwnStatus.installing;
        installBtn.classList.toggle('opacity-70', pwnStatus.installing);
        installBtn.classList.toggle('cursor-not-allowed', pwnStatus.installing);
    }

    const swapToPwnBtn = document.getElementById('pwn-swap-to-pwn-btn');
    if (swapToPwnBtn) {
        const busySwitching = pwnStatus.state === 'switching' && pwnStatus.target_mode === 'pwnagotchi';
        const pwnRunning = pwnStatus.state === 'running' && pwnStatus.target_mode === 'pwnagotchi';

        if (busySwitching || pwnRunning) {
            // Show portal link with countdown
            const portalUrl = 'http://' + window.location.hostname + ':8080';
            swapToPwnBtn.classList.remove('opacity-60', 'cursor-not-allowed');
            swapToPwnBtn.classList.add('bg-green-600', 'hover:bg-green-700');
            swapToPwnBtn.classList.remove('bg-amber-600', 'hover:bg-amber-700');

            if (!swapToPwnBtn._countdownRunning && _pwnSwapRequestedThisSession) {
                // Poll pwnagotchi portal directly - works even after Ragnar goes down.
                // mode:'no-cors' gives an opaque response but won't throw, meaning server is up.
                swapToPwnBtn._countdownRunning = true;
                let elapsed = 0;
                const MAX_WAIT = 60;
                swapToPwnBtn.disabled = true;
                swapToPwnBtn.textContent = `Waiting for Pwnagotchi... 0s`;
                const poll = setInterval(async () => {
                    elapsed++;
                    swapToPwnBtn.textContent = `Waiting for Pwnagotchi... ${elapsed}s`;
                    try {
                        await fetch(portalUrl, { mode: 'no-cors', cache: 'no-store' });
                        // Reached here = server responded (opaque ok)
                        clearInterval(poll);
                        swapToPwnBtn.disabled = false;
                        swapToPwnBtn.textContent = 'Go to Pwnagotchi Portal';
                        swapToPwnBtn.onclick = function(e) {
                            e.preventDefault();
                            window.open(portalUrl, '_blank');
                        };
                    } catch (_) {
                        // Not up yet; fall through unless timeout
                        if (elapsed >= MAX_WAIT) {
                            clearInterval(poll);
                            swapToPwnBtn.disabled = false;
                            swapToPwnBtn.textContent = 'Open Pwnagotchi Portal';
                            swapToPwnBtn.onclick = function(e) {
                                e.preventDefault();
                                window.open(portalUrl, '_blank');
                            };
                        }
                    }
                }, 1000);
            }
        } else {
            // Installed - normal swap button
            const disableSwap = pwnStatus.installing || pwnStatus.state === 'switching';
            swapToPwnBtn.disabled = disableSwap;
            swapToPwnBtn.textContent = 'Switch to Pwnagotchi';
            swapToPwnBtn.classList.toggle('opacity-60', disableSwap);
            swapToPwnBtn.classList.toggle('cursor-not-allowed', disableSwap);
            swapToPwnBtn.classList.remove('bg-green-600', 'hover:bg-green-700');
            swapToPwnBtn.onclick = null;
            swapToPwnBtn._countdownRunning = false;
            _pwnSwapRequestedThisSession = false;
        }
    }

    const swapHint = document.getElementById('pwn-swap-hint');
    if (swapHint) {
        let hint = 'Ragnar UI becomes unavailable once the service stops. Plan to reboot via SSH to come back.';
        if (pwnStatus.installing) {
            hint = 'Installer is still running. Swapping will be available once it completes.';
        } else if (pwnStatus.state === 'switching' && pwnStatus.target_mode === 'pwnagotchi') {
            hint = 'Pwnagotchi is starting up. Click the button above to open its portal once ready.';
        } else if (pwnStatus.state === 'running' && pwnStatus.target_mode === 'pwnagotchi') {
            hint = 'Pwnagotchi is running. Ragnar will shut down shortly.';
        } else if (pwnStatus.state === 'switching') {
            hint = 'Switch scheduled. Wait for the service hand-off to complete.';
        }
        swapHint.textContent = hint;
    }
}

// ---------------------------------------------------------------------------
// Pwnagotchi TOML Config — Load / Save
// ---------------------------------------------------------------------------

async function loadPwnConfig() {
    const alert = document.getElementById('pwn-config-alert');
    try {
        const response = await fetchAPI('/api/pwnagotchi/config');
        if (!response || !response.success) {
            _showPwnConfigAlert(alert, response?.error || 'Failed to load config', 'error');
            return;
        }
        const cfg = response.config;
        _setPwnCfgValue('pwn-cfg-name', cfg['main.name']);
        _setPwnCfgValue('pwn-cfg-whitelist', cfg['main.whitelist']);
        _setPwnCfgChecked('pwn-cfg-deauth', cfg['personality.deauth']);
        _setPwnCfgChecked('pwn-cfg-associate', cfg['personality.associate']);
        _setPwnCfgChecked('pwn-cfg-advertise', cfg['personality.advertise']);
        _setPwnCfgValue('pwn-cfg-min-rssi', String(cfg['personality.min_rssi']));
        _setPwnCfgValue('pwn-cfg-channels', cfg['personality.channels']);
        _setPwnCfgChecked('pwn-cfg-display-enabled', cfg['ui.display.enabled']);
        _setPwnCfgChecked('pwn-cfg-invert', cfg['ui.invert']);
        _setPwnCfgValue('pwn-cfg-rotation', String(cfg['ui.display.rotation']));
        _setPwnCfgValue('pwn-cfg-display-type', cfg['ui.display.type']);
        _setPwnCfgValue('pwn-cfg-web-user', cfg['ui.web.username']);
        _setPwnCfgValue('pwn-cfg-web-pass', cfg['ui.web.password']);
        _setPwnCfgValue('pwn-cfg-web-port', String(cfg['ui.web.port']));
        _setPwnCfgChecked('pwn-cfg-auto-tune', cfg['main.plugins.auto-tune.enabled']);
        _setPwnCfgChecked('pwn-cfg-webcfg', cfg['main.plugins.webcfg.enabled']);
        _setPwnCfgChecked('pwn-cfg-memtemp', cfg['main.plugins.memtemp.enabled']);
        _setPwnCfgChecked('pwn-cfg-grid', cfg['main.plugins.grid.enabled']);
        _setPwnCfgChecked('pwn-cfg-fix-services', cfg['main.plugins.fix_services.enabled']);
        _showPwnConfigAlert(alert, 'Configuration loaded', 'success');
        setTimeout(() => { if (alert) alert.classList.add('hidden'); }, 2000);
    } catch (error) {
        console.error('Error loading Pwnagotchi config:', error);
        _showPwnConfigAlert(alert, `Load failed: ${error.message}`, 'error');
    }
}

async function savePwnConfig() {
    const alert = document.getElementById('pwn-config-alert');
    const saveBtn = document.getElementById('pwn-config-save-btn');
    try {
        if (saveBtn) { saveBtn.disabled = true; saveBtn.textContent = 'Saving...'; }

        const config = {
            'main.name': document.getElementById('pwn-cfg-name')?.value || 'pwnagotchi',
            'main.whitelist': document.getElementById('pwn-cfg-whitelist')?.value || '',
            'personality.deauth': document.getElementById('pwn-cfg-deauth')?.checked || false,
            'personality.associate': document.getElementById('pwn-cfg-associate')?.checked || false,
            'personality.advertise': document.getElementById('pwn-cfg-advertise')?.checked || false,
            'personality.min_rssi': parseInt(document.getElementById('pwn-cfg-min-rssi')?.value || '-200', 10),
            'personality.channels': document.getElementById('pwn-cfg-channels')?.value || '',
            'ui.display.enabled': document.getElementById('pwn-cfg-display-enabled')?.checked || false,
            'ui.invert': document.getElementById('pwn-cfg-invert')?.checked || false,
            'ui.display.rotation': parseInt(document.getElementById('pwn-cfg-rotation')?.value || '180', 10),
            'ui.display.type': document.getElementById('pwn-cfg-display-type')?.value || 'waveshare_4',
            'ui.web.username': document.getElementById('pwn-cfg-web-user')?.value || 'ragnar',
            'ui.web.password': document.getElementById('pwn-cfg-web-pass')?.value || 'ragnar',
            'ui.web.port': parseInt(document.getElementById('pwn-cfg-web-port')?.value || '8080', 10),
            'main.plugins.auto-tune.enabled': document.getElementById('pwn-cfg-auto-tune')?.checked || false,
            'main.plugins.webcfg.enabled': document.getElementById('pwn-cfg-webcfg')?.checked || false,
            'main.plugins.memtemp.enabled': document.getElementById('pwn-cfg-memtemp')?.checked || false,
            'main.plugins.grid.enabled': document.getElementById('pwn-cfg-grid')?.checked || false,
            'main.plugins.fix_services.enabled': document.getElementById('pwn-cfg-fix-services')?.checked || false,
        };

        const response = await fetchAPI('/api/pwnagotchi/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ config })
        });

        if (response && response.success) {
            _showPwnConfigAlert(alert, `Saved ${response.updated?.length || 0} setting(s). Changes apply on next Pwnagotchi start.`, 'success');
            addConsoleMessage('Pwnagotchi config saved', 'info');
        } else {
            _showPwnConfigAlert(alert, response?.error || 'Save failed', 'error');
        }
    } catch (error) {
        console.error('Error saving Pwnagotchi config:', error);
        _showPwnConfigAlert(alert, `Save failed: ${error.message}`, 'error');
    } finally {
        if (saveBtn) { saveBtn.disabled = false; saveBtn.textContent = 'Save Changes'; }
    }
}

function _setPwnCfgValue(id, val) {
    const el = document.getElementById(id);
    if (el) el.value = val ?? '';
}

function _setPwnCfgChecked(id, val) {
    const el = document.getElementById(id);
    if (el) el.checked = Boolean(val);
}

function _showPwnConfigAlert(el, msg, type) {
    if (!el) return;
    el.classList.remove('hidden');
    el.textContent = msg;
    if (type === 'success') {
        el.className = 'mb-4 p-3 rounded-lg text-sm bg-green-900/40 text-green-300 border border-green-700';
    } else {
        el.className = 'mb-4 p-3 rounded-lg text-sm bg-red-900/40 text-red-300 border border-red-700';
    }
}

function _pwnBadgesHTML(net) {
    let badges = '';
    if (net.has_handshake) {
        const types = (net.handshake_types || []).join(', ');
        badges += `<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-fuchsia-900 bg-opacity-50 text-fuchsia-300" title="Handshake: ${escapeHtml(types)}">Handshake</span> `;
    }
    if (net.has_gps) {
        badges += '<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-emerald-900 bg-opacity-50 text-emerald-300" title="GPS coordinates available">GPS</span> ';
    }
    if (net.has_netjson) {
        badges += '<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-900 bg-opacity-50 text-blue-300" title="Network metadata available">NetJSON</span> ';
    }
    return badges || '<span class="text-gray-500 text-xs">-</span>';
}

function _pwnGpsHTML(net) {
    if (net.has_gps && net.gps) {
        const lat = Number(net.gps.latitude).toFixed(5);
        const lng = Number(net.gps.longitude).toFixed(5);
        return `<span class="font-mono text-emerald-300" title="Lat: ${lat}, Lng: ${lng}">${lat}, ${lng}</span>`;
    }
    return '<span class="text-gray-500">-</span>';
}

function _pwnFileSizeLabel(bytes) {
    if (!bytes || bytes <= 0) return '';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
}

function _pwnFilesHTML(files) {
    if (!Array.isArray(files) || files.length === 0) return '';
    return '<div class="flex flex-wrap gap-2 mt-2">' + files.map(f => {
        const name = escapeHtml(f.name || '');
        const size = _pwnFileSizeLabel(f.size);
        const sizeLabel = size ? ` (${size})` : '';
        const encodedName = encodeURIComponent(f.name || '');
        return `<a href="/api/pwnagotchi/download?file=${encodedName}" download
                    class="inline-flex items-center gap-1 px-2 py-1 rounded text-xs bg-slate-700 hover:bg-slate-600 text-slate-200 hover:text-white transition-colors"
                    title="Download ${name}${sizeLabel}">
                    <svg class="w-3 h-3 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg>
                    <span class="truncate max-w-[10rem]">${name}</span></a>`;
    }).join('') + '</div>';
}

function displayPwnNetworksTable(networks) {
    const container = document.getElementById('pwn-networks-table');
    if (!container) return;

    if (!Array.isArray(networks) || networks.length === 0) {
        container.innerHTML = '<p class="text-gray-400">No Pwnagotchi captures found yet.</p>';
        return;
    }

    const previewCount = 10;
    const hasMore = networks.length > previewCount;
    const previewItems = networks.slice(0, previewCount);
    const hiddenItems = hasMore ? networks.slice(previewCount) : [];

    /* --- Mobile card layout (shown < md) --- */
    function networkCardHTML(net) {
        const ssid = escapeHtml(net.ssid || 'Unknown');
        const bssid = escapeHtml(net.bssid || 'Unknown');
        const lastSeen = net.last_seen ? formatTimestamp(net.last_seen) : 'Unknown';
        return `
            <div class="bg-slate-800 bg-opacity-60 rounded-lg p-4">
                <div class="flex items-start justify-between gap-2 mb-2">
                    <span class="text-white font-semibold text-sm break-all">${ssid}</span>
                    <span class="text-xs text-gray-400 whitespace-nowrap">${lastSeen}</span>
                </div>
                <div class="text-xs text-gray-400 font-mono mb-2">${bssid}</div>
                <div class="flex flex-wrap gap-1 mb-1">${_pwnBadgesHTML(net)}</div>
                <div class="text-xs mt-1">${_pwnGpsHTML(net)}</div>
                ${_pwnFilesHTML(net.files)}
            </div>`;
    }

    /* --- Desktop table row (shown >= md) --- */
    function networkRowHTML(net) {
        const ssid = escapeHtml(net.ssid || 'Unknown');
        const bssid = escapeHtml(net.bssid || 'Unknown');
        const lastSeen = net.last_seen ? formatTimestamp(net.last_seen) : 'Unknown';
        return `
            <tr class="hover:bg-gray-700 transition-colors">
                <td class="px-4 py-3 text-sm text-white font-semibold">${ssid}</td>
                <td class="px-4 py-3 text-sm text-gray-300 font-mono">${bssid}</td>
                <td class="px-4 py-3 text-sm">${_pwnBadgesHTML(net)}</td>
                <td class="px-4 py-3 text-sm">${_pwnGpsHTML(net)}</td>
                <td class="px-4 py-3 text-sm text-gray-400 whitespace-nowrap">${lastSeen}</td>
                <td class="px-4 py-3 text-sm">${_pwnFilesHTML(net.files)}</td>
            </tr>`;
    }

    /* --- Build mobile cards --- */
    let mobileHTML = '<div class="md:hidden space-y-3">';
    previewItems.forEach(net => { mobileHTML += networkCardHTML(net); });
    if (hasMore) {
        mobileHTML += `
            <button onclick="togglePwnNetworksExpansion()"
                    class="flex items-center justify-center w-full py-3 px-4 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors text-gray-300 hover:text-white">
                <span id="pwn-networks-expand-text-m">Show ${hiddenItems.length} more</span>
                <svg id="pwn-networks-expand-arrow-m" class="w-4 h-4 ml-2 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
                </svg>
            </button>
            <div id="pwn-networks-hidden-m" class="hidden space-y-3">`;
        hiddenItems.forEach(net => { mobileHTML += networkCardHTML(net); });
        mobileHTML += '</div>';
    }
    mobileHTML += '</div>';

    /* --- Build desktop table --- */
    let tableHTML = `
        <div class="hidden md:block bg-gray-800 rounded-lg p-4">
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-700">
                    <thead>
                        <tr>
                            <th class="px-4 py-2 text-left text-xs font-medium text-gray-300 uppercase">SSID</th>
                            <th class="px-4 py-2 text-left text-xs font-medium text-gray-300 uppercase">BSSID</th>
                            <th class="px-4 py-2 text-left text-xs font-medium text-gray-300 uppercase">Data</th>
                            <th class="px-4 py-2 text-left text-xs font-medium text-gray-300 uppercase">GPS</th>
                            <th class="px-4 py-2 text-left text-xs font-medium text-gray-300 uppercase">Last Seen</th>
                            <th class="px-4 py-2 text-left text-xs font-medium text-gray-300 uppercase">Files</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-700">`;
    previewItems.forEach(net => { tableHTML += networkRowHTML(net); });
    tableHTML += '</tbody></table></div>';

    if (hasMore) {
        tableHTML += `
            <div class="mt-4">
                <button onclick="togglePwnNetworksExpansion()"
                        class="flex items-center justify-center w-full py-3 px-4 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors text-gray-300 hover:text-white">
                    <span id="pwn-networks-expand-text">Show ${hiddenItems.length} more networks</span>
                    <svg id="pwn-networks-expand-arrow" class="w-4 h-4 ml-2 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
                    </svg>
                </button>
                <div id="pwn-networks-hidden" class="hidden mt-2">
                    <div class="overflow-x-auto">
                        <table class="min-w-full divide-y divide-gray-700">
                            <tbody class="divide-y divide-gray-700">`;
        hiddenItems.forEach(net => { tableHTML += networkRowHTML(net); });
        tableHTML += '</tbody></table></div></div></div>';
    }
    tableHTML += '</div>';

    container.innerHTML = mobileHTML + tableHTML;
}

function togglePwnNetworksExpansion() {
    /* Toggle both desktop and mobile overflow sections */
    [['pwn-networks-hidden', 'pwn-networks-expand-text', 'pwn-networks-expand-arrow'],
     ['pwn-networks-hidden-m', 'pwn-networks-expand-text-m', 'pwn-networks-expand-arrow-m']
    ].forEach(([hiddenId, textId, arrowId]) => {
        const hidden = document.getElementById(hiddenId);
        const text = document.getElementById(textId);
        const arrow = document.getElementById(arrowId);
        if (!hidden) return;
        const isHidden = hidden.classList.contains('hidden');
        if (isHidden) {
            hidden.classList.remove('hidden');
            if (text) text.textContent = 'Show less';
            if (arrow) arrow.style.transform = 'rotate(180deg)';
        } else {
            hidden.classList.add('hidden');
            const count = hidden.querySelectorAll('tr, .bg-slate-800').length;
            if (text) text.textContent = `Show ${count} more`;
            if (arrow) arrow.style.transform = 'rotate(0deg)';
        }
    });
}

function updatePwnDiscoveredCard(status, visuals = null) {
    if (!status || typeof status !== 'object') return;
    const container = document.getElementById('pwn-discovered-card');
    if (!container) return;

    if (!arePwnFeaturesEnabled()) {
        container.classList.add('hidden');
        return;
    }

    const shouldShow = Boolean(status.installing || status.installed);
    if (!shouldShow) {
        container.classList.add('hidden');
        return;
    }

    container.classList.remove('hidden');
    const resolvedVisuals = visuals || getPwnStateVisuals(status);

    const badge = document.getElementById('pwn-card-badge');
    if (badge) {
        const state = (status.state || '').toLowerCase();
        if (state.includes('error') || state.includes('fail')) {
            badge.classList.add('hidden');
        } else {
            badge.classList.remove('hidden');
            badge.textContent = resolvedVisuals.badgeText;
            badge.className = `text-xs font-semibold uppercase tracking-wide px-3 py-1 rounded-full ${resolvedVisuals.badgeClass}`;
        }
    }

    const discoveries = status.discoveries || {};
    updateElement('pwn-card-network-count', String(discoveries.network_count || 0));
    updateElement('pwn-card-handshake-count', String(discoveries.networks_with_handshake || 0));
    updateElement('pwn-card-gps-count', String(discoveries.networks_with_gps || 0));
    updateElement('pwn-card-last-discovery', discoveries.last_discovery ? formatTimestamp(discoveries.last_discovery) : 'None');

    displayPwnNetworksTable(discoveries.networks || []);

    updateElement('pwn-card-updated', `Updated: ${status.timestamp ? formatTimestamp(status.timestamp) : new Date().toLocaleString()}`);
}

function resetPwnLogState(message) {
    pwnLogCursor = 0;
    pwnLogActiveFile = null;
    clearPwnLogViewer(message || 'Installer output will stream here during installation.');
    updatePwnLogPath(null);
    setPwnLogIndicator(false);
}

function clearPwnLogViewer(message) {
    const viewer = document.getElementById('pwn-log-viewer');
    const placeholder = document.getElementById('pwn-log-empty');
    if (!viewer || !placeholder) {
        return;
    }
    viewer.querySelectorAll('[data-pwn-log-line="true"]').forEach(line => line.remove());
    if (message) {
        placeholder.textContent = message;
    }
    placeholder.classList.remove('hidden');
}

function setPwnLogIndicator(active) {
    const indicator = document.getElementById('pwn-log-stream-indicator');
    if (!indicator) {
        return;
    }
    indicator.classList.toggle('hidden', !active);
}

function updatePwnLogPath(path) {
    const pathElement = document.getElementById('pwn-log-path');
    if (!pathElement) {
        return;
    }
    if (path) {
        pathElement.textContent = path;
        pathElement.classList.remove('text-gray-500');
    } else {
        pathElement.textContent = 'Log path will appear once the installer starts.';
        pathElement.classList.add('text-gray-500');
    }
}

function appendPwnLogEntries(lines = []) {
    const viewer = document.getElementById('pwn-log-viewer');
    if (!viewer || !Array.isArray(lines) || lines.length === 0) {
        return;
    }
    const placeholder = document.getElementById('pwn-log-empty');
    if (placeholder) {
        placeholder.classList.add('hidden');
    }

    const shouldStick = (viewer.scrollHeight - viewer.clientHeight - viewer.scrollTop) < 40;

    lines.forEach(line => {
        const row = document.createElement('div');
        row.dataset.pwnLogLine = 'true';
        row.className = `whitespace-pre-wrap break-words leading-snug ${getPwnLogLineClass(line)}`;
        row.textContent = line || ' ';
        viewer.appendChild(row);
    });

    trimPwnLogBuffer();

    if (shouldStick) {
        viewer.scrollTop = viewer.scrollHeight;
    }
}

function trimPwnLogBuffer(limit = 600) {
    const viewer = document.getElementById('pwn-log-viewer');
    if (!viewer) {
        return;
    }
    const lines = viewer.querySelectorAll('[data-pwn-log-line="true"]');
    if (lines.length <= limit) {
        return;
    }
    const removeCount = lines.length - limit;
    for (let i = 0; i < removeCount; i++) {
        lines[i].remove();
    }
}

function getPwnLogLineClass(line = '') {
    const normalized = line.toLowerCase();
    if (normalized.includes('error') || normalized.includes('failed') || normalized.includes('[err')) {
        return 'text-red-300';
    }
    if (normalized.includes('warn')) {
        return 'text-yellow-200';
    }
    if (normalized.includes('info') || normalized.includes('[info')) {
        return 'text-blue-200';
    }
    return 'text-gray-200';
}

function startPwnLogStreaming(options = {}) {
    const viewer = document.getElementById('pwn-log-viewer');
    if (!viewer) {
        return;
    }
    if (pwnLogStreamTimer) {
        return;
    }
    if (pwnLogStopTimeout) {
        clearTimeout(pwnLogStopTimeout);
        pwnLogStopTimeout = null;
    }
    pwnLogStreaming = true;
    setPwnLogIndicator(true);
    fetchPwnLogs({ initial: Boolean(options.initial) || pwnLogCursor === 0, silent: true });
    pwnLogStreamTimer = setInterval(() => fetchPwnLogs({ silent: true }), PWN_LOG_POLL_INTERVAL);
}

function stopPwnLogStreaming() {
    if (pwnLogStreamTimer) {
        clearInterval(pwnLogStreamTimer);
        pwnLogStreamTimer = null;
    }
    pwnLogStreaming = false;
    setPwnLogIndicator(false);
}

function schedulePwnLogStop() {
    if (pwnLogStopTimeout) {
        return;
    }
    pwnLogStopTimeout = setTimeout(() => {
        stopPwnLogStreaming();
        pwnLogStopTimeout = null;
    }, 12000);
}

function setPwnLogEmptyMessage(message) {
    const placeholder = document.getElementById('pwn-log-empty');
    if (!placeholder) {
        return;
    }
    placeholder.textContent = message;
    placeholder.classList.remove('hidden');
}

async function fetchPwnLogs(options = {}) {
    if (pwnLogFetchInFlight) {
        return;
    }

    const viewer = document.getElementById('pwn-log-viewer');
    if (!viewer) {
        return;
    }

    pwnLogFetchInFlight = true;

    try {
        const params = new URLSearchParams();
        if (pwnLogCursor > 0 && !options.initial) {
            params.set('cursor', pwnLogCursor.toString());
        } else {
            params.set('tail', '8192');
        }

        const result = await fetchAPI(`/api/pwnagotchi/logs?${params.toString()}`);

        if (!result || result.success === false) {
            if (!options.silent) {
                setPwnLogEmptyMessage((result && result.error) ? result.error : 'Installer log not available yet');
            }
            if (!result || !result.installing) {
                schedulePwnLogStop();
            }
            return;
        }

        if (typeof result.cursor === 'number') {
            pwnLogCursor = result.cursor;
        }

        if (result.file && result.file !== pwnLogActiveFile) {
            pwnLogActiveFile = result.file;
            clearPwnLogViewer('Streaming installer output…');
            updatePwnLogPath(result.file);
        }

        if (Array.isArray(result.entries) && result.entries.length > 0) {
            appendPwnLogEntries(result.entries);
        } else if (!options.silent && !pwnLogStreaming) {
            setPwnLogEmptyMessage('No installer activity yet.');
        }

        if (!result.installing) {
            schedulePwnLogStop();
        }

    } catch (error) {
        console.error('Error fetching Pwnagotchi logs:', error);
        if (!options.silent) {
            setPwnLogEmptyMessage(`Failed to load installer log (${error.message})`);
        }
    } finally {
        pwnLogFetchInFlight = false;
    }
}

function ensurePwnLogStreamingForStatus(status) {
    if (!status) {
        return;
    }

    if (status.log_file && status.log_file !== pwnLogActiveFile) {
        pwnLogActiveFile = status.log_file;
        updatePwnLogPath(status.log_file);
    }

    if (status.installing) {
        setPwnStatusPollInterval(PWN_STATUS_FAST_INTERVAL);
        startPwnLogStreaming({ initial: pwnLogCursor === 0 });
    } else {
        setPwnStatusPollInterval(PWN_STATUS_POLL_INTERVAL);
        if (pwnLogStreaming) {
            schedulePwnLogStop();
        }
    }
}

function getPwnStateVisuals(status) {
    const state = (status.state || 'not_installed').toLowerCase();
    if (state.includes('fail') || state.includes('error')) {
        return {
            badgeText: 'Error',
            badgeClass: 'bg-red-700 text-red-100',
            alertClass: 'border-red-500 bg-red-900/30',
            icon: '⚠️'
        };
    }
    if (status.installing || ['preflight', 'dependencies', 'python', 'installing'].includes(state)) {
        return {
            badgeText: 'Installing',
            badgeClass: 'bg-yellow-700 text-yellow-100',
            alertClass: 'border-yellow-500 bg-yellow-900/30',
            icon: '⏳'
        };
    }
    if (state === 'switching') {
        return {
            badgeText: 'Switching',
            badgeClass: 'bg-orange-700 text-orange-100',
            alertClass: 'border-orange-500 bg-orange-900/30',
            icon: '🔄'
        };
    }
    if (state === 'running') {
        return {
            badgeText: 'Running',
            badgeClass: 'bg-green-700 text-green-100',
            alertClass: 'border-green-500 bg-green-900/30',
            icon: '✅'
        };
    }
    if (state === 'installed') {
        return {
            badgeText: 'Installed',
            badgeClass: 'bg-blue-700 text-blue-100',
            alertClass: 'border-blue-500 bg-blue-900/30',
            icon: 'ℹ️'
        };
    }
    return {
        badgeText: 'Not Installed',
        badgeClass: 'bg-slate-700 text-slate-200',
        alertClass: 'border-slate-700 bg-slate-900',
        icon: 'ℹ️'
    };
}

function formatPwnStateLabel(state) {
    if (!state) {
        return 'Unknown';
    }
    return state.replace(/_/g, ' ').replace(/\b\w/g, char => char.toUpperCase());
}

function formatPwnModeLabel(mode) {
    return mode === 'pwnagotchi' ? 'Pwnagotchi' : 'Ragnar';
}

function formatPwnPhaseLabel(phase) {
    if (!phase) {
        return 'Idle';
    }
    return phase.replace(/_/g, ' ').replace(/\b\w/g, char => char.toUpperCase());
}

async function handlePwnInstallClick() {
    if (pwnStatus.installing) {
        addConsoleMessage('Pwnagotchi installer already running', 'warning');
        return;
    }

    const installBtn = document.getElementById('pwn-install-btn');
    if (installBtn) {
        installBtn.disabled = true;
        installBtn.textContent = 'Starting installer...';
        installBtn.classList.add('opacity-70', 'cursor-not-allowed');
    }

    resetPwnLogState('Installer requested. Waiting for output...');
    startPwnLogStreaming({ initial: true });

    try {
        const result = await postPwnAPI('/api/pwnagotchi/install', {});
        addConsoleMessage('Pwnagotchi installer started', 'success');
        if (result && result.status) {
            updatePwnagotchiUI(result.status);
        } else {
            refreshPwnagotchiStatus({ silent: true });
        }
    } catch (error) {
        console.error('Failed to start Pwnagotchi installer:', error);
        addConsoleMessage(`Install failed: ${error.message}`, 'error');
        stopPwnLogStreaming();
        setPwnLogEmptyMessage('Installer failed to start. Check Ragnar logs for details.');
    } finally {
        updatePwnButtons();
    }
}

async function handlePwnSwap(targetMode) {
    const normalized = targetMode === 'pwnagotchi' ? 'pwnagotchi' : 'ragnar';

    if (normalized === 'pwnagotchi' && !pwnStatus.installed) {
        addConsoleMessage('Install Pwnagotchi before swapping', 'warning');
        return;
    }

    const buttonId = normalized === 'pwnagotchi' ? 'pwn-swap-to-pwn-btn' : 'pwn-swap-to-ragnar-btn';
    const button = document.getElementById(buttonId);
    if (button) {
        button.disabled = true;
        button.textContent = 'Scheduling switch...';
        button.classList.add('opacity-60', 'cursor-not-allowed');
    }

    try {
        const result = await postPwnAPI('/api/pwnagotchi/swap', { target: normalized });
        if (normalized === 'pwnagotchi') _pwnSwapRequestedThisSession = true;
        const message = (result && result.message) ? result.message : `Switch scheduled to ${formatPwnModeLabel(normalized)}`;
        addConsoleMessage(message, 'info');
        if (result && result.status) {
            updatePwnagotchiUI(result.status);
        } else {
            refreshPwnagotchiStatus({ silent: true });
        }
    } catch (error) {
        console.error('Failed to schedule Pwnagotchi swap:', error);
        addConsoleMessage(`Swap failed: ${error.message}`, 'error');
    } finally {
        updatePwnButtons();
    }
}

async function postPwnAPI(endpoint, payload = {}) {
    const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
    });

    let data = null;
    try {
        data = await response.json();
    } catch (error) {
        data = null;
    }

    if (!response.ok || (data && data.success === false)) {
        const errorMessage = data && (data.error || data.message)
            ? (data.error || data.message)
            : `Request failed (${response.status})`;
        throw new Error(errorMessage);
    }

    return data || { success: true };
}

async function loadConnectData() {
    try {
        // Load Wi-Fi interfaces first so dropdowns are populated before status updates
        await loadWifiInterfaces();

        // Refresh Wi-Fi and Bluetooth status in parallel to shorten the loading time
        console.log('Loading connect tab, refreshing connectivity status...');
        await Promise.all([
            refreshWifiStatus(),
            refreshEthernetStatus(),
            refreshBluetoothStatus()
        ]);
    } catch (error) {
        console.error('Error loading connect data:', error);
    }
}

async function loadFilesData() {
    try {
        displayDirectoryTree();
        loadFiles('/');
        // Don't automatically load images - user must click "Load Images" button
    } catch (error) {
        console.error('Error loading files data:', error);
    }
}

// ============================================================================
// PWNAGOTCHI VISIBILITY MANAGEMENT
// ============================================================================

function arePwnFeaturesEnabled() {
    return localStorage.getItem('pwnagotchi-enabled') === 'true';
}

function applyPwnVisibilityPreference(isEnabled) {
    const pwnSection = document.getElementById('pwnagotchi-section');
    if (pwnSection) {
        pwnSection.style.display = isEnabled ? 'block' : 'none';
    }
    updatePwnDiscoveredCard(pwnStatus);
}

function togglePwnagotchiVisibility() {
    const checkbox = document.getElementById('pwnagotchi-enabled');
    if (!checkbox) {
        return;
    }

     if (checkbox.disabled) {
         checkbox.checked = false;
         return;
     }

    const isEnabled = checkbox.checked;
    localStorage.setItem('pwnagotchi-enabled', isEnabled ? 'true' : 'false');
    applyPwnVisibilityPreference(isEnabled);
}

function initializePwnagotchiVisibility() {
    const checkbox = document.getElementById('pwnagotchi-enabled');
    if (!checkbox) {
        return;
    }

    const isEnabled = arePwnFeaturesEnabled();
    checkbox.checked = isEnabled;
    applyPwnVisibilityPreference(isEnabled);
}

function updatePwnToggleAvailability(isHeadless) {
    headlessMode = Boolean(isHeadless);
    const checkbox = document.getElementById('pwnagotchi-enabled');
    if (!checkbox) {
        return;
    }

    const wrapper = document.getElementById('pwn-toggle-wrapper');
    const warning = document.getElementById('pwn-headless-warning');

    if (headlessMode) {
        if (checkbox.checked) {
            checkbox.checked = false;
            localStorage.setItem('pwnagotchi-enabled', 'false');
            applyPwnVisibilityPreference(false);
        }
        checkbox.disabled = true;
        checkbox.setAttribute('aria-disabled', 'true');
        if (wrapper) {
            wrapper.classList.add('cursor-not-allowed', 'opacity-60', 'pointer-events-none');
        }
        if (warning) {
            warning.classList.remove('hidden');
        }
    } else {
        checkbox.disabled = false;
        checkbox.removeAttribute('aria-disabled');
        if (wrapper) {
            wrapper.classList.remove('cursor-not-allowed', 'opacity-60', 'pointer-events-none');
        }
        if (warning) {
            warning.classList.add('hidden');
        }
    }
}

// ============================================================================
// HEADLESS MODE DETECTION AND MANAGEMENT
// ============================================================================

/**
 * Detect and handle headless mode (server installations without a display)
 * Headless mode hides display-related UI elements
 */
async function handleHeadlessMode() {
    try {
        const response = await fetch('/api/system/headless');
        const data = await response.json();
        
        const isHeadless = data.headless === true || data.is_headless === true;
        headlessMode = isHeadless;
        
        if (isHeadless) {
            console.log('[Headless] Headless mode detected - hiding Display UI elements');
            applyHeadlessVisibility(true);
        } else {
            console.log('[Headless] Display mode detected - Display UI elements visible');
            applyHeadlessVisibility(false);
        }
        
        // Update Pwnagotchi toggle availability based on headless mode
        updatePwnToggleAvailability(isHeadless);
        
    } catch (error) {
        // If endpoint doesn't exist or fails, assume not headless (default behavior)
        console.log('[Headless] Detection failed, assuming display mode:', error.message);
        headlessMode = false;
        applyHeadlessVisibility(false);
    }
}

/**
 * Apply headless mode visibility settings to UI elements
 * @param {boolean} isHeadless - Whether the system is in headless mode
 */
function applyHeadlessVisibility(isHeadless) {
    // Find all elements that require a display
    const displayElements = document.querySelectorAll('.requires-display');
    
    if (isHeadless) {
        // Hide all display-related elements
        displayElements.forEach(el => {
            el.style.display = 'none';
            el.setAttribute('data-hidden-by-headless', 'true');
        });
        
        console.log(`[Headless] Hidden ${displayElements.length} Display UI elements`);
        
        // If user is currently on Display tab, redirect to dashboard
        if (currentTab === 'epaper') {
            console.log('[Headless] Redirecting from Display tab to dashboard');
            showTab('dashboard');
        }
    } else {
        // Show all display-related elements
        displayElements.forEach(el => {
            if (el.getAttribute('data-hidden-by-headless') === 'true') {
                el.style.display = '';
                el.removeAttribute('data-hidden-by-headless');
            }
        });
        
        console.log(`[Headless] Restored ${displayElements.length} Display UI elements`);
    }
    if (window._updateNavMode) window._updateNavMode();
}

// ============================================================================
// HARDWARE PROFILE MANAGEMENT FUNCTIONS
// ============================================================================

async function loadHardwareProfiles() {
    try {
        const profiles = await fetchAPI('/api/config/hardware-profiles');
        const select = document.getElementById('hardware-profile-select');
        const applyBtn = document.getElementById('apply-profile-btn');
        
        if (!select) return;
        
        // Clear existing options
        select.innerHTML = '<option value="">Select a hardware profile...</option>';
        
        // Store profiles data for later use
        window.hardwareProfiles = profiles;
        
        // Populate dropdown options
        for (const [profileId, profile] of Object.entries(profiles)) {
            const option = document.createElement('option');
            option.value = profileId;
            option.textContent = `${profile.name} (${profile.ram}MB RAM)`;
            select.appendChild(option);
        }
        
        // Add change event listener to show profile details
        select.addEventListener('change', function() {
            const selectedProfileId = this.value;
            const applyBtn = document.getElementById('apply-profile-btn');
            
            if (selectedProfileId && profiles[selectedProfileId]) {
                showProfileDetails(profiles[selectedProfileId]);
                applyBtn.disabled = false;
            } else {
                hideProfileDetails();
                applyBtn.disabled = true;
            }
        });
        
    } catch (error) {
        console.error('Error loading hardware profiles:', error);
        addConsoleMessage('Failed to load hardware profiles', 'error');
        
        const select = document.getElementById('hardware-profile-select');
        if (select) {
            select.innerHTML = '<option value="">Error loading profiles</option>';
        }
    }
}

function showProfileDetails(profile) {
    const detailsDiv = document.getElementById('profile-details');
    if (!detailsDiv) return;
    
    document.getElementById('profile-description').textContent = profile.description || 'No description available';
    document.getElementById('profile-ram').textContent = `${profile.ram}MB`;
    document.getElementById('profile-threads').textContent = profile.settings.scanner_max_threads || 'N/A';
    document.getElementById('profile-concurrent').textContent = profile.settings.orchestrator_max_concurrent || 'N/A';
    document.getElementById('profile-speed').textContent = profile.settings.nmap_scan_aggressivity || 'N/A';
    
    detailsDiv.classList.remove('hidden');
}

function hideProfileDetails() {
    const detailsDiv = document.getElementById('profile-details');
    if (detailsDiv) {
        detailsDiv.classList.add('hidden');
    }
}

async function applySelectedProfile() {
    const select = document.getElementById('hardware-profile-select');
    const selectedProfileId = select.value;
    
    if (!selectedProfileId) {
        addConsoleMessage('Please select a hardware profile first', 'warning');
        return;
    }
    
    await confirmApplyProfile(selectedProfileId, window.hardwareProfiles[selectedProfileId]);
}

async function detectAndApplyHardware() {
    try {
        addConsoleMessage('Detecting hardware...', 'info');
        const infoDiv = document.getElementById('hardware-detection-info');
        infoDiv.innerHTML = '<span class="text-Ragnar-400">🔍 Detecting hardware...</span>';
        
        const hardware = await fetchAPI('/api/config/detect-hardware');
        
        // Display detection results
        infoDiv.innerHTML = `
            <div class="space-y-2">
                <div class="flex justify-between">
                    <span class="text-gray-400">Detected Model:</span>
                    <span class="text-white font-semibold">${hardware.model}</span>
                </div>
                <div class="flex justify-between">
                    <span class="text-gray-400">Total RAM:</span>
                    <span class="text-white font-semibold">${hardware.ram_gb} GB (${hardware.ram_mb} MB)</span>
                </div>
                <div class="flex justify-between">
                    <span class="text-gray-400">CPU Cores:</span>
                    <span class="text-white font-semibold">${hardware.cpu_count}</span>
                </div>
                <div class="flex justify-between">
                    <span class="text-gray-400">Recommended Profile:</span>
                    <span class="text-Ragnar-400 font-semibold">${hardware.recommended_profile}</span>
                </div>
            </div>
        `;
        
        addConsoleMessage(`Detected: ${hardware.model} with ${hardware.ram_gb}GB RAM`, 'success');
        
        // Auto-apply the recommended profile
        if (hardware.recommended_profile) {
            addConsoleMessage(`Applying recommended profile: ${hardware.recommended_profile}`, 'info');
            await applyHardwareProfile(hardware.recommended_profile);
        }
        
    } catch (error) {
        console.error('Error detecting hardware:', error);
        addConsoleMessage('Failed to detect hardware', 'error');
        document.getElementById('hardware-detection-info').innerHTML = 
            '<span class="text-red-400">❌ Failed to detect hardware. Try manual selection.</span>';
    }
}

async function confirmApplyProfile(profileId, profile) {
    if (confirm(`Apply profile "${profile.name}"?\n\n${profile.description}\n\nThis will update system resource settings and requires a service restart to take full effect.`)) {
        await applyHardwareProfile(profileId);
    }
}

async function applyHardwareProfile(profileId) {
    try {
        addConsoleMessage(`Applying hardware profile: ${profileId}...`, 'info');
        
        const result = await postAPI('/api/config/apply-profile', { profile_id: profileId });
        
        if (result.success) {
            addConsoleMessage(`✅ Profile applied: ${result.profile.name}`, 'success');
            addConsoleMessage('⚠️ Service restart required for changes to take effect', 'warning');
            
            // Update current profile display
            displayCurrentProfile({
                hardware_profile: profileId,
                hardware_profile_name: result.profile.name,
                hardware_profile_applied: result.profile.hardware_profile_applied || new Date().toISOString()
            });
            
            // Show restart prompt
            if (confirm('Hardware profile applied successfully!\n\nRestart the Ragnar service now to apply changes?')) {
                await restartService();
            }
        } else {
            addConsoleMessage('❌ Failed to apply profile', 'error');
        }
        
    } catch (error) {
        console.error('Error applying hardware profile:', error);
        addConsoleMessage(`Failed to apply hardware profile: ${error.message}`, 'error');
    }
}

function displayCurrentProfile(config) {
    const statusDiv = document.getElementById('current-profile-status');
    const nameSpan = document.getElementById('current-profile-name');
    const appliedSpan = document.getElementById('current-profile-applied');
    
    if (config.hardware_profile && config.hardware_profile_name) {
        statusDiv.classList.remove('hidden');
        nameSpan.textContent = config.hardware_profile_name;
        
        if (config.hardware_profile_applied) {
            const appliedDate = new Date(config.hardware_profile_applied);
            appliedSpan.textContent = `Applied: ${appliedDate.toLocaleString()}`;
        } else {
            appliedSpan.textContent = 'Applied recently';
        }
    } else {
        statusDiv.classList.add('hidden');
    }
}

// ============================================================================
// SYSTEM MANAGEMENT FUNCTIONS
// ============================================================================

function updateReleaseGateState(payload = {}) {
    const enabled = Boolean(payload && payload.enabled);
    const incomingMessage = typeof (payload && payload.message) === 'string' ? payload.message.trim() : '';
    const message = incomingMessage || RELEASE_GATE_DEFAULT_MESSAGE;
    releaseGateState = { enabled, message };

    const updateBtn = document.getElementById('update-btn');
    if (updateBtn) {
        updateBtn.dataset.releaseGate = enabled ? 'true' : 'false';
        ['ring-2', 'ring-yellow-500/50', 'ring-offset-2', 'ring-offset-slate-900'].forEach(cls => {
            if (enabled) {
                updateBtn.classList.add(cls);
            } else {
                updateBtn.classList.remove(cls);
            }
        });
    }

    if (!enabled && releaseGateResolver) {
        const resolver = releaseGateResolver;
        releaseGateResolver = null;
        releaseGatePendingPromise = null;
        hideReleaseGateModal();
        resolver(true);
    }
}

function showReleaseGateModal() {
    const modal = document.getElementById('release-gate-modal');
    const messageEl = document.getElementById('release-gate-modal-message');
    if (messageEl) {
        messageEl.textContent = releaseGateState.message || RELEASE_GATE_DEFAULT_MESSAGE;
    }
    if (modal) {
        modal.classList.remove('hidden');
        modal.classList.add('flex');
    }
}

function hideReleaseGateModal() {
    const modal = document.getElementById('release-gate-modal');
    if (modal) {
        modal.classList.add('hidden');
        modal.classList.remove('flex');
    }
}

function ensureReleaseGateAcknowledged() {
    if (!releaseGateState.enabled) {
        return Promise.resolve(true);
    }

    if (releaseGatePendingPromise) {
        showReleaseGateModal();
        return releaseGatePendingPromise;
    }

    releaseGatePendingPromise = new Promise(resolve => {
        releaseGateResolver = resolve;
        showReleaseGateModal();
    });
    return releaseGatePendingPromise;
}

function handleReleaseGateDecision(allowUpdate) {
    hideReleaseGateModal();
    if (releaseGateResolver) {
        const resolver = releaseGateResolver;
        releaseGateResolver = null;
        releaseGatePendingPromise = null;
        resolver(Boolean(allowUpdate));
    }
}

async function checkForUpdates() {
    try {
        const updateBtn = document.getElementById('update-btn');
        const updateStatusEl = document.getElementById('update-status');

        if (updateBtn) {
            updateBtn.onclick = performUpdate;
            updateBtn.disabled = true;
            updateBtn.className = 'w-full bg-gray-600 text-white py-2 px-4 rounded cursor-not-allowed';
        }
        updateElement('update-btn-text', 'Update System');

        updateElement('update-status', 'Checking...');
        if (updateStatusEl) {
            updateStatusEl.className = 'text-sm px-2 py-1 rounded bg-gray-700 text-gray-300';
        }
        updateElement('update-info', 'Checking for updates...');
        addConsoleMessage('Checking for system updates...', 'info');
        
        const data = await fetchAPI('/api/system/check-updates');
        const gitStatus = data.git_status || {};
        
        // Debug logging
        console.log('Update check response:', data);
        addConsoleMessage(`Debug: Repo path: ${data.repo_path}`, 'info');
        addConsoleMessage(`Debug: Current commit: ${data.current_commit}`, 'info');
        addConsoleMessage(`Debug: Latest commit: ${data.latest_commit}`, 'info');
        addConsoleMessage(`Debug: Commits behind: ${data.commits_behind}`, 'info');
        
        let infoMessage = '';
        if (data.updates_available && data.commits_behind > 0) {
            infoMessage = `${data.commits_behind} commits behind. Latest: ${data.latest_commit || 'Unknown'}`;
            updateElement('update-status', 'Update Available');
            if (updateStatusEl) {
                updateStatusEl.className = 'text-sm px-2 py-1 rounded bg-orange-700 text-orange-300';
            }
            if (updateBtn) {
                updateBtn.disabled = false;
                updateBtn.className = 'w-full bg-green-600 hover:bg-green-700 text-white py-2 px-4 rounded transition-colors';
            }
            addConsoleMessage(`Update available: ${data.commits_behind} commits behind`, 'warning');
        } else {
            infoMessage = 'System is up to date';
            updateElement('update-status', 'Up to Date');
            if (updateStatusEl) {
                updateStatusEl.className = 'text-sm px-2 py-1 rounded bg-green-700 text-green-300';
            }
            if (updateBtn) {
                updateBtn.disabled = true;
                updateBtn.className = 'w-full bg-gray-600 text-white py-2 px-4 rounded cursor-not-allowed';
            }
            addConsoleMessage('System is up to date', 'success');
        }

        const localStateMessages = [];
        const modifiedCount = Array.isArray(gitStatus.modified_files) ? gitStatus.modified_files.length : 0;

        if (gitStatus.has_conflicts) {
            localStateMessages.push('Local merge conflicts detected');
        } else if (gitStatus.is_dirty) {
            localStateMessages.push(`${modifiedCount} local change${modifiedCount === 1 ? '' : 's'}`);
        }

        if (gitStatus.status_error) {
            localStateMessages.push(`git status error: ${gitStatus.status_error}`);
        }

        updateElement('update-info', infoMessage);

        if (gitStatus.has_conflicts) {
            if (updateBtn) {
                updateBtn.disabled = false;
                updateBtn.onclick = resolveGitConflicts;
                updateBtn.className = 'w-full bg-red-600 hover:bg-red-700 text-white py-2 px-4 rounded transition-colors';
                updateElement('update-btn-text', 'Resolve Git Conflicts');
            }
            updateElement('update-status', 'Local Conflict');
            if (updateStatusEl) {
                updateStatusEl.className = 'text-sm px-2 py-1 rounded bg-red-700 text-red-200';
            }
            addConsoleMessage('Local git conflicts detected. Click "Resolve Git Conflicts" to reset and update.', 'warning');
            return;
        }

        if (data.updates_available && data.commits_behind > 0 && updateBtn) {
            if (gitStatus.is_dirty) {
                updateBtn.onclick = autoStashAndUpdate;
                updateBtn.className = 'w-full bg-green-600 hover:bg-green-700 text-white py-2 px-4 rounded transition-colors';
                updateElement('update-btn-text', 'Update System');
                addConsoleMessage('Local edits detected. Ragnar will handle them automatically during the update.', 'info');
            } else {
                updateBtn.onclick = performUpdate;
                updateElement('update-btn-text', 'Update System');
            }
        }
        
    } catch (error) {
        console.error('Error checking for updates:', error);
        updateElement('update-status', 'Error');
        document.getElementById('update-status').className = 'text-sm px-2 py-1 rounded bg-red-700 text-red-300';
        
        // Check if it's a git safe directory error
        if (error.message && error.message.includes('safe.directory')) {
            updateElement('update-info', 'Git safe directory issue detected');
            addConsoleMessage('Git safe directory error detected. Click the Fix Git button.', 'error');
            
            // Show fix git button
            const updateBtn = document.getElementById('update-btn');
            updateBtn.textContent = 'Fix Git Config';
            updateBtn.disabled = false;
            updateBtn.className = 'w-full bg-yellow-600 hover:bg-yellow-700 text-white py-2 px-4 rounded transition-colors';
            updateBtn.onclick = fixGitConfig;
        } else {
            updateElement('update-info', 'Failed to check for updates');
            addConsoleMessage(`Failed to check for updates: ${error.message}`, 'error');
        }
    }
}

async function fixGitConfig() {
    try {
        updateElement('update-btn-text', 'Fixing...');
        const updateBtn = document.getElementById('update-btn');
        updateBtn.disabled = true;
        
        addConsoleMessage('Fixing git configuration...', 'info');
        
        const result = await postAPI('/api/system/fix-git', {});
        
        if (result.success) {
            addConsoleMessage('Git configuration fixed successfully', 'success');
            
            // Reset button and retry update check
            updateBtn.textContent = 'Update System';
            updateBtn.onclick = performUpdate;
            
            // Retry update check
            setTimeout(() => {
                checkForUpdates();
            }, 1000);
        } else {
            addConsoleMessage(`Failed to fix git configuration: ${result.error}`, 'error');
            updateBtn.disabled = false;
            updateElement('update-btn-text', 'Fix Git Config');
        }
        
    } catch (error) {
        console.error('Error fixing git config:', error);
        addConsoleMessage('Failed to fix git configuration', 'error');
        const updateBtn = document.getElementById('update-btn');
        updateBtn.disabled = false;
        updateElement('update-btn-text', 'Fix Git Config');
    }
}

async function resolveGitConflicts() {
    const updateBtn = document.getElementById('update-btn');
    try {
        updateBtn.disabled = true;
        updateElement('update-btn-text', 'Resolving...');
        addConsoleMessage('Resolving git conflicts and pulling latest update...', 'info');

        const result = await postAPI('/api/system/resolve-conflicts', {});

        if (result.success) {
            addConsoleMessage('Conflicts resolved and update applied. Restarting...', 'success');
            if (result.warnings && result.warnings.length) {
                result.warnings.forEach(w => addConsoleMessage(w, 'warning'));
            }
            updateElement('update-btn-text', 'Done');
        } else {
            addConsoleMessage(`Failed to resolve conflicts: ${result.error}`, 'error');
            updateBtn.disabled = false;
            updateElement('update-btn-text', 'Resolve Git Conflicts');
        }
    } catch (error) {
        console.error('Error resolving git conflicts:', error);
        addConsoleMessage('Failed to resolve git conflicts', 'error');
        updateBtn.disabled = false;
        updateElement('update-btn-text', 'Resolve Git Conflicts');
    }
}

async function performUpdate() {
    const gateApproved = await ensureReleaseGateAcknowledged();
    if (!gateApproved) {
        addConsoleMessage('Update postponed until the release window opens.', 'info');
        return;
    }

    if (!confirm('This will update the system and restart the service. Continue?')) {
        return;
    }
    
    try {
        updateElement('update-btn-text', 'Update now');
        const updateBtn = document.getElementById('update-btn');
        updateBtn.disabled = true;
        updateBtn.className = 'w-full bg-gray-600 text-white py-2 px-4 rounded cursor-not-allowed';
        
        addConsoleMessage('Starting system update...', 'info');
        
        const data = await postAPI('/api/system/update', {});
        
        if (data.success) {
            addConsoleMessage('Update completed successfully', 'success');
            addConsoleMessage('System will restart automatically...', 'info');
            updateElement('update-info', 'Update completed. System restarting...');
            
            // Wait for service restart and verify it's back up
            setTimeout(async () => {
                await verifyServiceRestart();
            }, 10000); // Start checking after 10 seconds
        } else {
            addConsoleMessage(`Update failed: ${data.error || 'Unknown error'}`, 'error');
            updateElement('update-btn-text', 'Update System');
            updateBtn.disabled = false;
            updateBtn.className = 'w-full bg-green-600 hover:bg-green-700 text-white py-2 px-4 rounded transition-colors';
        }
        
    } catch (error) {
        console.error('Error performing update:', error);
        addConsoleMessage('Update failed due to network error', 'error');
        updateElement('update-btn-text', 'Update System');
        const updateBtn = document.getElementById('update-btn');
        updateBtn.disabled = false;
        updateBtn.className = 'w-full bg-green-600 hover:bg-green-700 text-white py-2 px-4 rounded transition-colors';
    }
}

async function autoStashAndUpdate() {
    const gateApproved = await ensureReleaseGateAcknowledged();
    if (!gateApproved) {
        addConsoleMessage('Update postponed until the release window opens.', 'info');
        return;
    }

    if (!confirm('This will update the system and restart the service. Continue?')) {
        return;
    }

    const updateBtn = document.getElementById('update-btn');

    const setButtonState = (busy, label) => {
        if (!updateBtn) {
            return;
        }
        updateBtn.disabled = !!busy;
        updateBtn.className = busy
            ? 'w-full bg-gray-600 text-white py-2 px-4 rounded cursor-wait'
            : 'w-full bg-green-600 hover:bg-green-700 text-white py-2 px-4 rounded transition-colors';
        updateElement('update-btn-text', label);
    };

    try {
        setButtonState(true, 'Updating...');
        addConsoleMessage('Applying update...', 'info');

        const response = await postAPI('/api/system/stash-update', {});

        if (response.success) {
            addConsoleMessage('Update completed successfully.', 'success');
            addConsoleMessage('System will restart automatically...', 'info');
            updateElement('update-info', 'Update applied. System restarting...');

            if (updateBtn) {
                updateBtn.className = 'w-full bg-gray-600 text-white py-2 px-4 rounded cursor-not-allowed';
                updateElement('update-btn-text', 'Updating...');
            }

            setTimeout(async () => {
                await verifyServiceRestart();
            }, 10000);
        } else {
            throw new Error(response.error || 'Update failed');
        }
    } catch (error) {
        console.error('Auto update error:', error);
        addConsoleMessage(`Update failed: ${error.message}`, 'error');
        setButtonState(false, 'Update System');
        updateElement('update-info', 'Update failed. Fix issues and retry.');
    }
}

async function verifyServiceRestart() {
    let attempts = 0;
    const maxAttempts = 12; // Try for up to 2 minutes (12 attempts * 10 seconds)
    
    addConsoleMessage('Verifying service is back online...', 'info');
    updateElement('update-info', 'Verifying service restart...');
    
    const checkService = async () => {
        attempts++;
        
        try {
            // Try to fetch the stats endpoint as a health check
            const response = await networkAwareFetch('/api/stats', {
                method: 'GET',
                headers: { 'Content-Type': 'application/json' },
                timeout: 5000
            });
            
            if (response.ok) {
                // Service is back up
                addConsoleMessage('✅ Service verified online after update', 'success');
                updateElement('update-info', 'Update completed successfully. Service is online.');
                
                // Reset the update button
                const updateBtn = document.getElementById('update-btn');
                updateElement('update-btn-text', 'Update System');
                updateBtn.disabled = false;
                updateBtn.className = 'w-full bg-green-600 hover:bg-green-700 text-white py-2 px-4 rounded transition-colors';
                
                // Check for updates to refresh status
                setTimeout(() => {
                    checkForUpdates();
                }, 5000);
                
                return; // Success, exit the checking loop
            } else {
                throw new Error(`HTTP ${response.status}`);
            }
        } catch (error) {
            console.log(`Service check attempt ${attempts}/${maxAttempts} failed:`, error.message);
            
            if (attempts >= maxAttempts) {
                // Max attempts reached, service might not have restarted properly
                addConsoleMessage('⚠️ Service restart verification timeout. Manual check may be needed.', 'warning');
                updateElement('update-info', 'Update completed, but service verification timed out.');
                
                // Reset the update button
                const updateBtn = document.getElementById('update-btn');
                updateElement('update-btn-text', 'Update System');
                updateBtn.disabled = false;
                updateBtn.className = 'w-full bg-green-600 hover:bg-green-700 text-white py-2 px-4 rounded transition-colors';
                
                return; // Exit the checking loop
            }
            
            // Continue checking
            addConsoleMessage(`Service check ${attempts}/${maxAttempts} - waiting for restart...`, 'info');
            setTimeout(checkService, 10000); // Check again in 10 seconds
        }
    };
    
    // Start the checking process after 10s
    checkService();
}

async function checkForUpdatesQuiet() {
    try {
        const data = await fetchAPI('/api/system/check-updates');
        
        if (data.updates_available && data.commits_behind > 0) {
            // Show update notification in console if not on config tab
            if (currentTab !== 'config') {
                addConsoleMessage(`🔄 System update available: ${data.commits_behind} commits behind`, 'warning');
            }
            
            // Add visual indicator to config tab
            const configTabBtn = document.querySelector('[data-tab="config"]');
            if (configTabBtn && !configTabBtn.querySelector('.update-indicator')) {
                const indicator = document.createElement('span');
                indicator.className = 'update-indicator absolute -top-1 -right-1 w-3 h-3 bg-orange-500 rounded-full pulse-glow';
                configTabBtn.style.position = 'relative';
                configTabBtn.appendChild(indicator);
            }
        } else {
            // Remove update indicator if up to date
            const configTabBtn = document.querySelector('[data-tab="config"]');
            const indicator = configTabBtn?.querySelector('.update-indicator');
            if (indicator) {
                indicator.remove();
            }
        }
        
    } catch (error) {
        // Silently fail for background checks
        console.debug('Background update check failed:', error);
    }
}

async function restartService() {
    if (!confirm('This will restart the Ragnar service. The web interface may be temporarily unavailable. Continue?')) {
        return;
    }
    
    try {
        addConsoleMessage('Restarting Ragnar service...', 'info');
        updateElement('service-status', 'Restarting...');
        document.getElementById('service-status').className = 'text-sm px-2 py-1 rounded bg-yellow-700 text-yellow-300';
        
        const data = await postAPI('/api/system/restart-service', {});
        
        if (data.success) {
            addConsoleMessage('Service restart initiated', 'success');
            addConsoleMessage('Service will be back online shortly...', 'info');
            
            // Update status after delay
            setTimeout(() => {
                updateElement('service-status', 'Running');
                document.getElementById('service-status').className = 'text-sm px-2 py-1 rounded bg-green-700 text-green-300';
                addConsoleMessage('Service restart completed', 'success');
            }, 10000); // 10 seconds delay
        } else {
            addConsoleMessage(`Service restart failed: ${data.error || 'Unknown error'}`, 'error');
            updateElement('service-status', 'Error');
            document.getElementById('service-status').className = 'text-sm px-2 py-1 rounded bg-red-700 text-red-300';
        }
        
    } catch (error) {
        console.error('Error restarting service:', error);
        addConsoleMessage('Failed to restart service', 'error');
        updateElement('service-status', 'Error');
        document.getElementById('service-status').className = 'text-sm px-2 py-1 rounded bg-red-700 text-red-300';
    }
}

async function rebootSystem() {
    if (!confirm('This will reboot the entire system. The device will be offline for several minutes. Continue?')) {
        return;
    }
    
    try {
        addConsoleMessage('Initiating system reboot...', 'warning');
        
        const data = await postAPI('/api/system/reboot', {});
        
        if (data.success) {
            addConsoleMessage('System reboot initiated', 'success');
            addConsoleMessage('Device will be offline for several minutes...', 'warning');
            
            // Update connection status
            updateConnectionStatus(false);
        } else {
            addConsoleMessage(`Reboot failed: ${data.error || 'Unknown error'}`, 'error');
        }
        
    } catch (error) {
        console.error('Error rebooting system:', error);
        addConsoleMessage('Failed to initiate system reboot', 'error');
    }
}

async function shutdownSystem() {
    if (!confirm('⚠️ This will SHUT DOWN the system completely.\n\nYou will need physical access to power the device back on.\n\nContinue?')) {
        return;
    }
    
    try {
        addConsoleMessage('Initiating system shutdown...', 'warning');
        updateElement('service-status', 'Shutting down...');
        document.getElementById('service-status').className = 'text-sm px-2 py-1 rounded bg-red-700 text-red-300';
        
        const data = await postAPI('/api/system/shutdown', {});
        
        if (data.success) {
            addConsoleMessage('System shutdown initiated', 'success');
            addConsoleMessage('Device will power off shortly...', 'warning');
            updateConnectionStatus(false);
        } else {
            addConsoleMessage(`Shutdown failed: ${data.error || 'Unknown error'}`, 'error');
            updateElement('service-status', 'Running');
            document.getElementById('service-status').className = 'text-sm px-2 py-1 rounded bg-green-700 text-green-300';
        }
        
    } catch (error) {
        console.error('Error shutting down system:', error);
        addConsoleMessage('Failed to initiate system shutdown', 'error');
    }
}

// ============================================================================
// DATA MANAGEMENT FUNCTIONS
// ============================================================================

async function resetVulnerabilities() {
    if (!confirm('⚠️ Reset All Vulnerabilities?\n\nThis will permanently delete:\n• All discovered vulnerabilities\n• Vulnerability scan results\n• Network intelligence vulnerability data\n\nThis action cannot be undone. Continue?')) {
        return;
    }
    
    try {
        addConsoleMessage('Resetting vulnerabilities...', 'warning');
        
        const data = await postAPI('/api/data/reset-vulnerabilities', {});
        
        if (data.success) {
            addConsoleMessage(`Vulnerabilities reset: ${data.deleted_count || 0} entries removed`, 'success');
            
            // Update vulnerability count display
            updateElement('vuln-count', '0');
            updateElement('vulnerability-count', '0');
            
            // Refresh current tab if we're on network or discovered tabs
            if (currentTab === 'network' || currentTab === 'discovered' || currentTab === 'threat-intel') {
                setTimeout(() => {
                    refreshCurrentTab();
                }, 500);
            }
        } else {
            addConsoleMessage(`Reset failed: ${data.error || 'Unknown error'}`, 'error');
        }
        
    } catch (error) {
        console.error('Error resetting vulnerabilities:', error);
        addConsoleMessage('Failed to reset vulnerabilities', 'error');
    }
}

async function resetThreatIntelligence() {
    if (!confirm('⚠️ Reset Threat Intelligence?\n\nThis will permanently delete:\n• All threat intelligence findings\n• Enriched threat data\n• Threat cache\n\nThis action cannot be undone. Continue?')) {
        return;
    }
    
    try {
        addConsoleMessage('Resetting threat intelligence...', 'warning');
        
        const data = await postAPI('/api/data/reset-threat-intel', {});
        
        if (data.success) {
            addConsoleMessage('Threat intelligence data reset successfully', 'success');
            
            // Refresh threat intel tab if active
            if (currentTab === 'threat-intel') {
                setTimeout(() => {
                    refreshCurrentTab();
                }, 500);
            }
        } else {
            addConsoleMessage(`Reset failed: ${data.error || 'Unknown error'}`, 'error');
        }
        
    } catch (error) {
        console.error('Error resetting threat intelligence:', error);
        addConsoleMessage('Failed to reset threat intelligence', 'error');
    }
}

// Update vulnerability count in config tab
async function updateVulnerabilityCount() {
    try {
        const stats = await fetchAPI('/api/stats');
        const count = stats.vulnerability_count || 0;
        updateElement('vuln-count', count.toString());
    } catch (error) {
        console.error('Error updating vulnerability count:', error);
        updateElement('vuln-count', '?');
    }
}

// ============================================================================
// WI-FI MANAGEMENT FUNCTIONS
// ============================================================================

async function startAPMode() {
    if (!confirm('Start AP Mode?\n\nThis will:\n• Disconnect from current Wi-Fi\n• Start "Ragnar" access point\n• Enable 3-minute smart cycling\n• Allow Wi-Fi configuration via AP\n\nContinue?')) {
        return;
    }
    
    try {
        addConsoleMessage('Starting AP Mode...', 'info');
        updateWifiStatus('Starting AP Mode...', 'connecting');
        
        const data = await postAPI('/api/wifi/ap/enable', {});
        
        if (data.success) {
            addConsoleMessage(`AP Mode started: ${data.ap_config.ssid}`, 'success');
            updateWifiStatus(
                `AP Mode Active: "${data.ap_config.ssid}" | ${data.ap_config.timeout}s timeout | Smart cycling enabled`,
                'ap-mode'
            );
            
            // Auto-refresh Wi-Fi status
            setTimeout(refreshWifiStatus, 2000);
        } else {
            addConsoleMessage(`Failed to start AP Mode: ${data.message}`, 'error');
            updateWifiStatus(`Failed to start AP Mode: ${data.message}`, 'error');
        }
        
    } catch (error) {
        console.error('Error starting AP mode:', error);
        addConsoleMessage('Error starting AP Mode', 'error');
        updateWifiStatus('Error starting AP Mode', 'error');
    }
}

async function refreshWifiStatus() {
    try {
        let activeInterface = getActiveWifiInterface();
        const statusQuery = activeInterface
            ? `/api/wifi/status?interface=${encodeURIComponent(activeInterface)}`
            : '/api/wifi/status';
        const data = await fetchAPI(statusQuery);
        console.log('Wi-Fi status data received:', data);
        const multiState = data.multi_interface || null;
        wifiMultiInterfaceState = multiState;
        if (multiState && Array.isArray(multiState.interfaces)) {
            setWifiInterfaceMetadata(multiState.interfaces);
        } else if (Array.isArray(data.interfaces)) {
            setWifiInterfaceMetadata(data.interfaces);
        }
        
        const statusIndicator = document.getElementById('wifi-status-indicator');
        const wifiInfo = document.getElementById('wifi-info');
        const connectedList = document.getElementById('wifi-connected-list');
        
        if (!statusIndicator || !wifiInfo) {
            console.error('Wi-Fi status elements not found in DOM');
            console.log('Looking for elements: wifi-status-indicator and wifi-info');
            return;
        }
        
        console.log('Wi-Fi status elements found, updating...');

        if (!activeInterface && data.interface) {
            activeInterface = setSelectedWifiInterface(data.interface, { skipRefresh: true });
        }
        if (Array.isArray(data.interfaces)) {
            renderWifiInterfaceSwitch(data.interfaces);
        }
        const interfaceLabel = data.interface ? data.interface : activeInterface;
        const ipBadge = data.ip_address ? ` (${data.ip_address})` : '';
        
        if (data.ap_mode_active) {
            const apMessage = `AP Mode Active: "${data.ap_ssid || 'Ragnar'}" | Connect to configure Wi-Fi`;
            console.log('Setting AP mode status:', apMessage);
            updateWifiStatus(apMessage, 'ap-mode');
            statusIndicator.textContent = 'AP Mode';
            statusIndicator.className = 'text-sm px-2 py-1 rounded bg-orange-700 text-orange-300';
            wifiInfo.textContent = apMessage;
        } else if (data.wifi_connected) {
            const ssid = data.current_ssid || 'Unknown Network';
            const connectedMessage = interfaceLabel
                ? `Connected to: ${ssid} on ${interfaceLabel}${ipBadge}`
                : `Connected to: ${ssid}`;
            console.log('Setting connected status:', connectedMessage);
            updateWifiStatus(connectedMessage, 'connected');
            statusIndicator.textContent = interfaceLabel ? `${interfaceLabel} • Connected` : 'Connected';
            statusIndicator.className = 'text-sm px-2 py-1 rounded bg-green-700 text-green-300';
            wifiInfo.textContent = connectedMessage;
        } else {
            console.log('Setting disconnected status');
            const disconnectedMessage = interfaceLabel
                ? `Wi-Fi disconnected on ${interfaceLabel}`
                : 'Wi-Fi disconnected';
            updateWifiStatus(disconnectedMessage, 'disconnected');
            statusIndicator.textContent = interfaceLabel ? `${interfaceLabel} • Disconnected` : 'Disconnected';
            statusIndicator.className = 'text-sm px-2 py-1 rounded bg-red-700 text-red-300';
            wifiInfo.textContent = disconnectedMessage;
        }
        if (connectedList) {
            const interfaces = Array.isArray(data.interfaces) ? data.interfaces : [];
            const connectedAdapters = interfaces.filter(iface => iface && iface.connected);
            const offlineAdapters = interfaces.filter(iface => iface && !iface.connected);

            const renderRow = (iface, isOnline = false) => {
                const ssid = iface && (iface.connected_ssid || iface.connection) ? escapeHtml(iface.connected_ssid || iface.connection) : 'No SSID';
                const ipLabel = iface && iface.ip_address ? `<div class="text-[11px] text-gray-400">${escapeHtml(iface.ip_address)}</div>` : '';
                const statusClass = isOnline ? 'text-green-400' : 'text-gray-500';
                const statusLabel = isOnline ? 'Online' : 'Offline';
                const detailLabel = isOnline
                    ? `SSID: ${ssid}`
                    : escapeHtml(iface?.state || 'Unavailable');
                return `
                    <div class="flex items-center justify-between gap-3">
                        <div>
                            <div class="text-sm font-semibold text-white">${escapeHtml(iface?.name || 'Unknown')}</div>
                            <div class="text-xs text-gray-400">${detailLabel}</div>
                        </div>
                        <div class="text-right">
                            <div class="text-xs ${statusClass}">${statusLabel}</div>
                            ${ipLabel}
                        </div>
                    </div>
                `;
            };

            let listMarkup = '<div class="text-[11px] uppercase tracking-wide text-gray-400">Connected Adapters</div>';
            if (connectedAdapters.length > 0) {
                listMarkup += connectedAdapters.map(iface => renderRow(iface, true)).join('');
            } else {
                listMarkup += '<div class="text-xs text-gray-500">No active Wi-Fi connections</div>';
            }

            if (offlineAdapters.length > 0) {
                listMarkup += '<div class="text-[11px] uppercase tracking-wide text-gray-400 mt-3 border-t border-slate-700 pt-2">Other Adapters</div>';
                listMarkup += offlineAdapters.map(iface => renderRow(iface, false)).join('');
            }

            connectedList.innerHTML = listMarkup;
            connectedList.classList.remove('hidden');
        }

        renderDashboardMultiInterfaceSummary(multiState, data);
        renderConnectTabMultiInterface(multiState);
        
        console.log('Wi-Fi status updated successfully');
            
    } catch (error) {
        console.error('Error refreshing Wi-Fi status:', error);
        updateWifiStatus('Error checking Wi-Fi status', 'error');
        
        const statusIndicator = document.getElementById('wifi-status-indicator');
        const wifiInfo = document.getElementById('wifi-info');
        
        if (statusIndicator) {
            statusIndicator.textContent = 'Error';
            statusIndicator.className = 'text-sm px-2 py-1 rounded bg-red-700 text-red-300';
        }
        if (wifiInfo) {
            wifiInfo.textContent = 'Error checking Wi-Fi status';
        }
        const connectedList = document.getElementById('wifi-connected-list');
        if (connectedList) {
            connectedList.innerHTML = '<div class="text-xs text-red-300">Unable to load adapter list</div>';
            connectedList.classList.remove('hidden');
        }
        wifiMultiInterfaceState = null;
    setWifiInterfaceMetadata([]);
        renderDashboardMultiInterfaceSummary(null);
        renderConnectTabMultiInterface(null);
    }
}

// ============================================================================
// ETHERNET / LAN STATUS
// ============================================================================

async function refreshEthernetStatus() {
    const indicator = document.getElementById('lan-status-indicator');
    const info = document.getElementById('lan-info');
    const listEl = document.getElementById('lan-interface-list');

    try {
        const data = await fetchAPI('/api/ethernet/status');

        if (!indicator || !info) return;

        if (data.active && data.active_interface) {
            const iface = data.active_interface;
            indicator.className = 'text-sm px-2 py-1 rounded bg-green-900/50 text-green-400';
            indicator.textContent = 'Connected';
            info.innerHTML = `<span class="text-green-400 font-medium">${escapeHtml(iface.name)}</span> &mdash; ${escapeHtml(iface.ip_address || 'No IP')}`;
            if (iface.network_cidr) {
                info.innerHTML += `<br><span class="text-gray-500 text-xs">Network: ${escapeHtml(iface.network_cidr)}</span>`;
            }
        } else if (data.available) {
            indicator.className = 'text-sm px-2 py-1 rounded bg-yellow-900/50 text-yellow-400';
            indicator.textContent = 'No Link';
            info.textContent = 'Ethernet interface found but no active connection';
        } else {
            indicator.className = 'text-sm px-2 py-1 rounded bg-gray-700 text-gray-400';
            indicator.textContent = 'Not Found';
            info.textContent = 'No Ethernet interfaces detected';
        }

        // Show interface list
        if (listEl && data.interfaces && data.interfaces.length > 0) {
            listEl.innerHTML = data.interfaces.map(iface => {
                const statusColor = iface.connected ? 'text-green-400' : iface.has_carrier ? 'text-yellow-400' : 'text-gray-500';
                const statusText = iface.connected ? 'Connected' : iface.has_carrier ? 'Link Up' : 'No Link';
                const ip = iface.ip_address || '—';
                return `<div class="flex justify-between"><span>${iface.name}</span><span>${ip}</span><span class="${statusColor}">${statusText}</span></div>`;
            }).join('');
            listEl.classList.remove('hidden');
        }
    } catch (e) {
        if (indicator) {
            indicator.className = 'text-sm px-2 py-1 rounded bg-red-900/50 text-red-400';
            indicator.textContent = 'Error';
        }
        if (info) info.textContent = 'Failed to check Ethernet status';
    }
}

function updateWifiStatus(message, type = '') {
    // This function can be enhanced to show status messages in a notification area
    // For now, we'll use console messages and update the UI elements
    addConsoleMessage(message, type === 'error' ? 'error' : type === 'ap-mode' ? 'warning' : 'info');
}

// ============================================================================
// WI-FI MANAGEMENT FUNCTIONS
// ============================================================================

let currentWifiNetworks = [];
let selectedWifiNetwork = null;
const WIFI_INTERFACE_STORAGE_KEY = 'wifi-selected-interface';
let selectedWifiInterface = null;
let wifiInterfaceMetadata = [];
const WIFI_NETWORK_CACHE_KEY_DEFAULT = '__default__';
const wifiNetworkResultCache = new Map();
let wifiMultiInterfaceState = null;
const DASHBOARD_STATS_CACHE_TTL = 4000;
let dashboardStatsCache = { key: null, timestamp: 0, data: null };
let dashboardStatsRequestState = null;

function slugifyNetworkIdentifier(value) {
    if (!value) {
        return null;
    }
    let normalized = value;
    if (typeof normalized.normalize === 'function') {
        normalized = normalized.normalize('NFKD');
    }
    normalized = normalized.replace(/[\u0300-\u036f]/g, '');
    normalized = normalized.replace(/[^A-Za-z0-9]+/g, '_');
    normalized = normalized.replace(/^_+|_+$/g, '');
    normalized = normalized.toLowerCase();
    return normalized || null;
}

function normalizeInterfaceMetadata(entries) {
    if (!Array.isArray(entries)) {
        return [];
    }
    return entries.map(entry => {
        if (!entry || typeof entry !== 'object') {
            return entry;
        }
        if (entry.network_slug) {
            return entry;
        }
        if (entry.connected_ssid) {
            return {
                ...entry,
                network_slug: slugifyNetworkIdentifier(entry.connected_ssid)
            };
        }
        return entry;
    });
}

function setWifiInterfaceMetadata(entries) {
    const previousList = wifiInterfaceMetadata || [];
    let previousSlug = null;
    if (selectedWifiInterface) {
        const prevMeta = Array.isArray(previousList)
            ? previousList.find(entry => entry && entry.name === selectedWifiInterface)
            : null;
        if (prevMeta) {
            previousSlug = prevMeta.network_slug || (prevMeta.connected_ssid ? slugifyNetworkIdentifier(prevMeta.connected_ssid) : null);
        }
    }

    wifiInterfaceMetadata = entries ? normalizeInterfaceMetadata(entries) : [];

    if (selectedWifiInterface) {
        const nextMeta = wifiInterfaceMetadata.find(entry => entry && entry.name === selectedWifiInterface);
        const nextSlug = nextMeta ? (nextMeta.network_slug || (nextMeta.connected_ssid ? slugifyNetworkIdentifier(nextMeta.connected_ssid) : null)) : null;
        if (previousSlug !== nextSlug) {
            clearDashboardStatsCache();
            refreshDashboardStatsForCurrentSelection({ forceRefresh: true }).catch(err => {
                console.debug('Dashboard stats refresh failed after interface metadata update', err);
            });
        }
    }
}

function clearDashboardStatsCache() {
    dashboardStatsCache = { key: null, timestamp: 0, data: null };
}

async function fetchDashboardStatsForSelection(options = {}) {
    const { forceRefresh = false } = options;
    const { network } = getSelectedDashboardNetworkKey();
    const cacheKey = network ? `network:${network}` : 'network:global';
    const now = Date.now();

    const cached = dashboardStatsCache;
    if (!forceRefresh && cached.key === cacheKey && (now - cached.timestamp) < DASHBOARD_STATS_CACHE_TTL && cached.data) {
        return cached.data;
    }

    if (!forceRefresh && dashboardStatsRequestState && dashboardStatsRequestState.key === cacheKey) {
        return dashboardStatsRequestState.promise;
    }

    const query = network ? `/api/dashboard/stats?network=${encodeURIComponent(network)}` : '/api/dashboard/stats';
    const requestPromise = (async () => {
        try {
            const payload = await fetchAPI(query);
            dashboardStatsCache = { key: cacheKey, timestamp: Date.now(), data: payload };
            return payload;
        } finally {
            if (dashboardStatsRequestState && dashboardStatsRequestState.key === cacheKey) {
                dashboardStatsRequestState = null;
            }
        }
    })();

    dashboardStatsRequestState = { key: cacheKey, promise: requestPromise };
    return requestPromise;
}

async function refreshDashboardStatsForCurrentSelection(options = {}) {
    const { forceRefresh = false, fallbackData = null } = options;
    try {
        const stats = await fetchDashboardStatsForSelection({ forceRefresh });
        if (stats) {
            updateDashboardStats(stats);
        } else if (fallbackData) {
            updateDashboardStats(fallbackData);
        }
        return stats;
    } catch (error) {
        console.warn('Unable to refresh dashboard stats for selection', error);
        if (fallbackData) {
            updateDashboardStats(fallbackData);
        }
        throw error;
    }
}

function formatInterfaceRole(role) {
    if (!role) {
        return 'Adapter';
    }
    if (role === 'internal') {
        return 'Internal';
    }
    if (role === 'external') {
        return 'External';
    }
    return role.replace(/_/g, ' ').replace(/\b\w/g, char => char.toUpperCase());
}

function formatInterfaceReason(reason) {
    if (!reason) {
        return '';
    }
    const labels = {
        global_disabled: 'Multi-scan disabled',
        user_disabled: 'Paused by user',
        no_ssid: 'No SSID',
        disconnected: 'Adapter offline'
    };
    return labels[reason] || reason.replace(/_/g, ' ');
}

function renderDashboardMultiInterfaceSummary(state, statusData = {}) {
    const container = document.getElementById('wifi-dashboard-interfaces');
    if (!container) {
        return;
    }

    if (!state || !Array.isArray(state.interfaces) || state.interfaces.length === 0) {
        container.innerHTML = '<div class="text-gray-500 text-[11px]">No additional adapters detected yet.</div>';
        renderDashboardInterfaceSwitch(null);
        return;
    }

    // Determine which interface is selected for dashboard display
    const activeInterface = getActiveWifiInterface();
    let selectedEntry = null;
    if (activeInterface) {
        selectedEntry = state.interfaces.find(entry => entry.name === activeInterface);
    }
    // Fallback: show first connected, else first
    if (!selectedEntry) {
        selectedEntry = state.interfaces.find(entry => entry.connected && entry.connected_ssid) || state.interfaces[0];
    }

    // Show only the selected interface's data
    let markup = '';
    if (selectedEntry) {
        const roleClass = selectedEntry.role === 'external'
            ? 'bg-indigo-900 text-indigo-100'
            : 'bg-slate-800 text-slate-100';
        const scanActive = Boolean(selectedEntry.scan_enabled && selectedEntry.connected && selectedEntry.connected_ssid);
        const scanLabel = scanActive ? 'Scanning' : 'Paused';
        const scanClass = scanActive ? 'text-green-300' : 'text-gray-400';
        const reason = selectedEntry.reason ? ` • ${formatInterfaceReason(selectedEntry.reason)}` : '';
        const ssidLabel = selectedEntry.connected_ssid ? escapeHtml(selectedEntry.connected_ssid) : 'No SSID';
        markup = `
            <div class="flex items-center justify-between gap-2">
                <div class="flex items-center gap-2 text-gray-100">
                    <span class="font-semibold text-xs">${escapeHtml(selectedEntry.name || 'iface')}</span>
                    <span class="text-[10px] px-2 py-0.5 rounded ${roleClass}">${formatInterfaceRole(selectedEntry.role)}</span>
                </div>
                <div class="text-right leading-tight text-[11px] ${scanClass}">
                    <div>${ssidLabel}</div>
                    <div class="text-[10px] text-gray-400">${scanLabel}${reason}</div>
                </div>
            </div>
        `;
    }
    container.innerHTML = markup;

    // Update connectivity indicator for selected interface
    const anyConnected = !!selectedEntry && selectedEntry.connected;
    const fallbackSsid = selectedEntry ? selectedEntry.connected_ssid : (statusData && statusData.current_ssid);
    const apMode = Boolean(statusData && statusData.ap_mode_active);
    updateConnectivityIndicator('wifi-status', anyConnected || Boolean(statusData && statusData.wifi_connected), fallbackSsid, apMode);
    renderDashboardInterfaceSwitch(state);
}

function renderConnectTabMultiInterface(state) {
    const summaryEl = document.getElementById('wifi-multi-status-summary');
    const listEl = document.getElementById('wifi-multi-interface-list');
    const pillEl = document.getElementById('wifi-multi-global-pill');
    const noteEl = document.getElementById('wifi-multi-limit-note');
    if (!summaryEl || !listEl || !pillEl) {
        return;
    }

    if (!state) {
        pillEl.textContent = 'Unavailable';
        pillEl.className = 'text-xs px-2 py-1 rounded bg-red-700 text-red-200';
        summaryEl.textContent = 'Multi-interface controller unavailable. Refresh Wi-Fi status to retry.';
        listEl.innerHTML = '<div class="text-xs text-red-300 bg-red-900/30 border border-red-800 rounded-lg p-3">Unable to load adapter details.</div>';
        return;
    }

    const interfaces = Array.isArray(state.interfaces) ? state.interfaces : [];
    const scanMode = (state.scan_mode || 'single').toLowerCase();
    const focusInterface = state.focus_interface || '';
    const focusSsid = state.focus_interface_ssid || '';
    const globalEnabled = scanMode === 'multi';
    pillEl.textContent = globalEnabled ? 'Single focus' : 'All adapters';
    pillEl.className = `text-xs px-2 py-1 rounded ${globalEnabled ? 'bg-green-700 text-green-100' : 'bg-amber-700 text-amber-100'}`;
    if (noteEl) {
        const maxAdapters = state.max_interfaces || 1;
        noteEl.textContent = globalEnabled
            ? `Monitoring up to ${maxAdapters} adapter${maxAdapters === 1 ? '' : 's'} simultaneously.`
            : 'Automation locks onto the focused adapter to prevent context drift.';
    }

    if (interfaces.length === 0) {
        summaryEl.textContent = 'Waiting for eligible adapters...';
        listEl.innerHTML = '<div class="text-xs text-gray-400 bg-slate-900/60 border border-dashed border-slate-700 rounded-lg p-3">Connect adapters to begin multi-interface scanning.</div>';
        updateMultiInterfaceModeControls(state);
        return;
    }

    const activeCount = interfaces.filter(entry => entry.scan_enabled && entry.connected && entry.connected_ssid).length;
    if (scanMode === 'single') {
        const focusLabel = focusInterface ? escapeHtml(focusInterface) : 'Select an adapter to focus on';
        const ssidTag = focusSsid ? `<span class="text-emerald-300 ml-2">${escapeHtml(focusSsid)}</span>` : '';
        summaryEl.innerHTML = `Single-adapter focus: <span class="text-white font-semibold">${focusLabel}</span>${ssidTag}`;
    } else {
        summaryEl.textContent = activeCount > 0
            ? `Actively scanning ${activeCount} adapter${activeCount === 1 ? '' : 's'}.`
            : 'All adapters are currently paused.';
    }

    listEl.innerHTML = interfaces.map(entry => {
        const scanning = Boolean(entry.scan_enabled && entry.connected && entry.connected_ssid);
        const buttonLabel = scanning ? 'Pause Scans' : 'Resume Scans';
        const buttonClasses = scanning
            ? 'text-xs px-3 py-1 rounded bg-yellow-600 hover:bg-yellow-500 text-white transition-colors'
            : 'text-xs px-3 py-1 rounded bg-green-600 hover:bg-green-500 text-white transition-colors';
        const connectionLabel = entry.connected
            ? (entry.connected_ssid ? `SSID: ${escapeHtml(entry.connected_ssid)}` : 'Connected')
            : escapeHtml(entry.state || 'Disconnected');
        const scanNote = scanning ? 'Scanning' : (entry.reason ? `Paused • ${formatInterfaceReason(entry.reason)}` : 'Paused');
        const scanClass = scanning ? 'text-green-300' : 'text-gray-400';
        const ipLabel = entry.ip_address ? ` • ${escapeHtml(entry.ip_address)}` : '';
        const roleClass = entry.role === 'external' ? 'bg-indigo-900 text-indigo-200' : 'bg-slate-800 text-slate-200';
        const focusChip = entry.focus_selected
            ? '<span class="text-[10px] px-2 py-0.5 rounded bg-amber-700/60 text-amber-200">Focus</span>'
            : '';
        return `
            <div class="border border-slate-700 rounded-lg p-3 bg-slate-900/50 flex flex-col gap-3">
                <div class="flex items-center justify-between gap-3">
                    <div>
                        <div class="flex items-center gap-2 text-sm font-semibold text-white">
                            <span>${escapeHtml(entry.name || 'iface')}</span>
                            <span class="text-[10px] px-2 py-0.5 rounded ${roleClass}">${formatInterfaceRole(entry.role)}</span>
                            ${focusChip}
                        </div>
                        <div class="text-[11px] text-gray-400">${connectionLabel}</div>
                    </div>
                    <button type="button" class="${buttonClasses}" data-interface="${escapeHtml(entry.name || '')}" data-scan-state="${scanning ? 'enabled' : 'disabled'}">${buttonLabel}</button>
                </div>
                <div class="text-[11px] ${scanClass}">${scanNote}${ipLabel}</div>
            </div>
        `;
    }).join('');

    listEl.querySelectorAll('button[data-interface]').forEach(button => {
        button.addEventListener('click', handleScanControlToggle);
    });

    updateMultiInterfaceModeControls(state);
}

function updateMultiInterfaceModeControls(state) {
    const buttonsContainer = document.getElementById('wifi-multi-mode-buttons');
    const focusWrapper = document.getElementById('wifi-multi-focus-controls');
    const focusSelect = document.getElementById('wifi-multi-focus-select');
    if (!buttonsContainer || !focusWrapper || !focusSelect) {
        return;
    }

    const activeMode = (state && state.scan_mode) ? state.scan_mode.toLowerCase() : 'single';
    const focusInterface = state && state.focus_interface ? state.focus_interface : '';
    const interfaces = state && Array.isArray(state.interfaces) ? state.interfaces : [];

    const buttons = buttonsContainer.querySelectorAll('button[data-mode]');
    buttons.forEach(button => {
        const mode = button.dataset.mode;
        if (!mode) {
            return;
        }
        const isActive = mode === activeMode;
        button.classList.toggle('bg-Ragnar-500', isActive);
        button.classList.toggle('border-Ragnar-400', isActive);
        button.classList.toggle('text-white', isActive);
        button.classList.toggle('shadow-md', isActive);
        button.classList.toggle('bg-slate-800', !isActive);
        button.classList.toggle('border-slate-600', !isActive);
        button.classList.toggle('text-gray-300', !isActive);
        button.onclick = async () => {
            if (button.dataset.busy === 'true' || mode === activeMode) {
                return;
            }
            await setMultiInterfaceMode(mode, button);
        };
    });

    const shouldShowFocus = activeMode === 'single';
    focusWrapper.classList.toggle('hidden', !shouldShowFocus);

    const uniqueOptions = interfaces
        .filter(entry => entry && entry.name)
        .map(entry => ({
            name: entry.name,
            label: `${entry.name}${entry.connected_ssid ? ` • ${entry.connected_ssid}` : ''}`
        }));

    if (shouldShowFocus) {
        const options = uniqueOptions.length
            ? ['<option value="">Select adapter</option>', ...uniqueOptions.map(entry => {
                const selected = entry.name === focusInterface ? ' selected' : '';
                return `<option value="${escapeHtml(entry.name)}"${selected}>${escapeHtml(entry.label)}</option>`;
            })]
            : ['<option value="">No adapters detected</option>'];
        focusSelect.innerHTML = options.join('');
        focusSelect.disabled = uniqueOptions.length === 0;
        focusSelect.onchange = async () => {
            const nextValue = focusSelect.value || '';
            await setMultiInterfaceFocus(nextValue);
        };
    } else {
        focusSelect.onchange = null;
    }
}

async function setMultiInterfaceMode(mode, button) {
    if (!mode) {
        return;
    }
    if (button) {
        button.dataset.busy = 'true';
        button.classList.add('opacity-60', 'cursor-not-allowed');
    }
    try {
        await postAPI('/api/wifi/scan-control/mode', { mode });
        addConsoleMessage(mode === 'multi' ? 'Single focus mode enabled' : 'All adapters mode enabled', 'info');
        await refreshWifiStatus();
    } catch (error) {
        console.error('Unable to update scan mode:', error);
        addConsoleMessage('Scan mode update failed', 'error');
    } finally {
        if (button) {
            button.classList.remove('opacity-60', 'cursor-not-allowed');
            delete button.dataset.busy;
        }
    }
}

async function setMultiInterfaceFocus(interfaceName) {
    try {
        await postAPI('/api/wifi/scan-control/mode', { focus_interface: interfaceName || '' });
        addConsoleMessage(interfaceName ? `Focused on ${interfaceName}` : 'Cleared scan focus', 'info');
        await refreshWifiStatus();
    } catch (error) {
        console.error('Unable to update focused adapter:', error);
        addConsoleMessage('Focus adapter update failed', 'error');
    }
}

function handleScanControlToggle(event) {
    const button = event.currentTarget;
    if (!button || button.dataset.busy === 'true') {
        return;
    }
    const interfaceName = button.dataset.interface;
    const currentlyEnabled = button.dataset.scanState === 'enabled';
    updateInterfaceScanState(interfaceName, !currentlyEnabled, button);
}

async function updateInterfaceScanState(interfaceName, enable, button) {
    if (!interfaceName) {
        return;
    }
    const endpoint = enable ? '/api/wifi/scan-control/start' : '/api/wifi/scan-control/stop';
    if (button) {
        button.dataset.busy = 'true';
        button.disabled = true;
        button.classList.add('opacity-60', 'cursor-not-allowed');
        button.textContent = enable ? 'Resuming…' : 'Pausing…';
    }

    let updated = false;
    try {
        const response = await postAPI(endpoint, { interface: interfaceName });
        if (!response || response.success === false) {
            throw new Error((response && (response.error || response.message)) || 'Request failed');
        }
        addConsoleMessage(`${enable ? 'Resumed' : 'Paused'} scans on ${interfaceName}`, 'info');
        updated = true;
    } catch (error) {
        console.error('Error updating scan interface:', error);
        addConsoleMessage(`Scan control failed on ${interfaceName}: ${error.message}`, 'error');
    } finally {
        if (button) {
            button.disabled = false;
            button.classList.remove('opacity-60', 'cursor-not-allowed');
            delete button.dataset.busy;
        }
    }

    if (updated) {
        try {
            await refreshWifiStatus();
        } catch (error) {
            console.warn('Wi-Fi status refresh failed after scan control change:', error);
        }
    }
}

function cacheWifiNetworkResult(interfaceName, payload) {
    if (!payload) {
        return;
    }
    const key = interfaceName || WIFI_NETWORK_CACHE_KEY_DEFAULT;
    wifiNetworkResultCache.set(key, {
        payload,
        timestamp: Date.now()
    });
}

function getCachedWifiNetworkResult(interfaceName) {
    const key = interfaceName || WIFI_NETWORK_CACHE_KEY_DEFAULT;
    const cached = wifiNetworkResultCache.get(key);
    return cached ? cached.payload : null;
}

function hasCachedWifiNetworks(interfaceName) {
    return Boolean(getCachedWifiNetworkResult(interfaceName));
}

function displayCachedWifiNetworks(interfaceName) {
    const cached = getCachedWifiNetworkResult(interfaceName);
    if (!cached) {
        return false;
    }
    displayWifiNetworks(cached, { forceInterface: interfaceName, skipInterfaceCheck: true, fromCache: true });
    return true;
}

function handleWifiInterfaceChange(event) {
    const nextInterface = (event?.target?.value || '').trim() || null;
    setSelectedWifiInterface(nextInterface);
}

function getActiveWifiInterface() {
    if (selectedWifiInterface) {
        return selectedWifiInterface;
    }
    const saved = localStorage.getItem(WIFI_INTERFACE_STORAGE_KEY);
    if (saved) {
        selectedWifiInterface = saved;
        return selectedWifiInterface;
    }
    const interfaceSelect = document.getElementById('wifi-interface-select');
    if (interfaceSelect && interfaceSelect.value) {
        selectedWifiInterface = interfaceSelect.value;
        return selectedWifiInterface;
    }
    return null;
}

function getNetworkSlugForInterface(interfaceName) {
    if (!interfaceName) {
        return null;
    }
    const meta = Array.isArray(wifiInterfaceMetadata)
        ? wifiInterfaceMetadata.find(entry => entry && entry.name === interfaceName)
        : null;
    if (!meta) {
        return null;
    }
    if (meta.network_slug) {
        return meta.network_slug;
    }
    if (meta.connected_ssid) {
        return slugifyNetworkIdentifier(meta.connected_ssid);
    }
    return null;
}

function getSelectedDashboardNetworkKey() {
    const iface = getActiveWifiInterface();
    const slug = getNetworkSlugForInterface(iface);
    if (slug) {
        return { interface: iface, network: slug };
    }
    return { interface: iface, network: null };
}

function updateWifiInterfaceSwitchActiveState(activeInterface) {
    const buttonsContainer = document.getElementById('wifi-interface-switch-buttons');
    if (!buttonsContainer) return;
    const buttons = buttonsContainer.querySelectorAll('button[data-interface]');
    buttons.forEach(button => {
        const isActive = button.dataset.interface === activeInterface;
        button.classList.remove('bg-Ragnar-600', 'border-Ragnar-400', 'text-white', 'shadow-lg', 'bg-slate-800', 'border-slate-600', 'text-gray-300');
        if (isActive) {
            button.classList.add('bg-Ragnar-600', 'border-Ragnar-400', 'text-white', 'shadow-lg');
        } else {
            button.classList.add('bg-slate-800', 'border-slate-600', 'text-gray-300');
        }
    });
}

function updateDashboardInterfaceSwitchActiveState(activeInterface) {
    const buttonsContainer = document.getElementById('wifi-dashboard-interface-buttons');
    if (!buttonsContainer) {
        return;
    }
    buttonsContainer.querySelectorAll('button[data-interface]').forEach(button => {
        const isActive = button.dataset.interface === activeInterface;
        button.classList.remove('bg-Ragnar-500', 'text-white', 'border-Ragnar-400', 'shadow');
        button.classList.remove('bg-slate-800', 'text-gray-300', 'border-slate-700');
        if (isActive) {
            button.classList.add('bg-Ragnar-500', 'text-white', 'border-Ragnar-400', 'shadow');
        } else {
            button.classList.add('bg-slate-800', 'text-gray-300', 'border-slate-700');
        }
    });
}

function renderDashboardInterfaceSwitch(state) {
    const wrapper = document.getElementById('wifi-dashboard-interface-switch');
    const buttonsContainer = document.getElementById('wifi-dashboard-interface-buttons');
    if (!wrapper || !buttonsContainer) {
        return;
    }

    const interfaces = state && Array.isArray(state.interfaces)
        ? state.interfaces.filter(entry => entry && entry.name)
        : [];
    const eligible = interfaces.filter(entry => entry.connected && entry.connected_ssid);

    buttonsContainer.innerHTML = '';
    if (eligible.length <= 1) {
        wrapper.classList.add('hidden');
        return;
    }

    wrapper.classList.remove('hidden');
    const activeInterface = getActiveWifiInterface();

    eligible.forEach(entry => {
        const button = document.createElement('button');
        button.type = 'button';
        button.dataset.interface = entry.name;
        button.className = 'px-2 py-1 rounded-full border text-[11px] transition-colors flex items-center gap-1';
        button.innerHTML = `
            <span class="font-semibold">${escapeHtml(entry.name)}</span>
            <span class="text-emerald-300">${escapeHtml(entry.connected_ssid || '')}</span>
        `;
        button.addEventListener('click', () => {
            if (entry.name !== getActiveWifiInterface()) {
                setSelectedWifiInterface(entry.name);
            }
        });
        buttonsContainer.appendChild(button);
    });

    updateDashboardInterfaceSwitchActiveState(activeInterface);
}

function renderWifiInterfaceSwitch(interfaces = []) {
    setWifiInterfaceMetadata(interfaces);
    const switchContainer = document.getElementById('wifi-interface-switch');
    const buttonsContainer = document.getElementById('wifi-interface-switch-buttons');
    if (!switchContainer || !buttonsContainer) {
        return;
    }

    const connectedInterfaces = wifiInterfaceMetadata.filter(iface => iface && iface.connected);
    const shouldDisplay = connectedInterfaces.length >= 2;
    buttonsContainer.innerHTML = '';
    switchContainer.classList.toggle('hidden', !shouldDisplay);

    if (!shouldDisplay) {
        return;
    }

    const activeName = getActiveWifiInterface() || (connectedInterfaces[0] ? connectedInterfaces[0].name : null);

    connectedInterfaces.forEach(iface => {
        const button = document.createElement('button');
        button.type = 'button';
        button.dataset.interface = iface.name;
        button.className = 'wifi-switch-btn flex-1 min-w-[180px] px-3 py-2 rounded-lg border transition-all text-left';
        const ssidLabel = iface.connected_ssid || iface.connection || 'No SSID';
        const ipLabel = iface.ip_address || 'No IP';
        const stateLabel = iface.state || 'UNKNOWN';
        button.innerHTML = `
            <div class="flex items-center justify-between gap-3">
                <div>
                    <div class="text-sm font-semibold">${iface.name}</div>
                    <div class="text-[11px] text-gray-300">${ssidLabel}</div>
                </div>
                <div class="text-right text-[11px] leading-tight text-gray-400">
                    <div>${ipLabel}</div>
                    <div>${stateLabel}</div>
                </div>
            </div>
        `;
        button.addEventListener('click', () => {
            if (iface.name !== getActiveWifiInterface()) {
                setSelectedWifiInterface(iface.name);
            }
        });
        buttonsContainer.appendChild(button);
    });

    updateWifiInterfaceSwitchActiveState(activeName);
}

async function refreshWifiNetworksForInterface(interfaceName) {
    if (!interfaceName) {
        return;
    }
    const networksList = document.getElementById('wifi-networks-list');
    if (!networksList) {
        return;
    }
    displayCachedWifiNetworks(interfaceName);
    try {
        const query = `/api/wifi/networks?interface=${encodeURIComponent(interfaceName)}`;
        const data = await fetchAPI(query);
        if (data) {
            displayWifiNetworks(data, { forceInterface: interfaceName, skipInterfaceCheck: true });
        }
    } catch (error) {
        console.warn('Unable to refresh Wi-Fi networks for interface', interfaceName, error);
    }
}

function setSelectedWifiInterface(interfaceName, options = {}) {
    const normalized = (interfaceName || '').trim() || null;
    const hasChanged = normalized !== selectedWifiInterface;
    selectedWifiInterface = normalized;

    if (selectedWifiInterface) {
        localStorage.setItem(WIFI_INTERFACE_STORAGE_KEY, selectedWifiInterface);
    } else {
        localStorage.removeItem(WIFI_INTERFACE_STORAGE_KEY);
    }

    const interfaceSelect = document.getElementById('wifi-interface-select');
    if (interfaceSelect && interfaceSelect.value !== (selectedWifiInterface || '')) {
        interfaceSelect.value = selectedWifiInterface || '';
    }

    updateWifiInterfaceSwitchActiveState(selectedWifiInterface);
    updateDashboardInterfaceSwitchActiveState(selectedWifiInterface);

    if (hasChanged) {
        clearDashboardStatsCache();
        refreshDashboardStatsForCurrentSelection({ forceRefresh: true }).catch(err => {
            console.debug('Dashboard stats refresh failed after interface change', err);
        });
    }

    if (!options.skipRefresh && hasChanged) {
        if (!displayCachedWifiNetworks(selectedWifiInterface)) {
            const networksList = document.getElementById('wifi-networks-list');
            if (networksList) {
                networksList.innerHTML = `
                    <div class="text-center text-gray-400 py-8">
                        <p>No cached Wi-Fi data for <span class="font-semibold text-gray-100">${escapeHtml(selectedWifiInterface || 'default')}</span>.</p>
                        <p class="text-sm mt-2">Fetching fresh scan results...</p>
                    </div>
                `;
            }
        }
        refreshWifiStatus().catch(err => console.warn('Wi-Fi status refresh failed for interface change', err));
        refreshWifiNetworksForInterface(selectedWifiInterface).catch(err => console.warn('Wi-Fi networks refresh failed for interface change', err));
    }

    return selectedWifiInterface;
}

async function loadWifiInterfaces() {
    try {
        const data = await fetchAPI('/api/wifi/interfaces');
        const interfaceSelect = document.getElementById('wifi-interface-select');
        
        if (!interfaceSelect) return;
        const savedInterface = localStorage.getItem(WIFI_INTERFACE_STORAGE_KEY);
        let selectionApplied = false;
        let firstConnectedInterface = null;
        let defaultInterface = null;
        
        if (data && Array.isArray(data.interfaces) && data.interfaces.length > 0) {
            setWifiInterfaceMetadata(data.interfaces);
            interfaceSelect.innerHTML = '';
            data.interfaces.forEach(iface => {
                const option = document.createElement('option');
                option.value = iface.name;
                option.textContent = `${iface.name}${iface.is_default ? ' (default)' : ''} - ${iface.state}`;
                if (!firstConnectedInterface && iface.connected) {
                    firstConnectedInterface = iface.name;
                }
                if (iface.is_default) {
                    defaultInterface = iface.name;
                }
                if (!selectionApplied && savedInterface && iface.name === savedInterface) {
                    option.selected = true;
                    selectionApplied = true;
                }
                interfaceSelect.appendChild(option);
            });
            if (!selectionApplied && firstConnectedInterface) {
                const match = Array.from(interfaceSelect.options).find(opt => opt.value === firstConnectedInterface);
                if (match) {
                    match.selected = true;
                    selectionApplied = true;
                }
            }
            if (!selectionApplied && defaultInterface) {
                const match = Array.from(interfaceSelect.options).find(opt => opt.value === defaultInterface);
                if (match) {
                    match.selected = true;
                    selectionApplied = true;
                }
            }
            console.log('Loaded Wi-Fi interfaces:', data.interfaces);
        } else {
            interfaceSelect.innerHTML = '<option value="wlan0">wlan0 (default)</option>';
            selectionApplied = true;
        }

        if (!selectionApplied && interfaceSelect.options.length > 0) {
            interfaceSelect.options[0].selected = true;
        }

        setSelectedWifiInterface(interfaceSelect.value || null, { skipRefresh: true });

        interfaceSelect.removeEventListener('change', handleWifiInterfaceChange);
        interfaceSelect.addEventListener('change', handleWifiInterfaceChange);

    renderWifiInterfaceSwitch((data && data.interfaces) || []);
    } catch (error) {
        console.error('Error loading Wi-Fi interfaces:', error);
        const interfaceSelect = document.getElementById('wifi-interface-select');
        if (interfaceSelect) {
            interfaceSelect.innerHTML = '<option value="wlan0">wlan0 (default)</option>';
        }
        setWifiInterfaceMetadata([]);
        renderWifiInterfaceSwitch([]);
    }
}

async function scanWifiNetworks() {
    const scanBtn = document.getElementById('scan-wifi-btn');
    const networksList = document.getElementById('wifi-networks-list');
    
    if (!networksList) return;
    const interfaceName = getActiveWifiInterface();
    const hasNetworkEntries = (payload) => {
        if (!payload) return false;
        if (Array.isArray(payload.available) && payload.available.length > 0) {
            return true;
        }
        if (Array.isArray(payload.networks) && payload.networks.length > 0) {
            return true;
        }
        return false;
    };
    const applyInterfaceContext = (payload) => {
        if (payload && interfaceName && !payload.interface) {
            payload.interface = interfaceName;
        }
        return payload;
    };
    let displayedFromScan = false;
    
    try {
        // Disable button and show scanning message
        if (scanBtn) {
            scanBtn.disabled = true;
            scanBtn.innerHTML = `
                <svg class="w-4 h-4 inline mr-1 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                </svg>
                Scanning...
            `;
        }
        
        networksList.innerHTML = `
            <div class="text-center text-gray-400 py-8">
                <svg class="w-8 h-8 inline animate-spin mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                </svg>
                <p>Scanning for Wi-Fi networks...</p>
            </div>
        `;
        
        // Trigger scan
        const scanPayload = interfaceName ? { interface: interfaceName } : {};
        let scanResponse = null;
        try {
            scanResponse = applyInterfaceContext(await postAPI('/api/wifi/scan', scanPayload));
        } catch (scanError) {
            throw scanError;
        }
        if (scanResponse && (hasNetworkEntries(scanResponse) || scanResponse.warning || scanResponse.error)) {
            displayWifiNetworks(scanResponse, { forceInterface: interfaceName, skipInterfaceCheck: true });
            displayedFromScan = true;
        }
        
        // Wait a bit for scan to complete
        await new Promise(resolve => setTimeout(resolve, 3000));
        
        // Get networks
        const query = interfaceName ? `/api/wifi/networks?interface=${encodeURIComponent(interfaceName)}` : '/api/wifi/networks';
        const data = applyInterfaceContext(await fetchAPI(query));
        
        console.log('Wi-Fi networks data:', data);
        
        if (!displayedFromScan || hasNetworkEntries(data)) {
            displayWifiNetworks(data, { forceInterface: interfaceName, skipInterfaceCheck: true });
            displayedFromScan = true;
        }
        
    } catch (error) {
        console.error('Error scanning Wi-Fi networks:', error);
        networksList.innerHTML = `
            <div class="text-center text-red-400 py-8">
                <p>Error scanning for networks</p>
                <p class="text-sm mt-2">${error.message}</p>
            </div>
        `;
    } finally {
        // Re-enable button
        if (scanBtn) {
            scanBtn.disabled = false;
            scanBtn.innerHTML = `
                <svg class="w-4 h-4 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path>
                </svg>
                Scan Networks
            `;
        }
    }
}

function displayWifiNetworks(data, options = {}) {
    const networksList = document.getElementById('wifi-networks-list');
    if (!networksList) return;

    let networks = [];
    let knownNetworks = [];
    const activeInterface = options.forceInterface || getActiveWifiInterface();
    const responseInterface = data.interface || null;
    const cacheKeyInterface = responseInterface || activeInterface || null;

    if (cacheKeyInterface) {
        cacheWifiNetworkResult(cacheKeyInterface, data);
    } else {
        cacheWifiNetworkResult(null, data);
    }

    if (!options.skipInterfaceCheck && responseInterface && activeInterface && responseInterface !== activeInterface) {
        console.info(`Ignoring Wi-Fi scan results for ${responseInterface} because ${activeInterface} is selected`);
        const cachedActive = getCachedWifiNetworkResult(activeInterface);
        if (cachedActive && cachedActive !== data) {
            displayWifiNetworks(cachedActive, { forceInterface: activeInterface, skipInterfaceCheck: true });
            return;
        }
        networksList.innerHTML = `
            <div class="text-center text-gray-400 py-8">
                <p>Scan results for <span class="font-semibold text-gray-100">${escapeHtml(responseInterface)}</span> are ready.</p>
                <p class="text-sm mt-2">Switch to that interface or run a new scan for <span class="font-semibold text-gray-100">${escapeHtml(activeInterface)}</span>.</p>
            </div>
        `;
        return;
    }

    const interfaceName = options.forceInterface || responseInterface || activeInterface;
    const warningMarkup = data.warning ? `
        <div class="text-xs text-yellow-300 bg-yellow-900/40 border border-yellow-800 rounded px-3 py-2 mb-3">
            ${escapeHtml(data.warning)}
        </div>
    ` : '';
    const sectionHeader = interfaceName ? `
        <div class="text-xs text-gray-400 mb-3">
            Showing results for interface <span class="font-semibold text-gray-100">${escapeHtml(interfaceName)}</span>
        </div>
    ` : '';
    if (interfaceName) {
        networksList.dataset.interface = interfaceName;
    } else {
        delete networksList.dataset.interface;
    }

    // Extract networks from response
    if (data.available) {
        networks = data.available;
    } else if (data.networks) {
        networks = data.networks;
    }

    // Extract known networks
    if (data.known) {
        knownNetworks = data.known.map(n => n.ssid || n);
    }

    console.log('Displaying networks:', networks);
    console.log('Known networks:', knownNetworks);

    if (!networks || networks.length === 0) {
        networksList.innerHTML = `
            ${sectionHeader}
            ${warningMarkup}
            <div class="text-center text-gray-400 py-8">
                <p>No Wi-Fi networks found${interfaceName ? ` on <span class="font-semibold text-gray-100">${escapeHtml(interfaceName)}</span>` : ''}</p>
                <p class="text-sm mt-2">Ensure the adapter is active and try scanning again. You can also switch interfaces above.</p>
            </div>
        `;
        return;
    }

    // Sort networks by signal strength
    networks.sort((a, b) => (b.signal || 0) - (a.signal || 0));

    // Store for later use
    currentWifiNetworks = networks;

    // Build network list HTML
    networksList.innerHTML = sectionHeader + warningMarkup + networks.map(network => {
        const ssid = network.ssid || network.SSID || 'Unknown Network';
        const signal = network.signal || 0;
        const isSecure = network.security !== 'open' && network.security !== 'Open';
        // Check both backend-provided 'known' flag AND local knownNetworks list
        // This ensures we catch both Ragnar's known networks AND NetworkManager system profiles
        const isKnown = network.known || network.has_system_profile || knownNetworks.includes(ssid);
        const isCurrent = network.in_use || false;
        
        // Determine signal icon
        let signalIcon = '';
        if (signal >= 70) {
            signalIcon = `<svg class="w-5 h-5 text-green-400" fill="currentColor" viewBox="0 0 20 20">
                <path d="M2 11a1 1 0 011-1h2a1 1 0 011 1v5a1 1 0 01-1 1H3a1 1 0 01-1-1v-5zM8 7a1 1 0 011-1h2a1 1 0 011 1v9a1 1 0 01-1 1H9a1 1 0 01-1-1V7zM14 4a1 1 0 011-1h2a1 1 0 011 1v12a1 1 0 01-1 1h-2a1 1 0 01-1-1V4z"></path>
            </svg>`;
        } else if (signal >= 50) {
            signalIcon = `<svg class="w-5 h-5 text-yellow-400" fill="currentColor" viewBox="0 0 20 20">
                <path d="M2 11a1 1 0 011-1h2a1 1 0 011 1v5a1 1 0 01-1 1H3a1 1 0 01-1-1v-5zM8 7a1 1 0 011-1h2a1 1 0 011 1v9a1 1 0 01-1 1H9a1 1 0 01-1-1V7z"></path>
            </svg>`;
        } else {
            signalIcon = `<svg class="w-5 h-5 text-red-400" fill="currentColor" viewBox="0 0 20 20">
                <path d="M2 11a1 1 0 011-1h2a1 1 0 011 1v5a1 1 0 01-1 1H3a1 1 0 01-1-1v-5z"></path>
            </svg>`;
        }
        
        // Security icon
        const securityIcon = isSecure ? `
            <svg class="w-4 h-4 text-gray-400" fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clip-rule="evenodd"></path>
            </svg>
        ` : '';
        
        // Badge for known/current network
        let badge = '';
        if (isCurrent) {
            badge = '<span class="text-xs px-2 py-1 rounded bg-green-600 text-white ml-2">Connected</span>';
        } else if (isKnown) {
            badge = '<span class="text-xs px-2 py-1 rounded bg-blue-600 text-white ml-2">Saved</span>';
        }
        
        return `
            <div class="bg-slate-800 rounded-lg p-3 hover:bg-slate-700 transition-colors cursor-pointer"
                 onclick="openWifiConnectModal('${ssid.replace(/'/g, "\\'")}', ${isKnown})">
                <div class="flex items-center justify-between">
                    <div class="flex items-center space-x-3 flex-1">
                        ${signalIcon}
                        <div class="flex-1">
                            <div class="flex items-center">
                                <span class="font-medium">${ssid}</span>
                                ${badge}
                            </div>
                            <div class="text-xs text-gray-400 mt-1">
                                ${isSecure ? 'Secured' : 'Open'} • Signal: ${signal}%
                            </div>
                        </div>
                    </div>
                    <div class="flex items-center space-x-2">
                        ${securityIcon}
                        <svg class="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
                        </svg>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

function openWifiConnectModal(ssid, isKnown) {
    const modal = document.getElementById('wifi-connect-modal');
    const ssidInput = document.getElementById('wifi-connect-ssid');
    const passwordSection = document.getElementById('wifi-password-section');
    const passwordInput = document.getElementById('wifi-connect-password');
    const statusDiv = document.getElementById('wifi-connect-status');
    
    if (!modal || !ssidInput) return;
    
    // Store selected network
    selectedWifiNetwork = { ssid, isKnown };
    
    // Set SSID
    ssidInput.value = ssid;
    
    // Clear password
    if (passwordInput) {
        passwordInput.value = '';
    }
    
    // Hide/show password section based on whether network is known
    if (passwordSection) {
        if (isKnown) {
            passwordSection.style.display = 'none';
        } else {
            passwordSection.style.display = 'block';
        }
    }
    
    // Hide status
    if (statusDiv) {
        statusDiv.classList.add('hidden');
    }
    
    // Show modal
    modal.classList.remove('hidden');
    modal.classList.add('flex');
}

function closeWifiConnectModal() {
    const modal = document.getElementById('wifi-connect-modal');
    if (modal) {
        modal.classList.add('hidden');
        modal.classList.remove('flex');
    }
    selectedWifiNetwork = null;
}

function togglePasswordVisibility() {
    const passwordInput = document.getElementById('wifi-connect-password');
    const eyeIcon = document.getElementById('password-eye-icon');
    
    if (!passwordInput) return;
    
    if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        if (eyeIcon) {
            eyeIcon.innerHTML = `
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21"></path>
            `;
        }
    } else {
        passwordInput.type = 'password';
        if (eyeIcon) {
            eyeIcon.innerHTML = `
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path>
            `;
        }
    }
}

async function connectToWifiNetwork() {
    if (!selectedWifiNetwork) return;
    
    const passwordInput = document.getElementById('wifi-connect-password');
    const passwordSection = document.getElementById('wifi-password-section');
    const saveCheckbox = document.getElementById('wifi-save-network');
    const statusDiv = document.getElementById('wifi-connect-status');
    const submitBtn = document.getElementById('wifi-connect-submit-btn');
    
    const ssid = selectedWifiNetwork.ssid;
    const isKnown = selectedWifiNetwork.isKnown;
    const password = isKnown ? null : (passwordInput ? passwordInput.value : '');
    const saveNetwork = saveCheckbox ? saveCheckbox.checked : true;
    
    // Validate password for new networks
    if (!isKnown && !password) {
        if (statusDiv) {
            statusDiv.classList.remove('hidden');
            statusDiv.innerHTML = '<div class="bg-red-600 rounded p-3 text-sm">Please enter a password</div>';
        }
        return;
    }
    
    try {
        // Disable submit button
        if (submitBtn) {
            submitBtn.disabled = true;
            submitBtn.innerHTML = `
                <svg class="w-4 h-4 inline mr-2 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                </svg>
                Connecting...
            `;
        }
        
        // Show connecting status
        if (statusDiv) {
            statusDiv.classList.remove('hidden');
            statusDiv.innerHTML = `
                <div class="bg-blue-600 rounded p-3 text-sm">
                    <svg class="w-4 h-4 inline mr-2 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                    </svg>
                    Connecting to ${ssid}...
                </div>
            `;
        }
        
        // Connect to network
        const data = await postAPI('/api/wifi/connect', {
            ssid: ssid,
            password: password,
            save: saveNetwork
        });
        
        if (data.success) {
            // Success
            if (statusDiv) {
                statusDiv.innerHTML = `
                    <div class="bg-green-600 rounded p-3 text-sm">
                        <svg class="w-4 h-4 inline mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                        </svg>
                        ${data.message || 'Connected successfully!'}
                    </div>
                `;
            }
            
            addConsoleMessage(`Connected to Wi-Fi: ${ssid}`, 'success');
            
            // Close modal after 2 seconds
            setTimeout(() => {
                closeWifiConnectModal();
                refreshWifiStatus();
            }, 2000);
            
        } else {
            // Failed
            if (statusDiv) {
                statusDiv.innerHTML = `
                    <div class="bg-red-600 rounded p-3 text-sm">
                        <svg class="w-4 h-4 inline mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                        </svg>
                        ${data.message || 'Connection failed'}
                    </div>
                `;
            }
            
            addConsoleMessage(`Failed to connect to Wi-Fi: ${ssid}`, 'error');
            
            // If this was a known network, show password field for retry
            if (isKnown && passwordSection) {
                passwordSection.style.display = 'block';
                if (passwordInput) {
                    passwordInput.value = '';
                    passwordInput.placeholder = 'Stored password failed - enter correct password';
                }
                // Update the network state so next attempt uses the password
                if (selectedWifiNetwork) {
                    selectedWifiNetwork.isKnown = false;
                }
            }
        }
        
    } catch (error) {
        console.error('Error connecting to Wi-Fi:', error);
        
        if (statusDiv) {
            statusDiv.classList.remove('hidden');
            statusDiv.innerHTML = `
                <div class="bg-red-600 rounded p-3 text-sm">
                    Error: ${error.message}
                </div>
            `;
        }
        
        addConsoleMessage(`Error connecting to Wi-Fi: ${error.message}`, 'error');
        
        // Show password field on connection error for known networks
        if (isKnown && passwordSection) {
            passwordSection.style.display = 'block';
            if (passwordInput) {
                passwordInput.value = '';
                passwordInput.placeholder = 'Connection error - please enter password';
            }
            // Update the network state
            if (selectedWifiNetwork) {
                selectedWifiNetwork.isKnown = false;
            }
        }
        
    } finally {
        // Re-enable submit button
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.innerHTML = 'Connect';
        }
    }
}

async function loadConsoleLogs() {
    try {
        const data = await fetchAPI('/api/logs');
        if (data && data.logs) {
            updateConsole(data.logs);
        }
    } catch (error) {
        console.error('Error loading console logs:', error);
        // Add fallback console messages if log loading fails
        addConsoleMessage('Unable to load historical logs from server', 'warning');
        addConsoleMessage('Console will show new messages as they occur', 'info');
    }
}

// ============================================================================
// BLUETOOTH MANAGEMENT FUNCTIONS
// ============================================================================

// Global variables for Bluetooth
let currentBluetoothDevices = [];
let isBluetoothScanning = false;
let bluetoothScanInterval = null;

async function refreshBluetoothStatus() {
    try {
        const data = await fetchAPI('/api/bluetooth/status');
        updateBluetoothStatus(data);
    } catch (error) {
        console.error('Error refreshing Bluetooth status:', error);
        updateBluetoothStatus({
            enabled: false,
            discoverable: false,
            error: 'Failed to get Bluetooth status'
        });
    }
}

function updateBluetoothStatus(data) {
    const statusIndicator = document.getElementById('bluetooth-status-indicator');
    const infoDiv = document.getElementById('bluetooth-info');
    const powerBtn = document.getElementById('bluetooth-power-btn');
    const powerText = document.getElementById('bluetooth-power-text');
    const discoverableBtn = document.getElementById('bluetooth-discoverable-btn');
    const discoverableText = document.getElementById('bluetooth-discoverable-text');
    
    if (!statusIndicator || !infoDiv || !powerBtn || !powerText) return;
    
    if (data.error) {
        statusIndicator.className = 'text-sm px-2 py-1 rounded bg-red-700 text-red-300';
        statusIndicator.textContent = 'Error';
        infoDiv.textContent = data.error;
        powerText.textContent = 'Enable Bluetooth';
        if (discoverableText) discoverableText.textContent = 'Make Discoverable';
        return;
    }
    
    if (data.enabled) {
        statusIndicator.className = 'text-sm px-2 py-1 rounded bg-green-700 text-green-300';
        statusIndicator.textContent = 'Enabled';
        powerText.textContent = 'Disable Bluetooth';
        powerBtn.className = 'w-full bg-red-600 hover:bg-red-700 text-white py-2 px-4 rounded transition-colors';
        
        let infoText = 'Bluetooth is enabled';
        if (data.address) {
            infoText += ` | Address: ${data.address}`;
        }
        if (data.name) {
            infoText += ` | Name: ${data.name}`;
        }
        infoDiv.textContent = infoText;
        
        if (discoverableBtn && discoverableText) {
            if (data.discoverable) {
                discoverableText.textContent = 'Hide Device';
                discoverableBtn.className = 'w-full bg-orange-600 hover:bg-orange-700 text-white py-2 px-4 rounded transition-colors';
            } else {
                discoverableText.textContent = 'Make Discoverable';
                discoverableBtn.className = 'w-full bg-cyan-600 hover:bg-cyan-700 text-white py-2 px-4 rounded transition-colors';
            }
            discoverableBtn.disabled = false;
        }
    } else {
        statusIndicator.className = 'text-sm px-2 py-1 rounded bg-gray-700 text-gray-300';
        statusIndicator.textContent = 'Disabled';
        infoDiv.textContent = 'Bluetooth is disabled';
        powerText.textContent = 'Enable Bluetooth';
        powerBtn.className = 'w-full bg-green-600 hover:bg-green-700 text-white py-2 px-4 rounded transition-colors';
        
        if (discoverableBtn && discoverableText) {
            discoverableText.textContent = 'Make Discoverable';
            discoverableBtn.className = 'w-full bg-gray-600 hover:bg-gray-700 text-white py-2 px-4 rounded transition-colors';
            discoverableBtn.disabled = true;
        }
    }
}

async function toggleBluetoothPower() {
    const powerBtn = document.getElementById('bluetooth-power-btn');
    const powerText = document.getElementById('bluetooth-power-text');
    
    if (!powerBtn || !powerText) return;
    
    const originalText = powerText.textContent;
    powerText.textContent = 'Processing...';
    powerBtn.disabled = true;
    
    try {
        const isEnabled = originalText === 'Disable Bluetooth';
        const endpoint = isEnabled ? '/api/bluetooth/disable' : '/api/bluetooth/enable';
        
        const response = await postAPI(endpoint, {});
        
        if (response.success) {
            addConsoleMessage(`Bluetooth ${isEnabled ? 'disabled' : 'enabled'} successfully`, 'success');
            setTimeout(refreshBluetoothStatus, 1000);
        } else {
            throw new Error(response.error || 'Failed to toggle Bluetooth');
        }
    } catch (error) {
        console.error('Error toggling Bluetooth power:', error);
        addConsoleMessage(`Error toggling Bluetooth: ${error.message}`, 'error');
        powerText.textContent = originalText;
    } finally {
        powerBtn.disabled = false;
        if (powerText.textContent === 'Processing...') {
            powerText.textContent = originalText;
        }
    }
}

async function toggleBluetoothDiscoverable() {
    const discoverableBtn = document.getElementById('bluetooth-discoverable-btn');
    const discoverableText = document.getElementById('bluetooth-discoverable-text');
    
    if (!discoverableBtn || !discoverableText) return;
    
    const originalText = discoverableText.textContent;
    discoverableText.textContent = 'Processing...';
    discoverableBtn.disabled = true;
    
    try {
        const isDiscoverable = originalText === 'Hide Device';
        const endpoint = isDiscoverable ? '/api/bluetooth/discoverable/off' : '/api/bluetooth/discoverable/on';
        
        const response = await postAPI(endpoint, {});
        
        if (response.success) {
            addConsoleMessage(`Bluetooth ${isDiscoverable ? 'hidden' : 'made discoverable'}`, 'success');
            setTimeout(refreshBluetoothStatus, 1000);
        } else {
            throw new Error(response.error || 'Failed to toggle discoverable mode');
        }
    } catch (error) {
        console.error('Error toggling Bluetooth discoverable:', error);
        addConsoleMessage(`Error toggling discoverable mode: ${error.message}`, 'error');
        discoverableText.textContent = originalText;
    } finally {
        discoverableBtn.disabled = false;
        if (discoverableText.textContent === 'Processing...') {
            discoverableText.textContent = originalText;
        }
    }
}

async function startBluetoothScan() {
    const scanBtn = document.getElementById('bluetooth-scan-btn');
    const scanText = document.getElementById('bluetooth-scan-text');
    const scanStatus = document.getElementById('bluetooth-scan-status');
    
    if (!scanBtn || !scanText || !scanStatus) return;
    
    if (isBluetoothScanning) {
        stopBluetoothScan();
        return;
    }
    
    isBluetoothScanning = true;
    scanText.textContent = 'Stop Scan';
    scanBtn.className = 'w-full bg-red-600 hover:bg-red-700 text-white py-2 px-4 rounded transition-colors mb-2';
    scanStatus.className = 'text-sm px-2 py-1 rounded bg-blue-700 text-blue-300';
    scanStatus.textContent = 'Scanning...';
    
    try {
        const response = await postAPI('/api/bluetooth/scan/start', {});
        
        if (response.success) {
            addConsoleMessage('Started Bluetooth device scan', 'info');
            
            // Immediately fetch and display devices
            try {
                const initialDevices = await fetchAPI('/api/bluetooth/devices');
                displayBluetoothDevices(initialDevices.devices || []);
            } catch (error) {
                console.error('Error getting initial Bluetooth devices:', error);
            }
            
            // Start periodic refresh to get discovered devices
            bluetoothScanInterval = setInterval(async () => {
                try {
                    const devices = await fetchAPI('/api/bluetooth/devices');
                    displayBluetoothDevices(devices.devices || []);
                } catch (error) {
                    console.error('Error getting Bluetooth devices:', error);
                }
            }, 2000);
            
        } else {
            throw new Error(response.error || 'Failed to start Bluetooth scan');
        }
    } catch (error) {
        console.error('Error starting Bluetooth scan:', error);
        addConsoleMessage(`Error starting Bluetooth scan: ${error.message}`, 'error');
        stopBluetoothScan();
    }
}

function stopBluetoothScan() {
    const scanBtn = document.getElementById('bluetooth-scan-btn');
    const scanText = document.getElementById('bluetooth-scan-text');
    const scanStatus = document.getElementById('bluetooth-scan-status');
    
    isBluetoothScanning = false;
    
    if (bluetoothScanInterval) {
        clearInterval(bluetoothScanInterval);
        bluetoothScanInterval = null;
    }
    
    if (scanBtn && scanText && scanStatus) {
        scanText.textContent = 'Start Scan';
        scanBtn.className = 'w-full bg-indigo-600 hover:bg-indigo-700 text-white py-2 px-4 rounded transition-colors mb-2';
        scanStatus.className = 'text-sm px-2 py-1 rounded bg-gray-700 text-gray-300';
        scanStatus.textContent = 'Ready';
    }
    
    // Stop the scan on the server
    postAPI('/api/bluetooth/scan/stop', {}).catch(error => {
    }).catch(error => {
        console.error('Error stopping Bluetooth scan:', error);
    });
    
    addConsoleMessage('Stopped Bluetooth device scan', 'info');
}

function displayBluetoothDevices(devices) {
    const devicesList = document.getElementById('bluetooth-devices-list');
    if (!devicesList) return;
    
    currentBluetoothDevices = devices;
    
    if (!devices || devices.length === 0) {
        devicesList.innerHTML = `
            <div class="text-center text-gray-400 py-8">
                ${isBluetoothScanning ? 'Scanning for devices...' : 'No devices found. Start a scan to discover nearby devices.'}
            </div>
        `;
        return;
    }
    
    devicesList.innerHTML = devices.map(device => `
        <div class="glass rounded-lg p-3 hover:bg-slate-700 transition-colors cursor-pointer"
             onclick="showBluetoothDeviceDetails('${device.address}')">
            <div class="flex items-center justify-between">
                <div class="flex-1">
                    <div class="font-medium text-white">
                        ${escapeHtml(device.name || 'Unknown Device')}
                    </div>
                    <div class="text-sm text-gray-400">
                        ${device.address} ${device.rssi ? `• ${device.rssi} dBm` : ''}
                    </div>
                    ${device.device_class ? `
                        <div class="text-xs text-gray-500 mt-1">
                            ${escapeHtml(device.device_class)}
                        </div>
                    ` : ''}
                </div>
                <div class="flex items-center space-x-2">
                    ${device.rssi ? `
                        <div class="text-xs px-2 py-1 rounded ${getRSSIClass(device.rssi)}">
                            ${device.rssi} dBm
                        </div>
                    ` : ''}
                    ${device.paired ? `
                        <div class="text-xs px-2 py-1 rounded bg-green-700 text-green-300">
                            Paired
                        </div>
                    ` : ''}
                </div>
            </div>
        </div>
    `).join('');
}

function getRSSIClass(rssi) {
    if (rssi >= -40) return 'bg-green-700 text-green-300';
    if (rssi >= -60) return 'bg-yellow-700 text-yellow-300';
    if (rssi >= -80) return 'bg-orange-700 text-orange-300';
    return 'bg-red-700 text-red-300';
}

function showBluetoothDeviceDetails(address) {
    const device = currentBluetoothDevices.find(d => d.address === address);
    if (!device) return;
    
    const modal = document.getElementById('bluetooth-device-modal');
    const nameInput = document.getElementById('bt-device-name');
    const macInput = document.getElementById('bt-device-mac');
    const rssiInput = document.getElementById('bt-device-rssi');
    const classInput = document.getElementById('bt-device-class');
    const servicesDiv = document.getElementById('bt-device-services');
    const pairBtn = document.getElementById('bt-pair-btn');
    
    if (!modal || !nameInput || !macInput) return;
    
    nameInput.value = device.name || 'Unknown Device';
    macInput.value = device.address;
    if (rssiInput) rssiInput.value = device.rssi ? `${device.rssi} dBm` : 'Unknown';
    if (classInput) classInput.value = device.device_class || 'Unknown';
    
    if (servicesDiv) {
        if (device.services && device.services.length > 0) {
            servicesDiv.innerHTML = device.services.map(service => `
                <div class="mb-1 text-sm">${escapeHtml(service)}</div>
            `).join('');
        } else {
            servicesDiv.innerHTML = '<div class="text-gray-400">No services detected</div>';
        }
    }
    
    if (pairBtn) {
        if (device.paired) {
            pairBtn.innerHTML = `
                <svg class="w-4 h-4 inline mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path>
                </svg>
                Unpair Device
            `;
            pairBtn.className = 'bg-red-600 hover:bg-red-700 text-white py-2 px-4 rounded transition-colors';
        } else {
            pairBtn.innerHTML = `
                <svg class="w-4 h-4 inline mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path>
                </svg>
                Pair Device
            `;
            pairBtn.className = 'bg-green-600 hover:bg-green-700 text-white py-2 px-4 rounded transition-colors';
        }
        pairBtn.setAttribute('data-device-address', device.address);
    }
    
    modal.classList.remove('hidden');
    modal.classList.add('flex');
}

function closeBluetoothDeviceModal() {
    const modal = document.getElementById('bluetooth-device-modal');
    const statusDiv = document.getElementById('bt-device-status');
    
    if (modal) {
        modal.classList.add('hidden');
        modal.classList.remove('flex');
    }
    
    if (statusDiv) {
        statusDiv.classList.add('hidden');
        statusDiv.innerHTML = '';
    }
}

async function pairBluetoothDevice() {
    const pairBtn = document.getElementById('bt-pair-btn');
    const statusDiv = document.getElementById('bt-device-status');
    
    if (!pairBtn) return;
    
    const address = pairBtn.getAttribute('data-device-address');
    if (!address) return;
    
    const device = currentBluetoothDevices.find(d => d.address === address);
    if (!device) return;
    
    const originalHTML = pairBtn.innerHTML;
    pairBtn.innerHTML = 'Processing...';
    pairBtn.disabled = true;
    
    if (statusDiv) {
        statusDiv.classList.remove('hidden');
        statusDiv.innerHTML = `
            <div class="bg-blue-600 rounded p-3 text-sm">
                ${device.paired ? 'Unpairing' : 'Pairing'} device ${device.name || address}...
            </div>
        `;
    }
    
    try {
        const endpoint = device.paired ? '/api/bluetooth/unpair' : '/api/bluetooth/pair';
        const response = await fetchAPI(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                address: address
            })
        });
        
        if (response.success) {
            const action = device.paired ? 'unpaired' : 'paired';
            addConsoleMessage(`Device ${device.name || address} ${action} successfully`, 'success');
            
            if (statusDiv) {
                statusDiv.innerHTML = `
                    <div class="bg-green-600 rounded p-3 text-sm">
                        Device ${action} successfully
                    </div>
                `;
            }
            
            // Refresh the device list
            setTimeout(() => {
                if (isBluetoothScanning) {
                    fetchAPI('/api/bluetooth/devices').then(data => {
                        displayBluetoothDevices(data.devices || []);
                    }).catch(error => {
                        console.error('Error refreshing devices:', error);
                    });
                }
                closeBluetoothDeviceModal();
            }, 2000);
            
        } else {
            throw new Error(response.error || `Failed to ${device.paired ? 'unpair' : 'pair'} device`);
        }
    } catch (error) {
        console.error('Error pairing/unpairing device:', error);
        addConsoleMessage(`Error: ${error.message}`, 'error');
        
        if (statusDiv) {
            statusDiv.innerHTML = `
                <div class="bg-red-600 rounded p-3 text-sm">
                    Error: ${error.message}
                </div>
            `;
        }
    } finally {
        pairBtn.disabled = false;
        if (pairBtn.innerHTML === 'Processing...') {
            pairBtn.innerHTML = originalHTML;
        }
    }
}

async function enumerateBluetoothServices() {
    const enumerateBtn = document.getElementById('bt-enumerate-btn');
    const statusDiv = document.getElementById('bt-device-status');
    const servicesDiv = document.getElementById('bt-device-services');
    
    if (!enumerateBtn) return;
    
    const address = document.getElementById('bt-pair-btn')?.getAttribute('data-device-address');
    if (!address) return;
    
    const device = currentBluetoothDevices.find(d => d.address === address);
    if (!device) return;
    
    const originalHTML = enumerateBtn.innerHTML;
    enumerateBtn.innerHTML = 'Enumerating...';
    enumerateBtn.disabled = true;
    
    if (statusDiv) {
        statusDiv.classList.remove('hidden');
        statusDiv.innerHTML = `
            <div class="bg-blue-600 rounded p-3 text-sm">
                Enumerating services for ${device.name || address}...
            </div>
        `;
    }
    
    try {
        const response = await postAPI('/api/bluetooth/enumerate', {
            address: address
        });
        
        if (response.success && response.services) {
            addConsoleMessage(`Found ${response.services.length} services on ${device.name || address}`, 'success');
            
            if (servicesDiv) {
                if (response.services.length > 0) {
                    servicesDiv.innerHTML = response.services.map(service => `
                        <div class="mb-2 p-2 bg-slate-800 rounded text-sm">
                            <div class="font-medium">${escapeHtml(service.name || 'Unknown Service')}</div>
                            <div class="text-gray-400 text-xs">${service.uuid}</div>
                            ${service.description ? `<div class="text-gray-500 text-xs mt-1">${escapeHtml(service.description)}</div>` : ''}
                        </div>
                    `).join('');
                } else {
                    servicesDiv.innerHTML = '<div class="text-gray-400">No services found</div>';
                }
            }
            
            if (statusDiv) {
                statusDiv.innerHTML = `
                    <div class="bg-green-600 rounded p-3 text-sm">
                        Found ${response.services.length} services
                    </div>
                `;
            }
            
        } else {
            throw new Error(response.error || 'Failed to enumerate services');
        }
    } catch (error) {
        console.error('Error enumerating services:', error);
        addConsoleMessage(`Error enumerating services: ${error.message}`, 'error');
        
        if (statusDiv) {
            statusDiv.innerHTML = `
                <div class="bg-red-600 rounded p-3 text-sm">
                    Error: ${error.message}
                </div>
            `;
        }
    } finally {
        enumerateBtn.disabled = false;
        if (enumerateBtn.innerHTML === 'Enumerating...') {
            enumerateBtn.innerHTML = originalHTML;
        }
    }
}

function clearBluetoothDevices() {
    const devicesList = document.getElementById('bluetooth-devices-list');
    if (devicesList) {
        devicesList.innerHTML = `
            <div class="text-center text-gray-400 py-8">
                Start a Bluetooth scan to discover nearby devices
            </div>
        `;
    }
    currentBluetoothDevices = [];
    addConsoleMessage('Cleared Bluetooth device list', 'info');
}

// ============================================================================
// BLUETOOTH PENTEST FUNCTIONS
// ============================================================================

async function startBeaconTracking() {
    const btn = document.getElementById('beacon-track-btn');
    const resultsDiv = document.getElementById('beacon-results');
    const durationInput = document.getElementById('beacon-duration');
    
    if (!btn || !resultsDiv || !durationInput) return;
    
    const duration = parseInt(durationInput.value) || 60;
    const originalText = btn.textContent;
    
    btn.disabled = true;
    btn.textContent = 'Tracking...';
    resultsDiv.classList.remove('hidden');
    resultsDiv.textContent = `Tracking beacons for ${duration} seconds...`;
    
    try {
        const response = await postAPI('/api/bluetooth/pentest/beacon-track', { duration });
        
        if (response.success) {
            const beaconCount = response.beacons_found || 0;
            resultsDiv.innerHTML = `
                <div class="text-green-400">✓ Found ${beaconCount} beacon(s)</div>
                <div class="mt-1">${JSON.stringify(response.beacons, null, 2)}</div>
            `;
            addConsoleMessage(`Beacon tracking complete: ${beaconCount} beacons found`, 'success');
            updatePentestSummary('beacon_tracking', response);
        } else {
            throw new Error(response.error || 'Beacon tracking failed');
        }
    } catch (error) {
        console.error('Beacon tracking error:', error);
        resultsDiv.innerHTML = `<div class="text-red-400">✗ Error: ${error.message}</div>`;
        addConsoleMessage(`Beacon tracking failed: ${error.message}`, 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = originalText;
    }
}

async function startDataExfiltration() {
    const btn = document.getElementById('exfil-btn');
    const resultsDiv = document.getElementById('exfil-results');
    const targetInput = document.getElementById('exfil-target');
    
    if (!btn || !resultsDiv || !targetInput) return;
    
    const target = targetInput.value.trim();
    if (!target || !target.match(/^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/)) {
        resultsDiv.classList.remove('hidden');
        resultsDiv.innerHTML = '<div class="text-red-400">✗ Invalid MAC address format</div>';
        return;
    }
    
    const originalText = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Exfiltrating...';
    resultsDiv.classList.remove('hidden');
    resultsDiv.textContent = `Extracting data from ${target}...`;
    
    try {
        const response = await postAPI('/api/bluetooth/pentest/exfiltrate', { target });
        
        if (response.device_info) {
            const serviceCount = response.services?.length || 0;
            const fileCount = response.files?.length || 0;
            const contactCount = response.contacts?.length || 0;
            
            resultsDiv.innerHTML = `
                <div class="text-green-400">✓ Exfiltration complete</div>
                <div class="mt-1 text-xs">
                    Services: ${serviceCount} | Files: ${fileCount} | Contacts: ${contactCount}
                </div>
            `;
            addConsoleMessage(`Data exfiltration from ${target} complete`, 'success');
            updatePentestSummary('exfiltration', response);
        } else {
            throw new Error(response.error || 'Exfiltration failed');
        }
    } catch (error) {
        console.error('Exfiltration error:', error);
        resultsDiv.innerHTML = `<div class="text-red-400">✗ Error: ${error.message}</div>`;
        addConsoleMessage(`Exfiltration failed: ${error.message}`, 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = originalText;
    }
}

async function startBlueBorneScan() {
    const btn = document.getElementById('blueborne-btn');
    const resultsDiv = document.getElementById('blueborne-results');
    const targetInput = document.getElementById('blueborne-target');
    
    if (!btn || !resultsDiv || !targetInput) return;
    
    const target = targetInput.value.trim();
    if (!target || !target.match(/^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/)) {
        resultsDiv.classList.remove('hidden');
        resultsDiv.innerHTML = '<div class="text-red-400">✗ Invalid MAC address format</div>';
        return;
    }
    
    const originalText = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Scanning...';
    resultsDiv.classList.remove('hidden');
    resultsDiv.textContent = `Scanning ${target} for BlueBorne...`;
    
    try {
        const response = await postAPI('/api/bluetooth/pentest/blueborne-scan', { target });
        
        const vulnCount = response.vulnerabilities?.length || 0;
        const isVulnerable = response.vulnerable || false;
        
        resultsDiv.innerHTML = `
            <div class="${isVulnerable ? 'text-red-400' : 'text-green-400'}">
                ${isVulnerable ? '⚠ Potentially vulnerable' : '✓ No vulnerabilities detected'}
            </div>
            ${vulnCount > 0 ? `<div class="mt-1 text-xs">Found ${vulnCount} potential issue(s)</div>` : ''}
        `;
        addConsoleMessage(`BlueBorne scan of ${target} complete`, 'info');
        updatePentestSummary('blueborne_scan', response);
    } catch (error) {
        console.error('BlueBorne scan error:', error);
        resultsDiv.innerHTML = `<div class="text-red-400">✗ Error: ${error.message}</div>`;
        addConsoleMessage(`BlueBorne scan failed: ${error.message}`, 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = originalText;
    }
}

async function startMovementTracking() {
    const btn = document.getElementById('track-btn');
    const resultsDiv = document.getElementById('track-results');
    const targetInput = document.getElementById('track-target');
    const durationInput = document.getElementById('track-duration');
    
    if (!btn || !resultsDiv || !targetInput || !durationInput) return;
    
    const target = targetInput.value.trim();
    const duration = parseInt(durationInput.value) || 300;
    
    if (!target || !target.match(/^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/)) {
        resultsDiv.classList.remove('hidden');
        resultsDiv.innerHTML = '<div class="text-red-400">✗ Invalid MAC address format</div>';
        return;
    }
    
    const originalText = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Tracking...';
    resultsDiv.classList.remove('hidden');
    resultsDiv.textContent = `Tracking ${target} for ${duration}s...`;
    
    try {
        const response = await postAPI('/api/bluetooth/pentest/track-movement', { target, duration });
        
        if (response.readings && response.readings.length > 0) {
            const avgRssi = response.readings.reduce((sum, r) => sum + r.rssi, 0) / response.readings.length;
            const avgDistance = response.readings.reduce((sum, r) => sum + r.distance_estimate, 0) / response.readings.length;
            
            resultsDiv.innerHTML = `
                <div class="text-green-400">✓ Tracking complete</div>
                <div class="mt-1 text-xs">
                    Readings: ${response.readings.length} | Avg RSSI: ${avgRssi.toFixed(1)} dBm | 
                    Avg Distance: ${avgDistance.toFixed(2)}m
                </div>
            `;
            addConsoleMessage(`Movement tracking of ${target} complete`, 'success');
            updatePentestSummary('movement_tracking', response);
        } else {
            throw new Error('No readings collected');
        }
    } catch (error) {
        console.error('Movement tracking error:', error);
        resultsDiv.innerHTML = `<div class="text-red-400">✗ Error: ${error.message}</div>`;
        addConsoleMessage(`Movement tracking failed: ${error.message}`, 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = originalText;
    }
}

// Pentest summary tracking
let pentestResults = {};

function updatePentestSummary(testType, data) {
    pentestResults[testType] = {
        timestamp: new Date().toISOString(),
        data: data
    };
    
    const summaryDiv = document.getElementById('pentest-summary');
    const contentDiv = document.getElementById('pentest-summary-content');
    
    if (!summaryDiv || !contentDiv) return;
    
    summaryDiv.classList.remove('hidden');
    
    const summaryLines = [];
    if (pentestResults.beacon_tracking) {
        summaryLines.push(`Beacon Tracking: ${pentestResults.beacon_tracking.data.beacons_found || 0} beacons found`);
    }
    if (pentestResults.exfiltration) {
        const d = pentestResults.exfiltration.data;
        summaryLines.push(`Data Exfiltration: ${d.services?.length || 0} services, ${d.files?.length || 0} files`);
    }
    if (pentestResults.blueborne_scan) {
        const vulnerable = pentestResults.blueborne_scan.data.vulnerable ? 'Vulnerable' : 'Safe';
        summaryLines.push(`BlueBorne Scan: ${vulnerable}`);
    }
    if (pentestResults.movement_tracking) {
        const count = pentestResults.movement_tracking.data.readings?.length || 0;
        summaryLines.push(`Movement Tracking: ${count} readings collected`);
    }
    if (pentestResults.airsnitch) {
        const d = pentestResults.airsnitch.data;
        const state = d.network_isolated ? 'Isolated ✓' : `${d.vulnerable_count}/${d.total_tests} failed ✗`;
        summaryLines.push(`AirSnitch: ${state}`);
    }

    contentDiv.innerHTML = summaryLines.map(line => `<div>• ${line}</div>`).join('');
}

async function downloadPentestReport() {
    try {
        const response = await fetchAPI('/api/bluetooth/pentest/report');
        
        if (response && response.timestamp) {
            const blob = new Blob([JSON.stringify(response, null, 2)], { type: 'application/json' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `bluetooth_pentest_${Date.now()}.json`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            
            addConsoleMessage('Pentest report downloaded', 'success');
        } else {
            throw new Error('No report data available');
        }
    } catch (error) {
        console.error('Report download error:', error);
        addConsoleMessage(`Failed to download report: ${error.message}`, 'error');
    }
}

// ============================================================================
// AIRSNITCH – Wi-Fi Client Isolation Testing
// ============================================================================

async function populateAirSnitchInterfaceDropdowns() {
    const victimSel   = document.getElementById('airsnitch-iface-victim');
    const attackerSel = document.getElementById('airsnitch-iface-attacker');
    if (!victimSel || !attackerSel) return;

    try {
        const [wifiData, ethData] = await Promise.allSettled([
            fetchAPI('/api/wifi/interfaces'),
            fetchAPI('/api/ethernet/interfaces'),
        ]);

        const ifaces = [];
        if (wifiData.status === 'fulfilled' && Array.isArray(wifiData.value?.interfaces)) {
            wifiData.value.interfaces.forEach(i => {
                const label = i.connected_ssid
                    ? `${i.name} — ${i.connected_ssid} (${i.state})`
                    : `${i.name} — ${i.state}`;
                ifaces.push({ value: i.name, label });
            });
        }
        if (ethData.status === 'fulfilled' && Array.isArray(ethData.value?.interfaces)) {
            ethData.value.interfaces.forEach(i => {
                const label = `${i.name} — ${i.state || (i.connected ? 'connected' : 'disconnected')}`;
                ifaces.push({ value: i.name, label });
            });
        }

        if (ifaces.length === 0) return;

        const prevVictim   = victimSel.value;
        const prevAttacker = attackerSel.value;

        [victimSel, attackerSel].forEach(sel => {
            sel.innerHTML = '';
            ifaces.forEach(({ value, label }) => {
                const opt = document.createElement('option');
                opt.value = value;
                opt.textContent = label;
                sel.appendChild(opt);
            });
        });

        // Restore previous selection if still available
        if (ifaces.some(i => i.value === prevVictim))   victimSel.value   = prevVictim;
        if (ifaces.some(i => i.value === prevAttacker)) attackerSel.value = prevAttacker;
    } catch (e) {
        // Leave defaults in place on error
    }
}

async function checkAirSnitchInstalled() {
    try {
        const data = await fetchAPI('/api/airsnitch/status');
        const notice = document.getElementById('airsnitch-install-notice');
        if (notice) {
            notice.classList.toggle('hidden', data.installed !== false);
        }
        return data.installed;
    } catch (e) {
        return null;
    }
}

async function installAirSnitch() {
    const btn       = document.getElementById('airsnitch-install-btn');
    const statusDiv = document.getElementById('airsnitch-status');
    const logDiv    = document.getElementById('airsnitch-install-log');

    if (btn)    { btn.disabled = true; btn.textContent = 'Installing…'; }
    if (logDiv) { logDiv.classList.remove('hidden'); logDiv.textContent = ''; }
    if (statusDiv) { statusDiv.classList.remove('hidden'); statusDiv.textContent = 'Starting installation…'; }

    try {
        const data = await postAPI('/api/airsnitch/install', {});
        if (!data.success) throw new Error(data.error || 'Install request failed');
        if (statusDiv) statusDiv.textContent = data.message || 'Installation running…';
        addConsoleMessage('AirSnitch installation started', 'info');

        // Poll the install log every 2 seconds until done
        await _pollAirSnitchInstallLog(btn, statusDiv, logDiv);
    } catch (e) {
        if (statusDiv) { statusDiv.classList.remove('hidden'); statusDiv.textContent = `Install failed: ${e.message}`; }
        if (logDiv)    { logDiv.textContent += `\nERROR: ${e.message}`; }
        addConsoleMessage(`AirSnitch install failed: ${e.message}`, 'error');
        if (btn) { btn.disabled = false; btn.textContent = 'Retry Install'; }
    }
}

async function _pollAirSnitchInstallLog(btn, statusDiv, logDiv) {
    return new Promise((resolve) => {
        const interval = setInterval(async () => {
            try {
                const data = await fetchAPI('/api/airsnitch/install-log');
                if (logDiv && data.log !== undefined) {
                    logDiv.textContent = data.log;
                    logDiv.scrollTop = logDiv.scrollHeight;
                }
                if (!data.installing) {
                    clearInterval(interval);
                    if (data.installed) {
                        if (statusDiv) statusDiv.textContent = 'Installation complete.';
                        if (btn) { btn.disabled = false; btn.textContent = 'Installed ✓'; }
                        // Hide the install notice since it's now installed
                        const notice = document.getElementById('airsnitch-install-notice');
                        if (notice) notice.classList.add('hidden');
                        addConsoleMessage('AirSnitch installed successfully', 'success');
                    } else {
                        if (statusDiv) statusDiv.textContent = 'Installation failed – see log above.';
                        if (btn) { btn.disabled = false; btn.textContent = 'Retry Install'; }
                        addConsoleMessage('AirSnitch installation failed', 'error');
                    }
                    resolve();
                }
            } catch (e) {
                clearInterval(interval);
                if (btn) { btn.disabled = false; btn.textContent = 'Retry Install'; }
                resolve();
            }
        }, 2000);
    });
}

async function runAirSnitch() {
    const btn = document.getElementById('airsnitch-run-btn');
    const statusDiv = document.getElementById('airsnitch-status');

    const ifaceVictim   = document.getElementById('airsnitch-iface-victim')?.value.trim()   || 'wlan1';
    const ifaceAttacker = document.getElementById('airsnitch-iface-attacker')?.value.trim() || 'wlan2';
    const server        = document.getElementById('airsnitch-server')?.value.trim()          || '8.8.8.8';
    const sameBss       = document.getElementById('airsnitch-same-bss')?.checked             || false;
    const tests         = [...document.querySelectorAll('.airsnitch-test-check:checked')].map(cb => cb.value);
    const victimSsid    = document.getElementById('airsnitch-victim-ssid')?.value.trim()    || '';
    const victimPsk     = document.getElementById('airsnitch-victim-psk')?.value            || '';
    const attackerSsid  = document.getElementById('airsnitch-attacker-ssid')?.value.trim()  || '';
    const attackerPsk   = document.getElementById('airsnitch-attacker-psk')?.value          || '';

    if (tests.length === 0) {
        if (statusDiv) { statusDiv.classList.remove('hidden'); statusDiv.textContent = 'Select at least one test.'; }
        return;
    }

    const originalText = btn?.textContent || 'Run AirSnitch';
    if (btn) { btn.disabled = true; btn.textContent = 'Running…'; }
    if (statusDiv) { statusDiv.classList.remove('hidden'); statusDiv.textContent = 'Tests running in background…'; }

    try {
        const body = {
            iface_victim: ifaceVictim,
            iface_attacker: ifaceAttacker,
            server: server,
            same_bss: sameBss,
            tests: tests,
        };
        if (victimSsid)   body.victim_ssid    = victimSsid;
        if (victimPsk)    body.victim_psk     = victimPsk;
        if (attackerSsid) body.attacker_ssid  = attackerSsid;
        if (attackerPsk)  body.attacker_psk   = attackerPsk;
        const data = await postAPI('/api/airsnitch/run', body);
        if (statusDiv) statusDiv.textContent = data.message || 'Started.';
        addConsoleMessage('AirSnitch tests started', 'info');

        // Poll for results after a short delay
        setTimeout(refreshAirSnitchResults, 10000);
    } catch (e) {
        if (statusDiv) statusDiv.textContent = `Error: ${e.message}`;
        addConsoleMessage(`AirSnitch failed: ${e.message}`, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = originalText; }
    }
}

async function refreshAirSnitchResults() {
    try {
        const data = await fetchAPI('/api/airsnitch/results');
        const resultsDiv   = document.getElementById('airsnitch-results');
        const contentDiv   = document.getElementById('airsnitch-results-content');
        if (!resultsDiv || !contentDiv) return;

        if (!data.results) {
            return; // No results yet – keep panel hidden
        }

        resultsDiv.classList.remove('hidden');
        const r = data.results;
        const summary = r.summary || {};
        const lines = [];

        lines.push(`<div class="text-gray-400">⏱ ${r.timestamp || ''}</div>`);
        lines.push(`<div>Interfaces: victim=<span class="text-cyan-400">${r.iface_victim}</span> attacker=<span class="text-cyan-400">${r.iface_attacker}</span></div>`);

        if (summary.network_isolated === true) {
            lines.push(`<div class="text-green-400 font-bold">✓ Network PASSES client isolation (${summary.total_tests} tests)</div>`);
        } else if (summary.vulnerable_count > 0) {
            lines.push(`<div class="text-red-400 font-bold">✗ Network FAILS client isolation – ${summary.vulnerable_count}/${summary.total_tests} test(s) vulnerable</div>`);
        }

        for (const [name, result] of Object.entries(r.tests || {})) {
            const icon  = result.vulnerable ? '✗' : '✓';
            const color = result.vulnerable ? 'text-red-400' : 'text-green-400';
            const label = name.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
            lines.push(`<div class="${color}">${icon} ${label}</div>`);
        }

        contentDiv.innerHTML = lines.join('');

        // Feed into pentest summary
        updatePentestSummary('airsnitch', {
            vulnerable_count: summary.vulnerable_count || 0,
            total_tests: summary.total_tests || 0,
            network_isolated: summary.network_isolated,
        });
    } catch (e) {
        console.error('AirSnitch results error:', e);
    }
}

// ============================================================================
// MANUAL MODE FUNCTIONS
// ============================================================================

const DEFAULT_MANUAL_ATTACK_MATRIX = {
    ssh: { label: 'SSH Brute Force', ports: ['22'] },
    ftp: { label: 'FTP Brute Force', ports: ['21'] },
    telnet: { label: 'Telnet Brute Force', ports: ['23'] },
    smb: { label: 'SMB Brute Force', ports: ['139', '445'] },
    rdp: { label: 'RDP Brute Force', ports: ['3389'] },
    sql: { label: 'SQL Brute Force', ports: ['3306'] }
};

if (typeof window !== 'undefined') {
    window.manualAttackMatrix = { ...DEFAULT_MANUAL_ATTACK_MATRIX };
    window.manualActionPreference = '';
}

function hydrateManualAttackMatrix(serverMatrix) {
    const matrix = {};
    const mergedKeys = new Set([
        ...Object.keys(DEFAULT_MANUAL_ATTACK_MATRIX),
        ...(serverMatrix ? Object.keys(serverMatrix) : [])
    ]);

    mergedKeys.forEach(key => {
        const fallback = DEFAULT_MANUAL_ATTACK_MATRIX[key] || {};
        const incoming = (serverMatrix && serverMatrix[key]) || {};
        const label = incoming.label || fallback.label || `${key.toUpperCase()} Attack`;
        const fallbackPorts = Array.isArray(fallback.ports) ? fallback.ports : [];
        const incomingPorts = Array.isArray(incoming.ports) ? incoming.ports : [];
        const ports = (incomingPorts.length ? incomingPorts : fallbackPorts).map(port => String(port));

        if (ports.length) {
            matrix[key] = { label, ports }; 
        }
    });

    return Object.keys(matrix).length ? matrix : { ...DEFAULT_MANUAL_ATTACK_MATRIX };
}

function getManualAttackMatrix() {
    return window.manualAttackMatrix || { ...DEFAULT_MANUAL_ATTACK_MATRIX };
}

function getValidActionsForPort(port) {
    if (!port) {
        return [];
    }
    const normalizedPort = String(port).trim();
    const matrix = getManualAttackMatrix();
    return Object.entries(matrix)
        .filter(([, config]) => Array.isArray(config.ports) && config.ports.map(String).includes(normalizedPort))
        .map(([action, config]) => ({ key: action, label: config.label || action.toUpperCase() }));
}

function isActionAllowedOnPort(action, port) {
    if (!action || !port) {
        return false;
    }
    const normalizedPort = String(port).trim();
    const matrix = getManualAttackMatrix();
    const config = matrix[action];
    return Boolean(config && config.ports && config.ports.map(String).includes(normalizedPort));
}

function setManualActionHelper(message, tone = 'muted') {
    const helper = document.getElementById('manual-action-helper');
    if (!helper) {
        return;
    }

    const toneClasses = {
        muted: 'text-gray-500',
        warning: 'text-yellow-400',
        error: 'text-red-400',
        success: 'text-green-400'
    };

    helper.textContent = message;
    helper.className = `text-[11px] mt-1 ${toneClasses[tone] || toneClasses.muted}`;
}

function syncManualModeUI(isManualMode) {
    manualModeActive = isManualMode;

    const manualHint = document.getElementById('manual-mode-hint');
    if (manualHint) {
        manualHint.classList.toggle('hidden', isManualMode);
    }

    document.querySelectorAll('.pentest-nav-btn').forEach(btn => {
        btn.classList.toggle('hidden', !isManualMode);
    });
    if (window._updateNavMode) window._updateNavMode();

    if (!isManualMode && currentTab === 'pentest') {
        showTab('dashboard');
    }

    if (isManualMode) {
        if (!manualDataPrimed) {
            loadManualModeData();
            manualDataPrimed = true;
        }
    } else {
        manualDataPrimed = false;
    }
}

async function loadManualModeData() {
    try {
        // Store current selections before reloading
        const currentIp = document.getElementById('manual-ip-dropdown')?.value || '';
        const currentPort = document.getElementById('manual-port-dropdown')?.value || '';
        const currentAction = document.getElementById('manual-action-dropdown')?.value || '';
        const currentVulnIp = document.getElementById('vuln-ip-dropdown')?.value || 'all';
        
        const data = await fetchAPI('/api/manual/targets');

        window.manualAttackMatrix = hydrateManualAttackMatrix(data.attack_matrix);
        window.manualActionPreference = currentAction;
        
        // Populate IP dropdown
        const ipDropdown = document.getElementById('manual-ip-dropdown');
        if (ipDropdown) {
            ipDropdown.innerHTML = '<option value="">Select IP</option>';
            if (data.targets && data.targets.length > 0) {
                data.targets.forEach(target => {
                    const option = document.createElement('option');
                    option.value = target.ip;
                    option.textContent = `${target.ip} (${target.hostname})`;
                    if (target.ip === currentIp) {
                        option.selected = true;
                    }
                    ipDropdown.appendChild(option);
                });
            }
        }
        
        // Populate vulnerability scan IP dropdown
        const vulnIpDropdown = document.getElementById('vuln-ip-dropdown');
        if (vulnIpDropdown) {
            vulnIpDropdown.innerHTML = '';

            const allOption = document.createElement('option');
            allOption.value = 'all';
            allOption.textContent = 'All Targets';
            if (currentVulnIp === 'all' || !currentVulnIp) {
                allOption.selected = true;
            }
            vulnIpDropdown.appendChild(allOption);

            if (data.targets && data.targets.length > 0) {
                data.targets.forEach(target => {
                    const option = document.createElement('option');
                    option.value = target.ip;
                    option.textContent = `${target.ip} (${target.hostname})`;
                    if (target.ip === currentVulnIp) {
                        option.selected = true;
                    }
                    vulnIpDropdown.appendChild(option);
                });
            }
        }
        
        // Populate action dropdown with available attack types
        const actionDropdown = document.getElementById('manual-action-dropdown');
        if (actionDropdown) {
            actionDropdown.innerHTML = '<option value="">Select Action</option>';
            actionDropdown.disabled = true;
        }
        
        // Store targets data for updateManualPorts function
        window.manualTargetsData = data.targets || [];
        
        // Restore port selection if IP was selected
        if (currentIp) {
            updateManualPorts();
            // Restore port selection after ports are populated
            setTimeout(() => {
                const portDropdown = document.getElementById('manual-port-dropdown');
                if (portDropdown && currentPort) {
                    portDropdown.value = currentPort;
                }
                updateManualActions();
            }, 50);
        } else {
            updateManualActions();
        }
        
    } catch (error) {
        console.error('Error loading Pentest Mode data:', error);
        addConsoleMessage('Failed to load Pentest Mode data', 'error');
    }
}

async function loadPentestData() {
    try {
        await loadManualModeData();
        await refreshBluetoothStatus();
    } catch (error) {
        console.error('Error loading pentest data:', error);
        addConsoleMessage('Failed to load pentest data', 'error');
    }
}

function updateManualPorts() {
    const ipDropdown = document.getElementById('manual-ip-dropdown');
    const portDropdown = document.getElementById('manual-port-dropdown');
    
    if (!ipDropdown || !portDropdown) return;
    
    const selectedIp = ipDropdown.value;
    portDropdown.innerHTML = '<option value="">Select Port</option>';
    
    if (selectedIp && window.manualTargetsData) {
        // Find the target with the selected IP
        const target = window.manualTargetsData.find(t => t.ip === selectedIp);
        if (target && target.ports) {
            target.ports.forEach(port => {
                const option = document.createElement('option');
                option.value = port;
                option.textContent = port;
                portDropdown.appendChild(option);
            });
        }
    }

    if (portDropdown) {
        portDropdown.value = '';
    }

    updateManualActions();
}

function updateManualActions() {
    const portDropdown = document.getElementById('manual-port-dropdown');
    const actionDropdown = document.getElementById('manual-action-dropdown');

    if (!actionDropdown) {
        return;
    }

    const selectedPort = portDropdown ? portDropdown.value : '';
    const previousSelection = window.manualActionPreference || actionDropdown.value || '';

    actionDropdown.innerHTML = '<option value="">Select Action</option>';
    actionDropdown.disabled = true;

    if (!selectedPort) {
        setManualActionHelper('Select a port to view compatible attack modules.', 'muted');
        return;
    }

    const validActions = getValidActionsForPort(selectedPort);

    if (!validActions.length) {
        setManualActionHelper(`No supported attack modules detected for port ${selectedPort}.`, 'warning');
        window.manualActionPreference = '';
        return;
    }

    validActions.forEach(action => {
        const option = document.createElement('option');
        option.value = action.key;
        option.textContent = action.label;
        actionDropdown.appendChild(option);
    });

    actionDropdown.disabled = false;

    if (previousSelection && validActions.some(action => action.key === previousSelection)) {
        actionDropdown.value = previousSelection;
    } else {
        actionDropdown.value = '';
        window.manualActionPreference = '';
    }

    if (actionDropdown.value) {
        window.manualActionPreference = actionDropdown.value;
        setManualActionHelper(`${actionDropdown.options[actionDropdown.selectedIndex].text} ready for port ${selectedPort}.`, 'success');
    } else {
        setManualActionHelper(`Found ${validActions.length} compatible ${validActions.length === 1 ? 'action' : 'actions'} on port ${selectedPort}. Choose one to proceed.`, 'success');
    }
}

const MANUAL_ATTACK_LOG_LIMIT = 40;

function setManualAttackStatus(message, type = 'info') {
    const statusWrap = document.getElementById('manual-attack-status');
    const statusMessage = document.getElementById('manual-attack-status-message');
    if (!statusWrap || !statusMessage) return;

    const styles = {
        success: 'border-green-500/40 bg-green-900/30 text-green-200',
        error: 'border-red-500/50 bg-red-900/40 text-red-200',
        warning: 'border-yellow-500/40 bg-yellow-900/30 text-yellow-200',
        info: 'border-slate-700 bg-slate-900/70 text-gray-200'
    };

    statusWrap.classList.remove('hidden');
    statusMessage.className = `rounded-lg px-4 py-3 text-sm ${styles[type] || styles.info}`;
    statusMessage.textContent = message;
}

function appendManualAttackLog(message, type = 'info') {
    const logContainer = document.getElementById('manual-attack-live-log');
    if (!logContainer) return;

    const colors = {
        success: 'text-green-300',
        error: 'text-red-300',
        warning: 'text-yellow-300',
        info: 'text-gray-300'
    };

    if (logContainer.dataset.initialized !== 'true') {
        logContainer.innerHTML = '';
        logContainer.dataset.initialized = 'true';
    }

    logContainer.classList.remove('hidden');
    const line = document.createElement('div');
    line.className = `flex text-xs font-mono ${colors[type] || colors.info}`;
    line.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
    logContainer.appendChild(line);

    while (logContainer.childElementCount > MANUAL_ATTACK_LOG_LIMIT) {
        logContainer.removeChild(logContainer.firstChild);
    }

    logContainer.scrollTop = logContainer.scrollHeight;
}

function handleManualAttackUpdate(update) {
    if (!update || (!update.action && !update.ip)) {
        return;
    }

    const severity = update.status || 'info';
    const stage = update.stage || 'info';
    const actionLabel = (update.action || 'attack').toUpperCase();
    const targetLabel = update.ip ? `${update.ip}${update.port ? `:${update.port}` : ''}` : 'target';
    const body = update.message || `${actionLabel} update`;
    const composedMessage = `${actionLabel} on ${targetLabel} • ${body}`;

    appendManualAttackLog(composedMessage, severity);

    if (stage === 'running') {
        setManualAttackStatus(body, 'info');
    } else if (stage === 'completed') {
        setManualAttackStatus(body, severity);
    } else if (stage === 'error') {
        setManualAttackStatus(body, 'error');
    } else if (stage === 'queued') {
        setManualAttackStatus(body, 'info');
    }
}

async function executeManualAttack() {
    const ip = document.getElementById('manual-ip-dropdown')?.value;
    const port = document.getElementById('manual-port-dropdown')?.value;
    const action = document.getElementById('manual-action-dropdown')?.value;
    const launchBtn = document.getElementById('manual-attack-launch-btn');

    const setButtonState = (busy, label) => {
        if (!launchBtn) return;
        launchBtn.disabled = !!busy;
        launchBtn.classList.toggle('cursor-wait', !!busy);
        if (busy) {
            launchBtn.classList.remove('bg-orange-600', 'hover:bg-orange-700');
            launchBtn.classList.add('bg-orange-500');
        } else {
            launchBtn.classList.remove('bg-orange-500');
            launchBtn.classList.add('bg-orange-600', 'hover:bg-orange-700');
        }
        launchBtn.textContent = label || (busy ? 'Launching...' : 'Execute Attack');
    };
    
    if (!ip || !port || !action) {
        addConsoleMessage('Please select IP, Port, and Action for manual attack', 'error');
        setManualAttackStatus('Please select a target IP, port, and action before launching.', 'error');
        appendManualAttackLog('Manual attack aborted - missing selections.', 'error');
        return;
    }

    if (!isActionAllowedOnPort(action, port)) {
        const matrix = getManualAttackMatrix();
        const allowedPorts = (matrix[action]?.ports || []).join(', ');
        const errorMessage = `${action.toUpperCase()} brute force is only available on port(s): ${allowedPorts || 'restricted'}.`;
        addConsoleMessage(errorMessage, 'error');
        setManualAttackStatus(errorMessage, 'error');
        appendManualAttackLog('Manual attack blocked due to incompatible port selection.', 'error');
        return;
    }
    
    const attackLabel = `${action.toUpperCase()} on ${ip}:${port}`;
    
    try {
        addConsoleMessage(`Executing manual attack: ${attackLabel}`, 'info');
        setManualAttackStatus(`Dispatching ${attackLabel}. This may take up to a minute depending on module output.`, 'info');
        setButtonState(true, 'Launching...');
        
        const data = await postAPI('/api/manual/execute-attack', {
            ip: ip,
            port: port,
            action: action
        });
        
        if (data.success) {
            const dispatchMessage = data.message || 'Manual attack accepted';
            addConsoleMessage(dispatchMessage, 'info');
            setManualAttackStatus(`${dispatchMessage}. Awaiting live module output...`, 'info');
            appendManualAttackLog(dispatchMessage, 'info');
        } else {
            const failureMessage = data.message || 'Unknown error';
            addConsoleMessage(`Manual attack failed: ${failureMessage}`, 'error');
            setManualAttackStatus(`Manual attack failed: ${failureMessage}`, 'error');
            appendManualAttackLog(`Attack failed: ${failureMessage}`, 'error');
        }
        
        setTimeout(() => setButtonState(false), 1200);
        
    } catch (error) {
        console.error('Error executing manual attack:', error);
        addConsoleMessage('Failed to execute manual attack due to network error', 'error');
        setManualAttackStatus(`Network error launching manual attack: ${error.message}`, 'error');
        appendManualAttackLog(`Network error: ${error.message}`, 'error');
        setButtonState(false, 'Execute Attack');
    }
}

async function startOrchestrator() {
    const statusEl = document.getElementById('system-control-status');

    // Show status and start progress
    if (statusEl) {
        statusEl.classList.remove('hidden');
        statusEl.textContent = 'Enabling automation...';
        statusEl.className = 'text-sm text-blue-600 mt-4';
    }

    addConsoleMessage('Enabling automation...', 'info');

    const data = await postAPI('/api/automation/orchestrator/start', {});

    if (data.success) {
        const automationActive = data.automation_enabled !== false;
        const modeLabelText = automationActive ? 'Auto' : 'Sleeping';
        const modeClass = automationActive ? 'text-green-400 font-semibold' : 'text-purple-300 font-semibold';

        addConsoleMessage(automationActive ? 'Automation enabled successfully' : 'Automation queued - waiting for connectivity', 'success');
        updateElement('Ragnar-mode', modeLabelText);
        const modeLabel = document.getElementById('Ragnar-mode');
        if (modeLabel) {
            modeLabel.className = modeClass;
        }

        if (statusEl) {
            statusEl.textContent = automationActive ? 'Automation enabled - Orchestrator running' : 'Automation queued - waiting for connectivity';
            statusEl.className = automationActive ? 'text-sm text-green-600 mt-4' : 'text-sm text-yellow-500 mt-4';

            // Hide status after 3 seconds
            setTimeout(() => {
                if (statusEl) {
                    statusEl.classList.add('hidden');
                }
            }, 3000);
        }

    } else {
        addConsoleMessage(`Failed to start automatic mode: ${data.message || 'Unknown error'}`, 'error');
        if (statusEl) {
            statusEl.textContent = `Error: ${data.message || 'Failed to start automatic mode'}`;
            statusEl.className = 'text-sm text-red-600 mt-4';
        }
    }

    return data;
}

async function stopOrchestrator() {
    const statusEl = document.getElementById('system-control-status');

    // Show status and start progress
    if (statusEl) {
        statusEl.classList.remove('hidden');
        statusEl.textContent = 'Stopping automatic mode...';
        statusEl.className = 'text-sm text-orange-600 mt-4';
    }

    addConsoleMessage('Disabling automation...', 'info');

    const data = await postAPI('/api/automation/orchestrator/stop', {});

    if (data.success) {
        addConsoleMessage('Automation disabled - Orchestrator sleeping', 'warning');
        updateElement('Ragnar-mode', 'Sleeping');
        const modeLabel = document.getElementById('Ragnar-mode');
        if (modeLabel) {
            modeLabel.className = 'text-purple-300 font-semibold';
        }

        if (statusEl) {
            statusEl.textContent = 'Automation disabled - Ragnar is sleeping';
            statusEl.className = 'text-sm text-orange-600 mt-4';

            // Hide status after 3 seconds
            setTimeout(() => {
                if (statusEl) {
                    statusEl.classList.add('hidden');
                }
            }, 3000);
        }

    } else {
        addConsoleMessage(`Failed to stop automatic mode: ${data.message || 'Unknown error'}`, 'error');
        if (statusEl) {
            statusEl.textContent = `Error: ${data.message || 'Failed to stop automatic mode'}`;
            statusEl.className = 'text-sm text-red-600 mt-4';
        }
    }

    return data;
}

async function triggerNetworkScan() {
    const statusEl = document.getElementById('system-control-status');
    
    try {
        // Show status and start progress
        if (statusEl) {
            statusEl.classList.remove('hidden');
            statusEl.textContent = 'Initiating network discovery scan...';
            statusEl.className = 'text-sm text-blue-600 mt-4';
        }
        
        addConsoleMessage('Triggering network scan...', 'info');
        
        const data = await postAPI('/api/manual/scan/network', {});
        
        if (data.success) {
            addConsoleMessage('Network scan triggered successfully', 'success');
            if (statusEl) {
                statusEl.textContent = 'Network scan started - Check Network tab for progress';
                statusEl.className = 'text-sm text-green-600 mt-4';
                
                // Hide status after 4 seconds
                setTimeout(() => {
                    if (statusEl) {
                        statusEl.classList.add('hidden');
                    }
                }, 4000);
            }
        } else {
            addConsoleMessage(`Failed to trigger network scan: ${data.message || 'Unknown error'}`, 'error');
            if (statusEl) {
                statusEl.textContent = `Error: ${data.message || 'Failed to trigger network scan'}`;
                statusEl.className = 'text-sm text-red-600 mt-4';
            }
        }
        
    } catch (error) {
        console.error('Error triggering network scan:', error);
        addConsoleMessage('Failed to trigger network scan', 'error');
        if (statusEl) {
            statusEl.textContent = `Error: ${error.message}`;
            statusEl.className = 'text-sm text-red-600 mt-4';
        }
    }
}

async function triggerVulnScan() {
    const statusEl = document.getElementById('system-control-status');
    
    try {
        const vulnIpDropdown = document.getElementById('vuln-ip-dropdown');
        const selectedIp = vulnIpDropdown ? vulnIpDropdown.value : 'all';
        const isAllTargets = !selectedIp || selectedIp === 'all';
        const scanLabel = isAllTargets ? 'all targets' : selectedIp;

        // Show status and start progress
        if (statusEl) {
            statusEl.classList.remove('hidden');
            statusEl.textContent = `Starting vulnerability scan for ${scanLabel}...`;
            statusEl.className = 'text-sm text-purple-600 mt-4';
        }

        addConsoleMessage(`Triggering vulnerability scan for ${scanLabel}...`, 'info');

        const data = await postAPI('/api/manual/scan/vulnerability', { ip: isAllTargets ? 'all' : selectedIp });
        
        if (data.success) {
            addConsoleMessage('Vulnerability scan triggered successfully', 'success');
            if (statusEl) {
                statusEl.textContent = `Vulnerability scan initiated for ${scanLabel} - Check Threat Intel tab in a few minutes`;
                statusEl.className = 'text-sm text-green-600 mt-4';
                
                // Hide status after 4 seconds
                setTimeout(() => {
                    if (statusEl) {
                        statusEl.classList.add('hidden');
                    }
                }, 4000);
            }
        } else {
            addConsoleMessage(`Failed to trigger vulnerability scan: ${data.message || 'Unknown error'}`, 'error');
            if (statusEl) {
                statusEl.textContent = `Error: ${data.message || 'Failed to trigger vulnerability scan'}`;
                statusEl.className = 'text-sm text-red-600 mt-4';
            }
        }
        
    } catch (error) {
        console.error('Error triggering vulnerability scan:', error);
        addConsoleMessage('Failed to trigger vulnerability scan', 'error');
        if (statusEl) {
            statusEl.textContent = `Error: ${error.message}`;
            statusEl.className = 'text-sm text-red-600 mt-4';
        }
    }
}

async function runManualLynisPentest() {
    const ipInput = document.getElementById('manual-lynis-ip');
    const userInput = document.getElementById('manual-lynis-username');
    const passInput = document.getElementById('manual-lynis-password');
    const statusWrap = document.getElementById('manual-lynis-status');
    const statusMessage = document.getElementById('manual-lynis-status-message');
    const submitBtn = document.getElementById('manual-lynis-btn');

    if (!ipInput || !userInput || !passInput) {
        addConsoleMessage('Manual Lynis form is missing elements', 'error');
        return;
    }

    const ip = ipInput.value.trim();
    const username = userInput.value.trim();
    const password = passInput.value;

    const setStatus = (message, type = 'info') => {
        if (!statusWrap || !statusMessage) return;
        const styles = {
            success: 'border-green-500/40 bg-green-900/30 text-green-200',
            error: 'border-red-500/50 bg-red-900/40 text-red-200',
            info: 'border-slate-700 bg-slate-900/70 text-gray-200'
        };
        statusWrap.classList.remove('hidden');
        statusMessage.className = `rounded-lg px-4 py-3 text-sm ${styles[type] || styles.info}`;
        statusMessage.textContent = message;
    };

    if (!ip || !username || !password) {
        setStatus('IP, username, and password are required to run Lynis manually.', 'error');
        return;
    }

    if (!isValidIPv4(ip)) {
        setStatus('Please enter a valid IPv4 address.', 'error');
        return;
    }

    // Show live status element
    const liveStatus = document.getElementById('lynis-audit-status');
    if (liveStatus) {
        liveStatus.classList.remove('hidden');
        liveStatus.textContent = 'Initializing Lynis audit...';
        liveStatus.className = 'text-sm text-blue-600 mt-2';
    }
    
    if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.textContent = 'Starting audit...';
        submitBtn.classList.add('bg-blue-600', 'cursor-wait');
        submitBtn.classList.remove('bg-red-600', 'hover:bg-red-700');
    }

    try {
        const response = await networkAwareFetch('/api/manual/pentest/lynis', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, username, password })
        });

        let payload = {};
        try {
            payload = await response.json();
        } catch (parseError) {
            console.warn('Unable to parse manual Lynis response JSON', parseError);
        }

        if (!response.ok || (payload && payload.success === false)) {
            throw new Error((payload && (payload.error || payload.message)) || `Request failed (${response.status})`);
        }

        const successMessage = (payload && payload.message) || `Lynis pentest initiated for ${ip}`;
        setStatus(successMessage, 'success');
        addConsoleMessage(successMessage, 'success');
        passInput.value = '';
        
        // Live status will be updated via WebSocket events
        // Don't reset the button here - let WebSocket handler do it
        return;
        
    } catch (error) {
        console.error('Error running manual Lynis pentest:', error);
        setStatus(`Failed to start Lynis pentest: ${error.message}`, 'error');
        addConsoleMessage(`Manual Lynis error: ${error.message}`, 'error');
        
        // Reset UI on error
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.textContent = 'Run Lynis Pentest';
            submitBtn.classList.remove('bg-blue-600', 'cursor-wait');
            submitBtn.classList.add('bg-red-600', 'hover:bg-red-700');
        }
        if (liveStatus) {
            liveStatus.textContent = `Error: ${error.message}`;
            liveStatus.className = 'text-sm text-red-600 mt-2';
        }
    }
}

// ============================================================================
// API HELPERS
// ============================================================================

const NETWORK_CONTEXT_PARAM = 'network';

function resolveNetworkAwareEndpoint(endpoint) {
    if (!endpoint || typeof endpoint !== 'string') {
        return endpoint;
    }

    const trimmed = endpoint.trim();
    if (!trimmed) {
        return endpoint;
    }

    const { network } = getSelectedDashboardNetworkKey() || {};
    if (!network) {
        return endpoint;
    }

    const likelyApiPath = trimmed.startsWith('/api/') || trimmed.startsWith('api/');

    try {
        const url = new URL(trimmed, window.location.origin);
        const sameOriginApi = url.origin === window.location.origin && url.pathname.startsWith('/api/');

        if (!sameOriginApi) {
            return endpoint;
        }

        if (!url.searchParams.has(NETWORK_CONTEXT_PARAM)) {
            url.searchParams.set(NETWORK_CONTEXT_PARAM, network);
        }

        if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
            return url.toString();
        }

        return `${url.pathname}${url.search}${url.hash}`;
    } catch (error) {
        if (!likelyApiPath) {
            return endpoint;
        }

        console.warn('Unable to normalize endpoint for network context', endpoint, error);
        const hasQuery = trimmed.includes('?');
        const alreadyHasParam = trimmed.includes(`${NETWORK_CONTEXT_PARAM}=`);

        if (alreadyHasParam) {
            return endpoint;
        }

        const separator = hasQuery ? '&' : '?';
        return `${trimmed}${separator}${NETWORK_CONTEXT_PARAM}=${encodeURIComponent(network)}`;
    }
}

function networkAwareFetch(endpoint, options = {}) {
    const resolvedEndpoint = resolveNetworkAwareEndpoint(endpoint);
    return fetch(resolvedEndpoint, options);
}

async function fetchAPI(endpoint, options = {}) {
    try {
        const response = await networkAwareFetch(endpoint, options);
        if (response.status === 401) {
            window.location.href = '/login';
            throw new Error('Authentication required');
        }
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error(`Error fetching ${endpoint}:`, error);
        throw error;
    }
}

async function postAPI(endpoint, data) {
    try {
        const response = await networkAwareFetch(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data)
        });
        if (response.status === 401) {
            window.location.href = '/login';
            throw new Error('Authentication required');
        }
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error(`Error posting to ${endpoint}:`, error);
        throw error;
    }
}

// ============================================================================
// DASHBOARD UPDATES
// ============================================================================

async function refreshDashboard() {
    try {
        const data = await fetchAPI('/api/status');
        updateDashboardStatus(data);
        await refreshDashboardStatsForCurrentSelection({ forceRefresh: true, fallbackData: data });
    } catch (error) {
        console.error('Error refreshing dashboard:', error);
    }
}

function updateDashboardStatus(data) {
    refreshDashboardStatsForCurrentSelection({ fallbackData: data }).catch(() => {
        updateDashboardStats(data);
    });

    // Update status - use the actual e-paper display text
    updateElement('Ragnar-status', data.ragnar_status || 'IDLE');
    updateElement('Ragnar-says', (data.ragnar_says || 'Hacking away...'));
    
    // Update mode and handle manual controls
    const automationEnabled = typeof data.automation_enabled === 'boolean' ? data.automation_enabled : !Boolean(data.manual_mode);
    const isManualMode = Boolean(data.manual_mode);
    
    let modeLabel = 'Auto';
    let modeClass = 'text-green-400 font-semibold';
    if (!automationEnabled) {
        modeLabel = 'Sleeping';
        modeClass = 'text-purple-300 font-semibold';
    } else if (isManualMode) {
        modeLabel = 'Manual';
        modeClass = 'text-orange-400 font-semibold';
    }

    updateElement('Ragnar-mode', modeLabel);
    
    const modeElement = document.getElementById('Ragnar-mode');
    if (modeElement) {
        modeElement.className = modeClass;
    }
    
    syncManualModeUI(isManualMode);
    updateAutomationToggleButton(automationEnabled);
    
    // Update connectivity status with WiFi SSID
    updateConnectivityIndicator('wifi-status', data.wifi_connected, data.current_ssid, data.ap_mode_active);
    updateConnectivityIndicator('bluetooth-status', data.bluetooth_active);
    updateConnectivityIndicator('usb-status', data.usb_active);
    updateConnectivityIndicator('pan-status', data.pan_connected);
    updateLanIndicator(data);

    // Update the primary connection card
    updatePrimaryConnectionCard(data);

    updateReleaseGateState(data.release_gate);
    updatePwnToggleAvailability(Boolean(data.headless_mode));
}

function updateAutomationToggleButton(automationEnabled, options = {}) {
    const button = document.getElementById('automation-toggle-btn');
    if (!button) {
        return;
    }

    const { force = false } = options;
    if (button.dataset.busy === 'true' && !force) {
        button.dataset.pendingState = automationEnabled ? 'enabled' : 'disabled';
        return;
    }

    if (force) {
        delete button.dataset.pendingState;
    }

    const baseClasses = 'w-full sm:w-auto px-4 py-2 rounded-lg font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-slate-900';
    if (automationEnabled) {
        button.textContent = 'Disable Automation';
        button.className = `${baseClasses} bg-orange-600 hover:bg-orange-500 text-white focus:ring-orange-500`;
        button.dataset.action = 'stop';
    } else {
        button.textContent = 'Enable Automation';
        button.className = `${baseClasses} bg-green-600 hover:bg-green-500 text-white focus:ring-green-500`;
        button.dataset.action = 'start';
    }
}

async function handleAutomationToggle() {
    const button = document.getElementById('automation-toggle-btn');
    if (!button || button.dataset.busy === 'true') {
        return;
    }

    const action = button.dataset.action || 'stop';
    const targetStateEnabled = action === 'start';
    button.dataset.busy = 'true';
    button.disabled = true;
    button.classList.add('opacity-70');
    button.textContent = action === 'start' ? 'Enabling...' : 'Disabling...';

    try {
        let data;
        if (action === 'start') {
            data = await startOrchestrator();
        } else {
            data = await stopOrchestrator();
        }

        // Use the actual server-reported state instead of assuming success
        const actualEnabled = data && data.success ? Boolean(data.automation_enabled) : !targetStateEnabled;
        updateAutomationToggleButton(actualEnabled, { force: true });

        refreshDashboard().catch(() => {/* best effort */});
    } catch (error) {
        console.error('Automation toggle failed:', error);
        addConsoleMessage('Failed to toggle automation', 'error');
        updateAutomationToggleButton(!targetStateEnabled, { force: true });
    } finally {
        button.dataset.busy = 'false';
        button.disabled = false;
        button.classList.remove('opacity-70');

        if (button.dataset.pendingState) {
            const pendingEnabled = button.dataset.pendingState === 'enabled';
            delete button.dataset.pendingState;
            updateAutomationToggleButton(pendingEnabled, { force: true });
        }
    }
}

function updateElement(id, value) {
    const element = document.getElementById(id);
    if (element) {
        element.textContent = value;
    }
}

function scaleStatNumber(elementId, value, options = {}) {
    const element = document.getElementById(elementId);
    if (!element) {
        return;
    }

    const config = {
        mediumDigits: 3,
        largeDigits: 4,
        baseClass: 'text-3xl',
        mediumClass: 'text-2xl',
        smallClass: 'text-xl',
        ...options
    };

    const numericValue = Number(value);
    const safeValue = Number.isFinite(numericValue) ? Math.trunc(numericValue) : 0;
    const digitCount = Math.abs(safeValue).toString().length;

    element.classList.remove(config.baseClass, config.mediumClass, config.smallClass);

    if (digitCount >= config.largeDigits) {
        element.classList.add(config.smallClass);
    } else if (digitCount >= config.mediumDigits) {
        element.classList.add(config.mediumClass);
    } else {
        element.classList.add(config.baseClass);
    }
}

function updateConnectivityIndicator(id, active, ssid = null, apMode = false) {
    const element = document.getElementById(id);
    if (element) {
        if (active) {
            element.className = 'w-3 h-3 bg-green-500 rounded-full pulse-glow';
        } else {
            element.className = 'w-3 h-3 bg-gray-600 rounded-full';
        }
    }
    
    // Update WiFi SSID display if this is the WiFi indicator
    if (id === 'wifi-status') {
        const ssidDisplay = document.getElementById('wifi-ssid-display');
        if (ssidDisplay) {
            if (apMode) {
                ssidDisplay.textContent = ssid ? `AP Mode: ${ssid}` : 'AP Mode';
                ssidDisplay.className = 'text-xs text-blue-400 truncate';
            } else if (active && ssid) {
                ssidDisplay.textContent = ssid;
                ssidDisplay.className = 'text-xs text-gray-400 truncate';
            } else {
                ssidDisplay.textContent = 'Not connected';
                ssidDisplay.className = 'text-xs text-gray-500 truncate';
            }
        }
    }
}

function updateLanIndicator(data) {
    const dot = document.getElementById('lan-status');
    const info = document.getElementById('lan-info-display');
    if (!dot && !info) return;

    if (data.ethernet_connected) {
        if (dot) dot.className = 'w-3 h-3 bg-green-500 rounded-full pulse-glow';
        if (info) {
            const iface = data.ethernet_interface || 'eth0';
            const ip = data.ethernet_ip || '';
            info.textContent = ip ? `${iface}: ${ip}` : iface;
            info.className = 'text-xs text-green-400 truncate';
        }
    } else {
        if (dot) dot.className = 'w-3 h-3 bg-gray-600 rounded-full';
        if (info) {
            info.textContent = 'Not connected';
            info.className = 'text-xs text-gray-500 truncate';
        }
    }
}

/**
 * Update the primary connection card on the dashboard.
 * Priority: Ethernet > WiFi > USB/PAN > Bluetooth
 */
function updatePrimaryConnectionCard(data) {
    const label = document.getElementById('primary-connection-label');
    const name = document.getElementById('primary-connection-name');
    const ip = document.getElementById('primary-connection-ip');
    const status = document.getElementById('primary-connection-status');
    const icon = document.getElementById('primary-connection-icon');

    if (!label) return;

    const lanIcon = '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2"></path></svg>';
    const wifiIcon = '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071c3.904-3.905 10.236-3.905 14.141 0M1.394 9.393c5.857-5.857 15.355-5.857 21.213 0"></path></svg>';

    if (data.ethernet_connected) {
        label.textContent = 'LAN';
        name.textContent = data.ethernet_interface || 'Ethernet';
        if (ip) ip.textContent = data.ethernet_ip || '';
        if (status) status.className = 'w-3 h-3 bg-green-500 rounded-full pulse-glow';
        if (icon) { icon.innerHTML = lanIcon; icon.className = 'text-green-400'; }
    } else if (data.wifi_connected) {
        const ssid = data.current_ssid || 'Connected';
        label.textContent = data.ap_mode_active ? 'AP Mode' : 'WiFi';
        name.textContent = data.ap_mode_active ? `AP: ${data.ap_ssid || 'Ragnar'}` : ssid;
        if (ip) ip.textContent = '';
        if (status) status.className = 'w-3 h-3 bg-green-500 rounded-full pulse-glow';
        if (icon) { icon.innerHTML = wifiIcon; icon.className = 'text-green-400'; }
    } else if (data.pan_connected) {
        label.textContent = 'USB/PAN';
        name.textContent = 'Connected via USB';
        if (ip) ip.textContent = '';
        if (status) status.className = 'w-3 h-3 bg-green-500 rounded-full pulse-glow';
        if (icon) icon.className = 'text-yellow-400';
    } else if (data.bluetooth_active) {
        label.textContent = 'Bluetooth';
        name.textContent = 'Bluetooth active';
        if (ip) ip.textContent = '';
        if (status) status.className = 'w-3 h-3 bg-blue-500 rounded-full pulse-glow';
        if (icon) icon.className = 'text-blue-400';
    } else {
        label.textContent = 'Disconnected';
        name.textContent = 'No active connection';
        if (ip) ip.textContent = '';
        if (status) status.className = 'w-3 h-3 bg-gray-600 rounded-full';
        if (icon) icon.className = 'text-gray-500';
    }
}

// ============================================================================
// CONSOLE
// ============================================================================

const MAX_CONSOLE_LINES = 200;
const CONSOLE_NOISE_PATTERNS = [
    'comment.py - INFO - Comments loaded successfully from cache'
];
const HISTORY_LOG_TYPE_COLORS = {
    'success': 'text-green-400',
    'error': 'text-red-400',
    'warning': 'text-yellow-400',
    'info': 'text-gray-300'
};

let consoleBuffer = [];
let lastConsoleLogLine = null;

function addConsoleMessage(message, type = 'info') {
    const timestamp = new Date().toLocaleTimeString();
    const colors = {
        'success': 'text-green-400',
        'error': 'text-red-400',
        'warning': 'text-yellow-400',
        'info': 'text-blue-400'
    };
    
    const colorClass = colors[type] || colors['info'];
    const logEntry = {
        timestamp,
        message,
        type,
        colorClass
    };
    
    consoleBuffer.push(logEntry);
    
    // Keep only the last MAX_CONSOLE_LINES
    if (consoleBuffer.length > MAX_CONSOLE_LINES) {
        consoleBuffer = consoleBuffer.slice(-MAX_CONSOLE_LINES);
    }
    
    updateConsoleDisplay();
}

function shouldHideConsoleLog(logLine) {
    return CONSOLE_NOISE_PATTERNS.some(pattern => logLine.includes(pattern));
}

function determineConsoleLogType(logLine) {
    if (!logLine) return 'info';
    const normalized = logLine.toLowerCase();
    if (normalized.includes('error')) return 'error';
    if (normalized.includes('warn')) return 'warning';
    if (normalized.includes('success')) return 'success';
    return 'info';
}

const LOG_TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/;

function extractLogTimestamp(logLine) {
    if (!logLine || logLine.length < 19) {
        return new Date().toLocaleTimeString();
    }
    const timestampCandidate = logLine.slice(0, 19);
    if (LOG_TIMESTAMP_PATTERN.test(timestampCandidate)) {
        const parsed = new Date(timestampCandidate.replace(' ', 'T'));
        if (!Number.isNaN(parsed.getTime())) {
            return parsed.toLocaleTimeString();
        }
    }
    return new Date().toLocaleTimeString();
}

function createConsoleEntryFromLog(logLine) {
    const type = determineConsoleLogType(logLine);
    return {
        timestamp: extractLogTimestamp(logLine),
        message: logLine,
        type,
        colorClass: HISTORY_LOG_TYPE_COLORS[type] || HISTORY_LOG_TYPE_COLORS['info']
    };
}

function updateConsole(logs) {
    if (!logs || !Array.isArray(logs)) {
        // If no logs available, add informational messages
        if (consoleBuffer.length === 0) {
            addConsoleMessage('No historical logs available', 'warning');
            addConsoleMessage('New activity will appear here as it occurs', 'info');
        }
        return;
    }
    
    // If logs are empty array, provide user feedback
    if (logs.length === 0) {
        if (consoleBuffer.length === 0) {
            addConsoleMessage('No recent activity logged', 'info');
            addConsoleMessage('Waiting for new events...', 'info');
        }
        return;
    }
    
    const cleanedLogs = logs
        .map(log => typeof log === 'string' ? log.trim() : '')
        .filter(log => log && !shouldHideConsoleLog(log));

    if (cleanedLogs.length === 0) {
        return;
    }

    let newLogLines = [];
    if (!lastConsoleLogLine) {
        consoleBuffer = [];
        newLogLines = cleanedLogs.slice(-MAX_CONSOLE_LINES);
    } else {
        const lastIndex = cleanedLogs.lastIndexOf(lastConsoleLogLine);
        if (lastIndex === cleanedLogs.length - 1) {
            lastConsoleLogLine = cleanedLogs[cleanedLogs.length - 1];
            return;
        }
        if (lastIndex !== -1) {
            newLogLines = cleanedLogs.slice(lastIndex + 1);
        } else {
            consoleBuffer = [];
            newLogLines = cleanedLogs.slice(-MAX_CONSOLE_LINES);
        }
    }

    if (newLogLines.length === 0) {
        lastConsoleLogLine = cleanedLogs[cleanedLogs.length - 1];
        return;
    }
    
    newLogLines.forEach(logLine => {
        consoleBuffer.push(createConsoleEntryFromLog(logLine));
    });
    
    if (consoleBuffer.length > MAX_CONSOLE_LINES) {
        consoleBuffer = consoleBuffer.slice(-MAX_CONSOLE_LINES);
    }
    
    lastConsoleLogLine = cleanedLogs[cleanedLogs.length - 1];
    updateConsoleDisplay();
}

function updateConsoleDisplay() {
    const console = document.getElementById('console-output');
    if (!console) return;
    
    console.innerHTML = consoleBuffer.map(entry => 
        `<div class="${entry.colorClass}">[${entry.timestamp}] ${escapeHtml(entry.message)}</div>`
    ).join('');
    
    // Auto-scroll to bottom
    console.scrollTop = console.scrollHeight;
}

function clearConsole() {
    consoleBuffer = [];
    const console = document.getElementById('console-output');
    if (console) {
        console.innerHTML = '<div class="text-green-400">Console cleared</div>';
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ============================================================================
// TABLE DISPLAYS
// ============================================================================

function displayNetworkTable(data) {
    const container = document.getElementById('network-table');
    const tableBody = document.getElementById('network-hosts-table');
    if (!container || !tableBody) {
        return;
    }

    // Save all existing deep scan button states before clearing table
    const existingRows = tableBody.querySelectorAll('tr[data-ip]');
    existingRows.forEach(row => {
        const ip = row.getAttribute('data-ip');
        if (ip) {
            saveDeepScanButtonState(ip);
        }
    });

    tableBody.innerHTML = '';

    const entries = Array.isArray(data) ? data : (data && Array.isArray(data.hosts) ? data.hosts : []);

    if (!entries || entries.length === 0) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="8" class="text-center py-8 text-gray-400">
                    No network data available. Start a scan to discover hosts.
                </td>
            </tr>
        `;
        updateHostCountDisplay();
        return;
    }

    entries.forEach(item => {
        const normalized = normalizeHostRecord(item);
        if (!normalized) {
            return;
        }

        const row = document.createElement('tr');
        row.setAttribute('data-ip', normalized.ip);
        row.className = 'border-b border-slate-700 hover:bg-slate-700/50 transition-colors';
        row.innerHTML = renderHostRow(normalized);
        tableBody.appendChild(row);
        
        // Restore deep scan button state after adding to DOM
        restoreDeepScanButtonState(normalized.ip);
    });

    updateHostCountDisplay();
    
    // Cleanup old button states for removed hosts
    cleanupOldDeepScanStates();
}

function displayCredentialsTable(data) {
    const container = document.getElementById('credentials-table');
    if (!container) return;
    
    if (!data || Object.keys(data).length === 0) {
        container.innerHTML = '<p class="text-gray-400">No credentials discovered yet</p>';
        return;
    }
    
    let html = '<div class="space-y-6">';
    
    Object.entries(data).forEach(([service, creds]) => {
        if (creds && creds.length > 0) {
            html += `
                <div class="bg-gray-800 rounded-lg p-4">
                    <h3 class="text-lg font-semibold text-Ragnar-400 mb-3">${service.toUpperCase()} (${creds.length})</h3>
                    <div class="overflow-x-auto">
                        <table class="min-w-full divide-y divide-gray-700">
                            <thead>
                                <tr>
                                    <th class="px-4 py-2 text-left text-xs font-medium text-gray-300 uppercase">Target</th>
                                    <th class="px-4 py-2 text-left text-xs font-medium text-gray-300 uppercase">Username</th>
                                    <th class="px-4 py-2 text-left text-xs font-medium text-gray-300 uppercase">Password</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-gray-700">
            `;
            
            creds.forEach(cred => {
                html += `
                    <tr class="hover:bg-gray-700 transition-colors">
                        <td class="px-4 py-2 text-sm text-white">${cred.ip || 'N/A'}</td>
                        <td class="px-4 py-2 text-sm text-green-400 font-mono">${cred.username || 'N/A'}</td>
                        <td class="px-4 py-2 text-sm text-yellow-400 font-mono">${cred.password || 'N/A'}</td>
                    </tr>
                `;
            });
            
            html += `
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
        }
    });
    
    html += '</div>';
    
    if (html === '<div class="space-y-6"></div>') {
        container.innerHTML = '<p class="text-gray-400">No credentials discovered yet</p>';
    } else {
        container.innerHTML = html;
    }
}

function displayLootTable(data) {
    const container = document.getElementById('loot-table');
    if (!container) return;
    
    if (!data || data.length === 0) {
        container.innerHTML = '<p class="text-gray-400">No loot data available</p>';
        return;
    }
    
    const previewCount = 6;
    const hasMoreItems = data.length > previewCount;
    const previewItems = data.slice(0, previewCount);
    const hiddenItems = hasMoreItems ? data.slice(previewCount) : [];
    
    function createLootItemHTML(item) {
        const filename = escapeHtml(item.filename || 'Unknown File');
        const size = escapeHtml(item.size || 'N/A');
        const source = escapeHtml(item.source || 'Unknown');
        const timestamp = escapeHtml(item.timestamp || 'Unknown');
        const encodedPath = item.path ? encodeURIComponent(item.path) : '';
        const buttonClasses = `bg-gray-800 rounded-lg p-4 text-left hover:bg-gray-700 transition-colors w-full ${encodedPath ? '' : 'opacity-60 cursor-not-allowed'}`;
        const clickAttr = encodedPath ? `onclick="openLootFile('${encodedPath}')"` : 'disabled aria-disabled="true"';
        const actionHint = encodedPath ? '<p class="text-xs text-Ragnar-400 mt-3">Open in Files →</p>' : '';
        
        return `
            <button type="button" class="${buttonClasses}" ${clickAttr}>
                <div class="flex items-center justify-between mb-2">
                    <h3 class="text-lg font-semibold text-Ragnar-400 truncate" title="${filename}">${filename}</h3>
                    <span class="text-xs text-gray-400 ml-2">${size}</span>
                </div>
                <div class="space-y-2 text-sm text-gray-300">
                    <p><span class="text-gray-400">Source:</span> ${source}</p>
                    <p><span class="text-gray-400">Timestamp:</span> ${timestamp}</p>
                </div>
                ${actionHint}
            </button>
        `;
    }
    
    let html = `<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4" id="loot-preview-items">`;
    
    // Add preview items
    previewItems.forEach(item => {
        html += createLootItemHTML(item);
    });
    
    html += '</div>';
    
    // Add expandable section for remaining items
    if (hasMoreItems) {
        html += `
            <div class="mt-4">
                <button onclick="toggleLootExpansion()" 
                        class="flex items-center justify-center w-full py-3 px-4 bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors text-gray-300 hover:text-white">
                    <span id="loot-expand-text">Show ${hiddenItems.length} more items</span>
                    <svg id="loot-expand-arrow" class="w-4 h-4 ml-2 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
                    </svg>
                </button>
                <div id="loot-hidden-items" class="hidden mt-4">
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        `;
        
        hiddenItems.forEach(item => {
            html += createLootItemHTML(item);
        });
        
        html += `
                    </div>
                </div>
            </div>
        `;
    }
    
    container.innerHTML = html;
}

function toggleLootExpansion() {
    const hiddenItems = document.getElementById('loot-hidden-items');
    const expandText = document.getElementById('loot-expand-text');
    const expandArrow = document.getElementById('loot-expand-arrow');
    
    if (!hiddenItems || !expandText || !expandArrow) return;
    
    const isHidden = hiddenItems.classList.contains('hidden');
    
    if (isHidden) {
        // Show hidden items
        hiddenItems.classList.remove('hidden');
        expandText.textContent = 'Show less';
        expandArrow.style.transform = 'rotate(180deg)';
    } else {
        // Hide items
        hiddenItems.classList.add('hidden');
        const hiddenItemCount = hiddenItems.querySelectorAll('button').length;
        expandText.textContent = `Show ${hiddenItemCount} more items`;
        expandArrow.style.transform = 'rotate(0deg)';
    }
}

function openLootFile(encodedPath) {
    if (!encodedPath) {
        showNotification('No file path available for this loot item.', 'warning');
        return;
    }

    try {
        const filePath = decodeURIComponent(encodedPath);
        if (!filePath || filePath === '/data_stolen') {
            showNotification('Unable to locate that file. It may have been moved or deleted.', 'warning');
            return;
        }

        const lastSlashIndex = filePath.lastIndexOf('/');
        if (lastSlashIndex === -1) {
            showNotification('Invalid file path received for loot item.', 'error');
            return;
        }

        const directory = lastSlashIndex === 0 ? '/' : filePath.substring(0, lastSlashIndex);
        const fileName = filePath.substring(lastSlashIndex + 1);

        if (!fileName) {
            showNotification('Unable to determine file name for loot item.', 'error');
            return;
        }

        pendingFileHighlight = {
            directory,
            file: fileName
        };

        showTab('files');
        loadFiles(directory, fileName);
        showNotification(`Opening ${fileName} in Files tab`, 'info');
    } catch (error) {
        console.error('Failed to open loot file:', error);
        showNotification('Failed to open file from loot item.', 'error');
    }
}

function displayConfigForm(config) {
    const container = document.getElementById('config-form');
    
    let html = '<div class="space-y-6"><form id="config-update-form">';
    
    // Group config by sections
    const sections = {
        'General': ['manual_mode', 'debug_mode', 'scan_vuln_running', 'scan_vuln_no_ports', 'enable_attacks', 'blacklistcheck'],
        'Network': ['network_max_failed_pings'],
        'Timing': ['startup_delay', 'web_delay', 'screen_delay', 'scan_interval'],
        'Display': ['epd_type', 'screen_reversed', 'spi_clock_mhz', 'gc9a01_mascot_color', 'ssd1306_i2c_address', 'lcd1602_i2c_address', 'max7219_spi_port', 'max7219_spi_device', 'max7219_block_orientation', 'display_brightness']
    };
    
    const knownBooleans = ['manual_mode', 'debug_mode', 'scan_vuln_running', 'scan_vuln_no_ports', 'enable_attacks', 'blacklistcheck'];
    const alwaysShowKeys = new Set(['network_max_failed_pings', 'gc9a01_mascot_color', 'ssd1306_i2c_address', 'lcd1602_i2c_address', 'spi_clock_mhz', 'max7219_spi_port', 'max7219_spi_device', 'max7219_block_orientation', 'display_brightness']);
    const fallbackValues = {
        network_max_failed_pings: 15,
        gc9a01_mascot_color: '#96C8FF',
        ssd1306_i2c_address: '0x3C',
        lcd1602_i2c_address: '0x27',
        spi_clock_mhz: 2,
        max7219_spi_port: 0,
        max7219_spi_device: 0,
        max7219_block_orientation: -90,
        display_brightness: 8
    };
    const checkboxHandlers = {
        scan_vuln_running: 'handleVulnScanToggle(this)',
        enable_attacks: 'handleEnableAttacksToggle(this)'
    };

    for (const [sectionName, keys] of Object.entries(sections)) {
        html += `
            <div class="bg-slate-800 bg-opacity-50 rounded-lg p-4">
                <h3 class="text-lg font-bold mb-4 text-Ragnar-400">${sectionName}</h3>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        `;
        
        keys.forEach(key => {
            const hasKey = Object.prototype.hasOwnProperty.call(config, key);
            // Check if config has the key, or provide defaults for known boolean settings
            let value = config[key];
            
            // If key is missing and it's a known boolean, default to true (except manual_mode)
            if (!hasKey && knownBooleans.includes(key)) {
                value = (key === 'manual_mode') ? false : true;
            }
            
            if (!hasKey && alwaysShowKeys.has(key)) {
                value = fallbackValues[key];
            }
            
            if (hasKey || knownBooleans.includes(key) || alwaysShowKeys.has(key)) {
                const selectOptions = displaySelectOptions[key];
                const type = typeof value === 'boolean' ? 'checkbox' : 'text';
                const label = getConfigLabel(key);
                const description = escapeHtml(getConfigDescription(key));
                
                if (Array.isArray(selectOptions)) {
                    let selectedValue = typeof value === 'boolean' ? String(value) : (value ?? '');
                    // For epd_type, map driver name to size key so the dropdown matches
                    if (key === 'epd_type') {
                        selectedValue = epdTypeToSizeKey(selectedValue);
                    }
                    // For screen_reversed, normalize legacy boolean values to rotation angles
                    if (key === 'screen_reversed') {
                        if (selectedValue === 'true') selectedValue = '180';
                        else if (selectedValue === 'false') selectedValue = '0';
                    }
                    html += `
                        <div class="space-y-2">
                            <label class="flex items-center gap-2 text-sm text-gray-400">
                                ${label}
                                <span class="info-icon" tabindex="0" role="button" aria-label="${description}" data-tooltip="${description}">ⓘ</span>
                            </label>
                            <select name="${key}" class="w-full px-4 py-2 rounded-lg bg-slate-700 border border-slate-600 focus:border-Ragnar-500 focus:ring-1 focus:ring-Ragnar-500">
                                ${selectOptions.map(option => `<option value="${option.value}" ${option.value === String(selectedValue) ? 'selected' : ''}>${option.label}</option>`).join('')}
                            </select>
                        </div>
                    `;
                } else if (type === 'checkbox') {
                    // Determine if this checkbox should be disabled based on dependencies
                    const disabledAttr = (key === 'scan_vuln_no_ports' && !config.scan_vuln_running) ? 'disabled' : '';
                    const disabledClass = disabledAttr ? 'opacity-50 cursor-not-allowed' : '';
                    
                    const handlerAttr = checkboxHandlers[key] ? `onchange="${checkboxHandlers[key]}"` : '';
                    html += `
                        <label class="flex items-center space-x-3 p-3 rounded-lg hover:bg-slate-700 hover:bg-opacity-50 transition-colors cursor-pointer ${disabledClass}">
                            <input type="checkbox" name="${key}" ${value ? 'checked' : ''} ${disabledAttr}
                                   class="w-5 h-5 rounded bg-slate-700 border-slate-600 text-Ragnar-500 focus:ring-Ragnar-500"
                                   ${handlerAttr}>
                            <span class="flex items-center gap-2">
                                ${label}
                                <span class="info-icon" tabindex="0" role="button" aria-label="${description}" data-tooltip="${description}">ⓘ</span>
                            </span>
                        </label>
                    `;
                } else if (key === 'gc9a01_mascot_color') {
                    const colorVal = (value && typeof value === 'string' && value.startsWith('#')) ? value : '#96C8FF';
                    html += `
                        <div class="space-y-2" id="cfg-gc9a01-color-row">
                            <label class="flex items-center gap-2 text-sm text-gray-400">
                                ${label}
                                <span class="info-icon" tabindex="0" role="button" aria-label="${description}" data-tooltip="${description}">ⓘ</span>
                            </label>
                            <div class="flex items-center gap-3">
                                <input type="color" name="${key}" value="${colorVal}"
                                       class="h-9 w-16 cursor-pointer rounded border border-slate-600 bg-slate-700 p-1">
                                <span class="text-xs text-gray-500">Mascot tint on GC9A01 round display</span>
                            </div>
                        </div>
                    `;
                } else if (key === 'ssd1306_i2c_address') {
                    const currentVal = (value && typeof value === 'string') ? value : '0x3C';
                    html += `
                        <div class="space-y-2" id="cfg-ssd1306-addr-row">
                            <label class="flex items-center gap-2 text-sm text-gray-400">
                                ${label}
                                <span class="info-icon" tabindex="0" role="button" aria-label="${description}" data-tooltip="${description}">ⓘ</span>
                            </label>
                            <input type="text" name="${key}" id="cfg-ssd1306-addr-input"
                                   class="w-full bg-gray-800 border border-gray-600 rounded px-3 py-2 text-sm font-mono"
                                   value="${currentVal}" placeholder="0x3C or 0x3D">
                            <p class="text-xs text-gray-500">Most modules use 0x3C. Use 0x3D if display doesn't initialize.</p>
                        </div>
                    `;
                } else if (key === 'lcd1602_i2c_address') {
                    const currentVal = (value && typeof value === 'string') ? value : '0x27';
                    html += `
                        <div class="space-y-2" id="cfg-lcd1602-addr-row">
                            <label class="flex items-center gap-2 text-sm text-gray-400">
                                ${label}
                                <span class="info-icon" tabindex="0" role="button" aria-label="${description}" data-tooltip="${description}">ⓘ</span>
                            </label>
                            <input type="text" name="${key}" id="cfg-lcd1602-addr-input"
                                   class="w-full bg-gray-800 border border-gray-600 rounded px-3 py-2 text-sm font-mono"
                                   value="${currentVal}" placeholder="0x27 or 0x3F">
                            <p class="text-xs text-gray-500">Most PCF8574 backpacks use 0x27. Address is auto-detected if unreachable.</p>
                        </div>
                    `;
                } else if (key === 'max7219_spi_port') {
                    const spiPort = (value !== undefined && value !== null) ? value : 0;
                    html += `
                        <div class="space-y-2" id="cfg-max7219-spi-port-row">
                            <label class="flex items-center gap-2 text-sm text-gray-400">
                                ${label}
                                <span class="info-icon" tabindex="0" role="button" aria-label="${description}" data-tooltip="${description}">ⓘ</span>
                            </label>
                            <input type="number" name="${key}" id="cfg-max7219-spi-port-input"
                                   class="w-full bg-gray-800 border border-gray-600 rounded px-3 py-2 text-sm font-mono"
                                   value="${spiPort}" min="0" max="1">
                            <p class="text-xs text-gray-500">SPI bus (0 = SPI0, 1 = SPI1). Default: 0.</p>
                        </div>
                    `;
                } else if (key === 'max7219_block_orientation') {
                    const orient = (value !== undefined && value !== null) ? value : -90;
                    html += `
                        <div class="space-y-2" id="cfg-max7219-block-row">
                            <label class="flex items-center gap-2 text-sm text-gray-400">
                                ${label}
                                <span class="info-icon" tabindex="0" role="button" aria-label="${description}" data-tooltip="${description}">ⓘ</span>
                            </label>
                            <input type="number" name="${key}" id="cfg-max7219-block-input"
                                   class="w-full bg-gray-800 border border-gray-600 rounded px-3 py-2 text-sm font-mono"
                                   value="${orient}" step="90">
                            <p class="text-xs text-gray-500">Rotation of each 8×8 block in degrees (0, 90, -90, 180). Try -90 if display looks sideways.</p>
                        </div>
                    `;
                } else if (key === 'display_brightness') {
                    const brightness = (value !== undefined && value !== null) ? value : 8;
                    html += `
                        <div class="space-y-2" id="cfg-display-brightness-row">
                            <label class="flex items-center gap-2 text-sm text-gray-400">
                                ${label}
                                <span class="info-icon" tabindex="0" role="button" aria-label="${description}" data-tooltip="${description}">ⓘ</span>
                            </label>
                            <input type="number" name="${key}" id="cfg-display-brightness-input"
                                   class="w-full bg-gray-800 border border-gray-600 rounded px-3 py-2 text-sm font-mono"
                                   value="${brightness}" min="0" max="15">
                            <p class="text-xs text-gray-500">Brightness 0–15. Applies to MAX7219, SSD1306, GC9A01. Default: 8.</p>
                        </div>
                    `;
                } else if (key === 'spi_clock_mhz') {
                    const clockMhz = (value !== undefined && value !== null) ? value : 2;
                    html += `
                        <div class="space-y-2" id="cfg-spi-clock-row">
                            <label class="flex items-center gap-2 text-sm text-gray-400">
                                ${label}
                                <span class="info-icon" tabindex="0" role="button" aria-label="${description}" data-tooltip="${description}">ⓘ</span>
                            </label>
                            <input type="number" name="${key}" id="cfg-spi-clock-input"
                                   class="w-full bg-gray-800 border border-gray-600 rounded px-3 py-2 text-sm font-mono"
                                   value="${clockMhz}" min="0.5" max="4" step="0.5">
                        </div>
                    `;
                } else {
                    html += `
                        <div class="space-y-2">
                            <label class="flex items-center gap-2 text-sm text-gray-400">
                                ${label}
                                <span class="info-icon" tabindex="0" role="button" aria-label="${description}" data-tooltip="${description}">ⓘ</span>
                            </label>
                            <input type="${type}" name="${key}" value="${value}"
                                   class="w-full px-4 py-2 rounded-lg bg-slate-700 border border-slate-600 focus:border-Ragnar-500 focus:ring-1 focus:ring-Ragnar-500">
                        </div>
                    `;
                }
            }
        });
        
        html += '</div></div>';
    }
    
    html += `
        <button type="submit" class="w-full bg-Ragnar-600 hover:bg-Ragnar-700 text-white font-bold py-3 px-6 rounded-lg transition-colors">
            Save Configuration
        </button>
    </form></div>`;
    
    container.innerHTML = html;
    
    // Add form submit handler
    document.getElementById('config-update-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        await saveConfig(e.target);
    });

    // Show/hide display-type-specific rows based on selected display type
    const epdSelect = document.querySelector('select[name="epd_type"]');
    const colorRow = document.getElementById('cfg-gc9a01-color-row');
    const addrRow = document.getElementById('cfg-ssd1306-addr-row');
    const lcdAddrRow = document.getElementById('cfg-lcd1602-addr-row');
    const max7219SpiPortRow = document.getElementById('cfg-max7219-spi-port-row');
    const max7219SpiDevRow = document.getElementById('cfg-max7219-spi-device-row');
    const max7219BlockRow = document.getElementById('cfg-max7219-block-row');
    const brightnessRow = document.getElementById('cfg-display-brightness-row');
    const spiClockRow = document.getElementById('cfg-spi-clock-row');
    function syncDisplayRows() {
        const val = epdSelect ? epdSelect.value : '';
        const isMax7219 = val === 'max7219_8panel' || val === 'max7219_4panel';
        const isSsd1306 = val === '0in96_oled';
        const isGc9a01 = val === '1in28_tft';
        const isLcd1602 = val === 'lcd1602';
        const isEpaper = !isMax7219 && !isSsd1306 && !isGc9a01 && !isLcd1602;
        if (colorRow) colorRow.style.display = isGc9a01 ? '' : 'none';
        if (addrRow) addrRow.style.display = isSsd1306 ? '' : 'none';
        if (lcdAddrRow) lcdAddrRow.style.display = isLcd1602 ? '' : 'none';
        if (max7219SpiPortRow) max7219SpiPortRow.style.display = isMax7219 ? '' : 'none';
        if (max7219SpiDevRow) max7219SpiDevRow.style.display = isMax7219 ? '' : 'none';
        if (max7219BlockRow) max7219BlockRow.style.display = isMax7219 ? '' : 'none';
        if (brightnessRow) brightnessRow.style.display = (isMax7219 || isSsd1306 || isGc9a01) ? '' : 'none';
        if (spiClockRow) spiClockRow.style.display = isEpaper ? '' : 'none';
    }
    if (epdSelect) {
        epdSelect.addEventListener('change', syncDisplayRows);
        syncDisplayRows();
    }

    const attacksEnabled = config.hasOwnProperty('enable_attacks') ? Boolean(config.enable_attacks) : true;
    updateAttackWarningBanner(attacksEnabled);
}

// Handle vulnerability scanning checkbox toggle to enable/disable dependent options
function handleVulnScanToggle(checkbox) {
    const scanVulnNoPortsCheckbox = document.querySelector('input[name="scan_vuln_no_ports"]');
    const scanVulnNoPortsLabel = scanVulnNoPortsCheckbox ? scanVulnNoPortsCheckbox.closest('label') : null;
    
    if (scanVulnNoPortsCheckbox) {
        scanVulnNoPortsCheckbox.disabled = !checkbox.checked;
        
        if (scanVulnNoPortsLabel) {
            if (checkbox.checked) {
                scanVulnNoPortsLabel.classList.remove('opacity-50', 'cursor-not-allowed');
            } else {
                scanVulnNoPortsLabel.classList.add('opacity-50', 'cursor-not-allowed');
            }
        }
    }
}

function updateAttackWarningBanner(isEnabled) {
    const banner = document.getElementById('attack-warning');
    if (!banner) {
        return;
    }
    if (isEnabled) {
        banner.classList.remove('hidden');
    } else {
        banner.classList.add('hidden');
    }
}

function handleEnableAttacksToggle(checkbox) {
    if (checkbox.checked) {
        const confirmed = confirm('Warning: enabling automated attacks will run offensive actions (bruteforce, credential reuse, file theft) against discovered hosts. Do you have authorization to continue?');
        if (!confirmed) {
            checkbox.checked = false;
            updateAttackWarningBanner(false);
            addConsoleMessage('Automated attacks remain disabled.', 'warning');
            showNotification('Automated attacks remain disabled.', 'info');
            return;
        }
        showNotification('Automated attacks are enabled. Ensure you are authorized before proceeding.', 'warning');
        addConsoleMessage('Automated attacks enabled. Ragnar will launch offensive actions on discovered hosts.', 'warning');
    } else {
        addConsoleMessage('Automated attacks disabled.', 'info');
    }

    updateAttackWarningBanner(checkbox.checked);
}

async function saveConfig(form) {
    const formData = new FormData(form);
    const config = {};
    
    // First, get all checkboxes and set them to false by default
    const checkboxes = form.querySelectorAll('input[type="checkbox"]');
    checkboxes.forEach(checkbox => {
        config[checkbox.name] = false;
    });
    
    // Then get all form values, including checked checkboxes
    for (const [key, value] of formData.entries()) {
        const input = form.elements[key];
        if (input.type === 'checkbox') {
            config[key] = input.checked;
        } else if (value === 'true' || value === 'false') {
            config[key] = value === 'true';
        } else if (!isNaN(value) && value !== '') {
            config[key] = Number(value);
        } else {
            config[key] = value;
        }
    }
    
    // Handle unchecked checkboxes explicitly
    checkboxes.forEach(checkbox => {
        config[checkbox.name] = checkbox.checked;
    });
    
    console.log('Saving config:', config); // Debug logging
    
    try {
        const result = await postAPI('/api/config', config);
        addConsoleMessage('Configuration saved successfully', 'success');
        
        // If manual_mode was changed, refresh the dashboard to update UI
        if (config.hasOwnProperty('manual_mode')) {
            setTimeout(() => {
                refreshDashboard();
            }, 500);
        }
        
    } catch (error) {
        console.error('Config save error:', error);
        addConsoleMessage('Failed to save configuration', 'error');
    }
}

// AI Configuration Functions
async function loadAIConfiguration(config) {
    // Mirror current configuration for AI enable toggle
    const aiEnabledCheckbox = document.getElementById('ai-enabled-toggle');
    if (aiEnabledCheckbox) {
        const aiEnabled = config && Object.prototype.hasOwnProperty.call(config, 'ai_enabled')
            ? Boolean(config.ai_enabled)
            : false;
        aiEnabledCheckbox.checked = aiEnabled;
    }
    
    // Fetch token status from environment variable
    try {
        const tokenStatus = await fetchAPI('/api/ai/token');
        const apiTokenInput = document.getElementById('openai-api-token');
        if (apiTokenInput) {
            if (tokenStatus.configured && tokenStatus.token_preview) {
                // Show preview of token
                apiTokenInput.value = '';
                apiTokenInput.placeholder = `Configured: ${tokenStatus.token_preview}`;
            } else {
                apiTokenInput.value = '';
                apiTokenInput.placeholder = 'sk-...';
            }
        }
    } catch (error) {
        console.error('Failed to fetch AI token status:', error);
    }
}

async function toggleAIEnabled() {
    const checkbox = document.getElementById('ai-enabled-toggle');
    const statusDiv = document.getElementById('ai-config-status');
    const statusMessage = document.getElementById('ai-config-status-message');
    if (!checkbox || !statusDiv || !statusMessage) {
        return;
    }

    const desiredState = checkbox.checked;
    const payload = { ai_enabled: desiredState };

    try {
        const result = await postAPI('/api/config', payload);

        if (desiredState && result && result.ai_reload_success === false) {
            throw new Error(result.ai_reload_error || 'AI engine failed to initialize. Check server logs.');
        }

        statusDiv.className = desiredState
            ? 'p-3 rounded-lg text-sm bg-green-900/30 border border-green-700'
            : 'p-3 rounded-lg text-sm bg-blue-900/30 border border-blue-700';
        statusMessage.textContent = desiredState
            ? '✓ AI Insights enabled. Ragnar will request GPT analysis for dashboards.'
            : 'ℹ AI Insights disabled. Ragnar will stop requesting GPT analysis until re-enabled.';
        statusDiv.classList.remove('hidden');

        setTimeout(() => {
            statusDiv.classList.add('hidden');
        }, 4000);

        if (currentTab === 'dashboard') {
            setTimeout(() => {
                loadAIInsights().catch(err => console.error('Failed to refresh AI insights after toggle:', err));
            }, 500);
        }
    } catch (error) {
        console.error('Failed to toggle AI insights:', error);
        checkbox.checked = !desiredState;  // Revert UI state on failure
        statusDiv.className = 'p-3 rounded-lg text-sm bg-red-900/30 border border-red-700';
        statusMessage.textContent = `✗ Failed to ${desiredState ? 'enable' : 'disable'} AI Insights (${error.message || 'unknown error'})`;
        statusDiv.classList.remove('hidden');
        setTimeout(() => {
            statusDiv.classList.add('hidden');
        }, 5000);
    }
}

async function saveAIToken() {
    const tokenInput = document.getElementById('openai-api-token');
    const statusDiv = document.getElementById('ai-config-status');
    const statusMessage = document.getElementById('ai-config-status-message');
    const token = tokenInput.value.trim();
    
    if (!token) {
        statusDiv.className = 'p-3 rounded-lg text-sm bg-yellow-900/30 border border-yellow-700';
        statusMessage.textContent = '⚠ Please enter an API token.';
        statusDiv.classList.remove('hidden');
        setTimeout(() => statusDiv.classList.add('hidden'), 3000);
        return;
    }
    
    try {
        // Save token to .bashrc as environment variable
        const result = await postAPI('/api/ai/token', { token: token });
        
        if (result.success) {
            statusDiv.className = 'p-3 rounded-lg text-sm bg-green-900/30 border border-green-700';
            let message = result.message || '✓ API token saved to .bashrc successfully. AI features are now ready to use.';
            if (result.user) {
                message += ` (User: ${result.user})`;
            }
            statusMessage.textContent = message;
            statusDiv.classList.remove('hidden');
            
            addConsoleMessage('OpenAI API token saved to environment variable', 'success');
            
            // Reload AI configuration to show token preview
            const config = await fetchAPI('/api/config');
            await loadAIConfiguration(config);
            
            // Hide status after 8 seconds (longer to show additional info)
            setTimeout(() => {
                statusDiv.classList.add('hidden');
            }, 8000);
            
            // Refresh dashboard to update AI insights
            if (currentTab === 'dashboard') {
                setTimeout(() => refreshDashboard(), 500);
            }
        } else {
            throw new Error(result.message || 'Failed to save token');
        }
        
    } catch (error) {
        console.error('Failed to save AI token:', error);
        statusDiv.className = 'p-3 rounded-lg text-sm bg-red-900/30 border border-red-700';
        statusMessage.textContent = `✗ Failed to save API token: ${error.message || 'Please try again.'}`;
        statusDiv.classList.remove('hidden');
    }
}

// ─── Pushover Notification Functions ───────────────────────────────────
async function loadPushoverConfiguration(config) {
    // Sync toggle checkboxes from config
    const toggle = document.getElementById('pushover-enabled-toggle');
    if (toggle) toggle.checked = Boolean(config && config.pushover_enabled);

    const evtMap = {
        'pushover-notify-new-device': 'pushover_notify_new_device',
        'pushover-notify-new-vuln': 'pushover_notify_new_vulnerability',
        'pushover-notify-new-cred': 'pushover_notify_new_credential',
        'pushover-notify-device-lost': 'pushover_notify_device_lost',
        'pushover-notify-device-back-online': 'pushover_notify_device_back_online'
    };
    for (const [elemId, key] of Object.entries(evtMap)) {
        const cb = document.getElementById(elemId);
        if (cb) cb.checked = config && Object.prototype.hasOwnProperty.call(config, key) ? Boolean(config[key]) : false;
    }

    // Fetch key status from backend
    try {
        const ks = await fetchAPI('/api/pushover/keys');
        const ukInput = document.getElementById('pushover-user-key');
        const atInput = document.getElementById('pushover-api-token');
        if (ukInput) {
            ukInput.value = '';
            ukInput.placeholder = ks.user_key_configured ? `Configured: ${ks.user_key_preview || '••••'}` : 'Your user key...';
        }
        if (atInput) {
            atInput.value = '';
            atInput.placeholder = ks.api_token_configured ? `Configured: ${ks.api_token_preview || '••••'}` : 'Your app token...';
        }
    } catch (e) {
        console.error('Failed to fetch Pushover key status:', e);
    }
}

async function togglePushoverEnabled() {
    const cb = document.getElementById('pushover-enabled-toggle');
    if (!cb) return;
    try {
        await postAPI('/api/config', { pushover_enabled: cb.checked });
        showPushoverStatus(cb.checked ? '✓ Pushover notifications enabled' : 'ℹ Pushover notifications disabled',
            cb.checked ? 'green' : 'blue');
    } catch (e) {
        cb.checked = !cb.checked;
        showPushoverStatus('✗ Failed to toggle Pushover: ' + (e.message || 'unknown error'), 'red');
    }
}

async function savePushoverKeys() {
    const ukInput = document.getElementById('pushover-user-key');
    const atInput = document.getElementById('pushover-api-token');
    const userKey = ukInput ? ukInput.value.trim() : '';
    const apiToken = atInput ? atInput.value.trim() : '';

    if (!userKey && !apiToken) {
        showPushoverStatus('⚠ Please enter at least one key.', 'yellow');
        return;
    }

    try {
        const payload = {};
        if (userKey) payload.user_key = userKey;
        if (apiToken) payload.api_token = apiToken;
        const result = await postAPI('/api/pushover/keys', payload);
        if (result.success) {
            showPushoverStatus('✓ Pushover keys saved successfully!', 'green');
            addConsoleMessage('Pushover keys saved', 'success');
            const config = await fetchAPI('/api/config');
            await loadPushoverConfiguration(config);
        } else {
            throw new Error(result.message || 'Save failed');
        }
    } catch (e) {
        showPushoverStatus('✗ Failed to save keys: ' + (e.message || 'unknown error'), 'red');
    }
}

async function savePushoverTriggers() {
    const evtMap = {
        'pushover-notify-new-device': 'pushover_notify_new_device',
        'pushover-notify-new-vuln': 'pushover_notify_new_vulnerability',
        'pushover-notify-new-cred': 'pushover_notify_new_credential',
        'pushover-notify-device-lost': 'pushover_notify_device_lost',
        'pushover-notify-device-back-online': 'pushover_notify_device_back_online'
    };
    const payload = {};
    for (const [elemId, key] of Object.entries(evtMap)) {
        const cb = document.getElementById(elemId);
        if (cb) payload[key] = cb.checked;
    }
    try {
        await postAPI('/api/config', payload);
        showPushoverStatus('✓ Notification triggers updated', 'green', 2000);
    } catch (e) {
        showPushoverStatus('✗ Failed to update triggers: ' + (e.message || 'unknown'), 'red');
    }
}

async function testPushover() {
    showPushoverStatus('Sending test notification...', 'blue', 0);
    try {
        const result = await postAPI('/api/pushover/test', {});
        if (result.success) {
            showPushoverStatus('✓ Test notification sent! Check your device.', 'green', 5000);
            addConsoleMessage('Pushover test notification sent', 'success');
        } else {
            throw new Error(result.message || 'Send failed');
        }
    } catch (e) {
        showPushoverStatus('✗ Test failed: ' + (e.message || 'unknown error'), 'red', 6000);
    }
}

function showPushoverStatus(msg, color, timeout) {
    const div = document.getElementById('pushover-config-status');
    const span = document.getElementById('pushover-config-status-message');
    if (!div || !span) return;
    const colors = {
        green:  'bg-green-900/30 border border-green-700',
        red:    'bg-red-900/30 border border-red-700',
        yellow: 'bg-yellow-900/30 border border-yellow-700',
        blue:   'bg-blue-900/30 border border-blue-700'
    };
    div.className = 'p-3 rounded-lg text-sm ' + (colors[color] || colors.blue);
    span.textContent = msg;
    div.classList.remove('hidden');
    if (timeout !== 0) {
        setTimeout(() => div.classList.add('hidden'), timeout || 4000);
    }
}

// E-Paper Display Functions
async function loadEpaperDisplay() {
    try {
        const data = await fetchAPI('/api/epaper-display');
        
        // Update status text
        updateElement('epaper-status-1', data.status_text || 'Unknown');
        updateElement('epaper-status-2', data.status_text2 || 'Unknown');
        
        // Update timestamp
        if (data.timestamp) {
            const date = new Date(data.timestamp * 1000);
            updateElement('epaper-timestamp', date.toLocaleString());
        }
        
        // Update display image
        const imgElement = document.getElementById('epaper-display-image');
        const loadingElement = document.getElementById('epaper-loading');
        const connectionElement = document.getElementById('epaper-connection');
        
        if (data.image) {
            imgElement.src = data.image;
            imgElement.style.display = 'block';
            loadingElement.style.display = 'none';
            
            // Update resolution info
            if (data.width && data.height) {
                updateElement('epaper-resolution', `${data.width} x ${data.height}`);
            }
            
            // Update connection status
            connectionElement.textContent = 'Live';
            connectionElement.className = 'text-green-400 font-medium';
        } else {
            imgElement.style.display = 'none';
            loadingElement.style.display = 'flex';
            loadingElement.innerHTML = `
                <div class="text-center text-gray-600">
                    <svg class="h-8 w-8 mx-auto mb-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                    </svg>
                    <p>${data.message || 'No display image available'}</p>
                </div>
            `;
            
            // Update connection status
            connectionElement.textContent = 'Offline';
            connectionElement.className = 'text-red-400 font-medium';
        }
        
    } catch (error) {
        console.error('Error loading display:', error);
        addConsoleMessage('Failed to load display', 'error');
        
        // Update connection status
        const connectionElement = document.getElementById('epaper-connection');
        connectionElement.textContent = 'Error';
        connectionElement.className = 'text-red-400 font-medium';
    }
}

function refreshEpaperDisplay() {
    addConsoleMessage('Refreshing display...', 'info');
    loadEpaperDisplay();
}

// E-Paper display size toggle functionality
let epaperSizeMode = 'large'; // default to large size
function toggleEpaperSize() {
    const imgElement = document.getElementById('epaper-display-image');
    
    if (epaperSizeMode === 'large') {
        // Switch to extra large
        imgElement.style.maxHeight = '1200px';
        imgElement.style.minHeight = '600px';
        epaperSizeMode = 'xlarge';
        addConsoleMessage('Display size: Extra Large', 'info');
    } else if (epaperSizeMode === 'xlarge') {
        // Switch to medium
        imgElement.style.maxHeight = '600px';
        imgElement.style.minHeight = '300px';
        epaperSizeMode = 'medium';
        addConsoleMessage('Display size: Medium', 'info');
    } else {
        // Switch back to large
        imgElement.style.maxHeight = '800px';
        imgElement.style.minHeight = '400px';
        epaperSizeMode = 'large';
        addConsoleMessage('Display size: Large', 'info');
    }
}

// Add e-paper display to auto-refresh
function setupEpaperAutoRefresh() {
    setInterval(() => {
        if (currentTab === 'epaper') {
            loadEpaperDisplay();
        }
    }, 5000); // Refresh every 5 seconds when on e-paper tab
}

// ============================================================================
// FILE MANAGEMENT FUNCTIONS
// ============================================================================

let currentDirectory = '/';
let fileOperationInProgress = false;
let currentFileSort = 'name';
let currentFileSearch = '';

function setFileSort(sort) {
    currentFileSort = sort;
    document.querySelectorAll('.file-sort-btn').forEach(btn => {
        const isActive = btn.getAttribute('data-sort') === sort;
        btn.classList.toggle('bg-Ragnar-600', isActive);
        btn.classList.toggle('text-white', isActive);
        btn.classList.toggle('text-gray-400', !isActive);
        btn.classList.toggle('hover:text-white', !isActive);
    });
    refreshFiles();
}

function onFileSearch(value) {
    currentFileSearch = value.trim().toLowerCase();
    refreshFiles();
}

function loadFiles(path = '/', highlightFile = null) {
    if (fileOperationInProgress) return;
    const desiredHighlight = highlightFile || (pendingFileHighlight && pendingFileHighlight.directory === path ? pendingFileHighlight.file : null);
    
    networkAwareFetch(`/api/files/list?path=${encodeURIComponent(path)}`)
        .then(response => response.json())
        .then(files => {
            const appliedHighlight = displayFiles(files, path, desiredHighlight);
            updateCurrentPath(path);
            if (desiredHighlight) {
                pendingFileHighlight = null;
            }
        })
        .catch(error => {
            console.error('Error loading files:', error);
            showFileError('Failed to load files: ' + error.message);
        });
}

function displayFiles(files, path, highlightFile = null) {
    const fileList = document.getElementById('file-list');
    currentDirectory = path;
    
    if (!fileList) return false;
    
    if (files.length === 0) {
        fileList.innerHTML = '<p class="text-gray-400 p-4">No files found in this directory</p>';
        return false;
    }
    
    let html = '<div class="space-y-2">';
    
    // Add back button if not in root
    if (path !== '/') {
        const parentPath = path.split('/').slice(0, -1).join('/') || '/';
        html += `
            <div class="flex items-center p-3 hover:bg-slate-700 rounded-lg cursor-pointer transition-colors" onclick="loadFiles('${escapeAttr(parentPath)}')">
                <svg class="w-5 h-5 mr-3 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"></path>
                </svg>
                <span class="text-blue-400">.. (Parent Directory)</span>
            </div>
        `;
    }
    
    // Apply search filter (only to files, not directories)
    if (currentFileSearch) {
        files = files.filter(f => f.is_directory || f.name.toLowerCase().includes(currentFileSearch));
    }

    if (files.length === 0 && currentFileSearch) {
        fileList.innerHTML = `<p class="text-gray-400 p-4">No files match "<span class="text-white">${escapeHtml(currentFileSearch)}</span>"</p>`;
        return false;
    }

    // Sort: directories always first, then apply chosen sort within each group
    files.sort((a, b) => {
        if (a.is_directory && !b.is_directory) return -1;
        if (!a.is_directory && b.is_directory) return 1;
        if (currentFileSort === 'date') return (b.modified || 0) - (a.modified || 0);
        if (currentFileSort === 'size') return (b.size || 0) - (a.size || 0);
        return a.name.toLowerCase().localeCompare(b.name.toLowerCase());
    });

    files.forEach(file => {
        const icon = file.is_directory ? 
            `<svg class="w-5 h-5 mr-3 text-yellow-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-5l-2-2H5a2 2 0 00-2 2z"></path>
            </svg>` :
            `<svg class="w-5 h-5 mr-3 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
            </svg>`;
        
        const size = file.is_directory ? '' : formatBytes(file.size);
        const date = file.modified ? new Date(file.modified * 1000).toLocaleDateString() : '';
        const fileKey = encodeURIComponent(file.name);
        
        html += `
            <div class="flex items-center justify-between p-3 hover:bg-slate-700 rounded-lg transition-colors" data-file-key="${fileKey}">
                <div class="flex items-center cursor-pointer flex-1" onclick="${file.is_directory ? `loadFiles('${escapeAttr(file.path)}')` : `previewFile('${escapeAttr(file.path)}')`}">
                    ${icon}
                    <div class="flex-1">
                        <div class="font-medium">${escapeHtml(file.name)}</div>
                        ${!file.is_directory && size ? `<div class="text-sm text-gray-400">${size} • ${date}</div>` : ''}
                    </div>
                </div>
                ${!file.is_directory ? `
                    <div class="flex space-x-2">
                        <button onclick="downloadFile('${escapeAttr(file.path)}')" class="p-2 text-blue-400 hover:bg-slate-600 rounded" title="Download">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-4-4m4 4l4-4m6 4H6"></path>
                            </svg>
                        </button>
                        <button onclick="deleteFile('${escapeAttr(file.path)}')" class="p-2 text-red-400 hover:bg-slate-600 rounded" title="Delete">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path>
                            </svg>
                        </button>
                    </div>
                ` : ''}
            </div>
        `;
    });
    
    html += '</div>';
    fileList.innerHTML = html;

    if (highlightFile) {
        const highlightKey = encodeURIComponent(highlightFile);
        const target = fileList.querySelector(`[data-file-key="${highlightKey}"]`);
        if (target) {
            target.classList.add('ring-2', 'ring-Ragnar-500', 'ring-offset-2', 'ring-offset-slate-900');
            target.scrollIntoView({ behavior: 'smooth', block: 'center' });
            setTimeout(() => {
                target.classList.remove('ring-2', 'ring-Ragnar-500', 'ring-offset-2', 'ring-offset-slate-900');
            }, 4000);
            return true;
        }
        addConsoleMessage(`Could not highlight ${highlightFile} under ${path}`, 'warning');
    }

    return false;
}

function displayDirectoryTree() {
    const treeContainer = document.getElementById('directory-tree');
    if (!treeContainer) return;
    
    const directories = [
        { name: 'Data Stolen', path: '/data_stolen', icon: '🗃️' },
        { name: 'Scan Results', path: '/scan_results', icon: '📊' },
        { name: 'Cracked Passwords', path: '/crackedpwd', icon: '🔓' },
        { name: 'Vulnerabilities', path: '/vulnerabilities', icon: '⚠️' },
        { name: 'Logs', path: '/logs', icon: '📋' },
        { name: 'Backups', path: '/backups', icon: '💾' },
        { name: 'Uploads', path: '/uploads', icon: '📤' }
    ];
    
    let html = '<div class="space-y-1">';
    directories.forEach(dir => {
        html += `
            <div class="flex items-center p-3 hover:bg-slate-700 rounded-lg cursor-pointer transition-colors" onclick="loadFiles('${dir.path}')">
                <span class="mr-3">${dir.icon}</span>
                <span>${dir.name}</span>
            </div>
        `;
    });
    html += '</div>';
    
    treeContainer.innerHTML = html;
}

function updateCurrentPath(path) {
    const pathElement = document.getElementById('current-path');
    if (pathElement) {
        pathElement.textContent = path;
    }
}

function downloadFile(filePath) {
    if (fileOperationInProgress) return;
    
    const downloadUrl = resolveNetworkAwareEndpoint(`/api/files/download?path=${encodeURIComponent(filePath)}`);
    
    // Create a temporary link to trigger download
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.download = '';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    
    showFileSuccess(`Downloading ${filePath.split('/').pop()}`);
}

// ── File Preview ────────────────────────────────────────────────
function previewFile(filePath) {
    const modal = document.getElementById('file-preview-modal');
    const content = document.getElementById('preview-content');
    const filename = document.getElementById('preview-filename');
    const truncBadge = document.getElementById('preview-truncated-badge');
    const dlBtn = document.getElementById('preview-download-btn');
    if (!modal) return;

    const name = filePath.split('/').pop();
    filename.textContent = name;
    truncBadge.classList.add('hidden');
    content.innerHTML = `<div class="text-center text-gray-400 py-12">
        <svg class="w-8 h-8 inline animate-spin mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
        </svg>
        <p>Loading preview...</p>
    </div>`;

    dlBtn.onclick = () => downloadFile(filePath);
    modal.classList.remove('hidden');
    modal.classList.add('flex');

    networkAwareFetch(`/api/files/preview?path=${encodeURIComponent(filePath)}`)
        .then(r => r.json())
        .then(data => {
            if (data.error) {
                content.innerHTML = `<p class="text-red-400 p-4">${escapeHtml(data.error)}</p>`;
                return;
            }
            if (data.type === 'image') {
                content.innerHTML = `<div class="flex items-center justify-center h-full p-4">
                    <img src="data:${data.mime};base64,${data.data}" alt="${escapeHtml(name)}" class="max-w-full max-h-full object-contain rounded">
                </div>`;
            } else if (data.type === 'text') {
                if (data.truncated) truncBadge.classList.remove('hidden');
                const isCSV = name.toLowerCase().endsWith('.csv');
                if (isCSV) {
                    // Render CSV as table
                    const lines = data.content.split('\n').filter(l => l.trim());
                    if (lines.length > 0) {
                        const headers = lines[0].split(',');
                        const rows = lines.slice(1);
                        content.innerHTML = `<div class="overflow-auto"><table class="w-full text-xs border-collapse">
                            <thead><tr>${headers.map(h => `<th class="border border-slate-600 px-2 py-1 bg-slate-800 text-left">${escapeHtml(h.trim())}</th>`).join('')}</tr></thead>
                            <tbody>${rows.map(r => `<tr class="hover:bg-slate-800">${r.split(',').map(c => `<td class="border border-slate-700 px-2 py-1 font-mono">${escapeHtml(c.trim())}</td>`).join('')}</tr>`).join('')}</tbody>
                        </table></div>`;
                    }
                } else {
                    content.innerHTML = `<pre class="text-xs text-gray-300 font-mono whitespace-pre-wrap break-words leading-relaxed">${escapeHtml(data.content)}</pre>`;
                }
            } else if (data.type === 'too_large') {
                content.innerHTML = `<div class="text-center text-gray-400 py-12">
                    <p class="mb-3">File is too large to preview (${formatBytes(data.size)})</p>
                    <button onclick="downloadFile('${escapeAttr(filePath)}')" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm">Download Instead</button>
                </div>`;
            } else {
                content.innerHTML = `<div class="text-center text-gray-400 py-12">
                    <p class="mb-1">Cannot preview this file type (${escapeHtml(data.mime || 'unknown')})</p>
                    <p class="text-sm mb-3">Size: ${formatBytes(data.size)}</p>
                    <button onclick="downloadFile('${escapeAttr(filePath)}')" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm">Download</button>
                </div>`;
            }
        })
        .catch(err => {
            content.innerHTML = `<p class="text-red-400 p-4">Failed to load preview: ${escapeHtml(err.message)}</p>`;
        });
}

function closeFilePreview() {
    const modal = document.getElementById('file-preview-modal');
    if (modal) { modal.classList.add('hidden'); modal.classList.remove('flex'); }
}

// Close preview on backdrop click or Escape key
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeFilePreview(); });
document.getElementById('file-preview-modal')?.addEventListener('click', function(e) {
    if (e.target === this) closeFilePreview();
});

function deleteFile(filePath) {
    if (fileOperationInProgress) return;
    
    const fileName = filePath.split('/').pop();
    showFileConfirmModal(
        'Delete File',
        `Are you sure you want to delete "${fileName}"? This action cannot be undone.`,
        () => {
            fileOperationInProgress = true;
            networkAwareFetch('/api/files/delete', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ path: filePath })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showFileSuccess(`Deleted ${fileName}`);
                    refreshFiles();
                } else {
                    showFileError(`Failed to delete file: ${data.error}`);
                }
            })
            .catch(error => {
                showFileError(`Error deleting file: ${error.message}`);
            })
            .finally(() => {
                fileOperationInProgress = false;
                closeFileModal();
            });
        }
    );
}

function uploadFile() {
    // Create file input
    const input = document.createElement('input');
    input.type = 'file';
    input.multiple = true;
    
    input.onchange = function(event) {
        const files = event.target.files;
        if (files.length === 0) return;
        
        const formData = new FormData();
        
        // Add all selected files
        for (let file of files) {
            formData.append('file', file);
        }
        
        // Set upload path (default to uploads)
        formData.append('path', '/uploads');
        
        fileOperationInProgress = true;
        showFileLoading('Uploading files...');
        
        networkAwareFetch('/api/files/upload', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showFileSuccess(`Uploaded ${files.length} file(s)`);
                refreshFiles();
            } else {
                showFileError(`Upload failed: ${data.error}`);
            }
        })
        .catch(error => {
            showFileError(`Upload error: ${error.message}`);
        })
        .finally(() => {
            fileOperationInProgress = false;
        });
    };
    
    input.click();
}

function clearFiles() {
    showFileConfirmModal(
        'Clear Files',
        `
        <div class="space-y-3">
            <p>Choose the type of file clearing:</p>
            <div class="space-y-2">
                <label class="flex items-center">
                    <input type="radio" name="clearType" value="light" checked class="mr-2">
                    <span>Light Clear (logs, temporary files only)</span>
                </label>
                <label class="flex items-center">
                    <input type="radio" name="clearType" value="full" class="mr-2">
                    <span>Full Clear (all data including configs)</span>
                </label>
            </div>
        </div>
        `,
        () => {
            const selectedType = document.querySelector('input[name="clearType"]:checked')?.value || 'light';
            
            fileOperationInProgress = true;
            showFileLoading('Clearing files...');
            
            networkAwareFetch('/api/files/clear', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ type: selectedType })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showFileSuccess(data.message);
                    refreshFiles();
                } else {
                    showFileError(`Clear failed: ${data.error}`);
                }
            })
            .catch(error => {
                showFileError(`Clear error: ${error.message}`);
            })
            .finally(() => {
                fileOperationInProgress = false;
                closeFileModal();
            });
        }
    );
}

function refreshFiles() {
    displayDirectoryTree();
    loadFiles(currentDirectory);
}

function showFileSuccess(message) {
    showNotification(message, 'success');
}

function showFileError(message) {
    showNotification(message, 'error');
}

function showFileLoading(message) {
    showNotification(message, 'info');
}

function showFileConfirmModal(title, content, onConfirm) {
    const modal = document.getElementById('file-operations-modal');
    const modalTitle = document.getElementById('modal-title');
    const modalContent = document.getElementById('modal-content');
    const confirmBtn = document.getElementById('modal-confirm');
    
    if (!modal || !modalTitle || !modalContent || !confirmBtn) return;
    
    modalTitle.textContent = title;
    modalContent.innerHTML = content;
    
    // Remove existing listeners
    const newConfirmBtn = confirmBtn.cloneNode(true);
    confirmBtn.parentNode.replaceChild(newConfirmBtn, confirmBtn);
    
    // Add new listener
    newConfirmBtn.addEventListener('click', onConfirm);
    
    modal.classList.remove('hidden');
    modal.classList.add('flex');
}

function closeFileModal() {
    const modal = document.getElementById('file-operations-modal');
    if (modal) {
        modal.classList.add('hidden');
        modal.classList.remove('flex');
    }
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function showNotification(message, type) {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `fixed top-4 right-4 z-50 p-4 rounded-lg max-w-sm transform translate-x-full transition-transform duration-300 ${
        type === 'success' ? 'bg-green-600' : 
        type === 'error' ? 'bg-red-600' : 
        'bg-blue-600'
    } text-white`;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    // Animate in
    setTimeout(() => {
        notification.style.transform = 'translateX(0)';
    }, 100);
    
    // Remove after 3 seconds
    setTimeout(() => {
        notification.style.transform = 'translateX(100%)';
        setTimeout(() => {
            document.body.removeChild(notification);
        }, 300);
    }, 3000);
}

// ============================================================================
// SYSTEM MONITORING FUNCTIONS
// ============================================================================

let systemMonitoringInterval;
let currentProcessSort = 'cpu';

function loadSystemData() {
    fetchSystemStatus();
    fetchNetworkStats();
    
    // Auto-refresh every 5 seconds when on system tab
    if (systemMonitoringInterval) {
        clearInterval(systemMonitoringInterval);
    }
    
    systemMonitoringInterval = setInterval(() => {
        if (currentTab === 'system') {
            fetchSystemStatus();
            fetchNetworkStats();
        }
    }, 5000);
}

function fetchSystemStatus() {
    networkAwareFetch('/api/system/status')
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                showSystemError('Failed to load system status: ' + data.error);
                return;
            }
            updateSystemOverview(data);
            updateProcessList(data.processes);
            updateNetworkInterfaces(data.network_interfaces);
            updateTemperatureDisplay(data.temperatures);
        })
        .catch(error => {
            console.error('Error fetching system status:', error);
            showSystemError('Failed to load system status');
        });
}

function fetchNetworkStats() {
    networkAwareFetch('/api/system/network-stats')
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                console.error('Network stats error:', data.error);
                return;
            }
            updateNetworkStats(data);
        })
        .catch(error => {
            console.error('Error fetching network stats:', error);
        });
}

function updateSystemOverview(data) {
    // CPU
    const cpuUsage = document.getElementById('cpu-usage');
    const cpuDetails = document.getElementById('cpu-details');
    const cpuProgress = document.getElementById('cpu-progress');
    
    if (cpuUsage) cpuUsage.textContent = `${data.cpu.percent}%`;
    if (cpuDetails) cpuDetails.textContent = `${data.cpu.count} cores`;
    if (cpuProgress) cpuProgress.style.width = `${data.cpu.percent}%`;
    
    // Memory
    const memoryUsage = document.getElementById('memory-usage');
    const memoryDetails = document.getElementById('memory-details');
    const memoryProgress = document.getElementById('memory-progress');
    
    if (memoryUsage) memoryUsage.textContent = `${data.memory.percent}%`;
    if (memoryDetails) memoryDetails.textContent = `${data.memory.used_formatted} / ${data.memory.total_formatted}`;
    if (memoryProgress) memoryProgress.style.width = `${data.memory.percent}%`;

    // Swap (if reported)
    if (data.swap) {
        const swapUsage = document.getElementById('swap-usage');
        const swapDetails = document.getElementById('swap-details');
        const swapProgress = document.getElementById('swap-progress');
        const swapPercent = Number.isFinite(data.swap.percent) ? data.swap.percent : 0;

        if (swapUsage) swapUsage.textContent = `${swapPercent}%`;
        if (swapDetails) swapDetails.textContent = `${data.swap.used_formatted} / ${data.swap.total_formatted}`;
        if (swapProgress) swapProgress.style.width = `${swapPercent}%`;
    }
    
    // Disk
    const diskUsage = document.getElementById('disk-usage');
    const diskDetails = document.getElementById('disk-details');
    const diskProgress = document.getElementById('disk-progress');
    
    if (diskUsage) diskUsage.textContent = `${data.disk.percent}%`;
    if (diskDetails) diskDetails.textContent = `${data.disk.used_formatted} / ${data.disk.total_formatted}`;
    if (diskProgress) diskProgress.style.width = `${data.disk.percent}%`;
    
    // Battery (PiSugar - only shown when connected)
    const batteryCard = document.getElementById('battery-card');
    if (batteryCard) {
        if (data.battery) {
            batteryCard.classList.remove('hidden');
            const lvl = data.battery.level;
            const charging = data.battery.charging;
            const batteryUsage = document.getElementById('battery-usage');
            const batteryDetails = document.getElementById('battery-details');
            const batteryProgress = document.getElementById('battery-progress');
            const batteryIcon = document.getElementById('battery-icon');

            if (batteryUsage) batteryUsage.textContent = `${lvl}%`;
            if (batteryDetails) {
                let detail = charging ? 'Charging' : 'On battery';
                if (data.battery.voltage) detail += ` (${data.battery.voltage}V)`;
                batteryDetails.textContent = detail;
            }
            if (batteryProgress) {
                batteryProgress.style.width = `${lvl}%`;
                batteryProgress.className = 'h-2 rounded-full transition-all duration-300 ' +
                    (lvl <= 20 ? 'bg-red-500' : lvl <= 50 ? 'bg-yellow-500' : 'bg-emerald-500');
            }
            if (batteryIcon) {
                batteryIcon.className = 'w-5 h-5 ' +
                    (lvl <= 20 ? 'text-red-400' : lvl <= 50 ? 'text-yellow-400' : 'text-emerald-400');
            }
        } else {
            batteryCard.classList.add('hidden');
        }
    }

    // Uptime
    const uptimeDisplay = document.getElementById('uptime-display');
    if (uptimeDisplay) uptimeDisplay.textContent = data.uptime.formatted;
}

function updateProcessList(processes) {
    const processList = document.getElementById('process-list');
    if (!processList) return;
    
    if (processes.length === 0) {
        processList.innerHTML = '<p class="text-gray-400 text-center py-4">No process data available</p>';
        return;
    }
    
    let html = '';
    processes.slice(0, 10).forEach(proc => {
        const cpuPercent = (proc.cpu_percent || 0).toFixed(1);
        const memoryPercent = (proc.memory_percent || 0).toFixed(1);
        
        html += `
            <div class="flex items-center justify-between p-2 bg-slate-800 rounded text-sm">
                <div class="flex-1 truncate">
                    <span class="font-medium">${proc.name}</span>
                    <span class="text-gray-400 ml-2">PID: ${proc.pid}</span>
                </div>
                <div class="flex space-x-3 text-xs">
                    <span class="text-blue-400">${cpuPercent}% CPU</span>
                    <span class="text-green-400">${memoryPercent}% MEM</span>
                </div>
            </div>
        `;
    });
    
    processList.innerHTML = html;
}

function updateNetworkInterfaces(interfaces) {
    const networkInterfaces = document.getElementById('network-interfaces');
    if (!networkInterfaces) return;
    
    if (interfaces.length === 0) {
        networkInterfaces.innerHTML = '<p class="text-gray-400 text-center py-4">No network interfaces found</p>';
        return;
    }
    
    let html = '';
    interfaces.forEach(iface => {
        const statusColor = iface.is_up ? 'text-green-400' : 'text-red-400';
        const statusText = iface.is_up ? 'UP' : 'DOWN';
        
        html += `
            <div class="border border-gray-700 rounded p-3">
                <div class="flex items-center justify-between mb-2">
                    <span class="font-medium">${iface.name}</span>
                    <span class="${statusColor} text-xs">${statusText}</span>
                </div>
                <div class="text-xs text-gray-400 space-y-1">
                    ${iface.speed > 0 ? `<div>Speed: ${iface.speed} Mbps</div>` : ''}
                    ${iface.addresses.map(addr => 
                        `<div>${addr.address} (${addr.family})</div>`
                    ).join('')}
                </div>
            </div>
        `;
    });
    
    networkInterfaces.innerHTML = html;
}

function updateNetworkStats(data) {
    const networkStats = document.getElementById('network-stats');
    if (!networkStats) return;
    
    let html = '';
    
    // Connection summary
    html += `
        <div class="bg-slate-800 rounded p-3">
            <h4 class="font-medium mb-2">Connections</h4>
            <div class="text-2xl font-bold text-blue-400">${data.total_connections}</div>
            <div class="text-xs text-gray-400">Total active</div>
        </div>
    `;
    
    // Interface statistics
    Object.entries(data.interfaces).slice(0, 4).forEach(([name, stats]) => {
        html += `
            <div class="bg-slate-800 rounded p-3">
                <h4 class="font-medium mb-2">${name}</h4>
                <div class="text-xs space-y-1">
                    <div class="flex justify-between">
                        <span class="text-gray-400">Sent:</span>
                        <span class="text-green-400">${stats.bytes_sent_formatted}</span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-gray-400">Received:</span>
                        <span class="text-blue-400">${stats.bytes_recv_formatted}</span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-gray-400">Packets:</span>
                        <span>${stats.packets_sent + stats.packets_recv}</span>
                    </div>
                </div>
            </div>
        `;
    });
    
    networkStats.innerHTML = html;
}

function updateTemperatureDisplay(temperatures) {
    const tempSection = document.getElementById('temperature-section');
    const tempDisplay = document.getElementById('temperature-display');
    
    if (!tempSection || !tempDisplay) return;
    
    if (Object.keys(temperatures).length === 0) {
        tempSection.classList.add('hidden');
        return;
    }
    
    tempSection.classList.remove('hidden');
    
    let html = '';
    Object.entries(temperatures).forEach(([sensor, temp]) => {
        const tempColor = temp > 70 ? 'text-red-400' : temp > 50 ? 'text-yellow-400' : 'text-green-400';
        
        html += `
            <div class="bg-slate-800 rounded p-3">
                <h4 class="font-medium mb-1 text-sm">${sensor}</h4>
                <div class="text-xl font-bold ${tempColor}">${temp.toFixed(1)}°C</div>
            </div>
        `;
    });
    
    tempDisplay.innerHTML = html;
}

function sortProcesses(sortBy) {
    currentProcessSort = sortBy;
    
    // Update button states
    document.querySelectorAll('.process-sort-btn').forEach(btn => {
        if (btn.dataset.sort === sortBy) {
            btn.classList.remove('bg-gray-600');
            btn.classList.add('bg-Ragnar-600');
        } else {
            btn.classList.remove('bg-Ragnar-600');
            btn.classList.add('bg-gray-600');
        }
    });
    
    // Fetch processes with new sort order
    networkAwareFetch(`/api/system/processes?sort=${sortBy}`)
        .then(response => response.json())
        .then(processes => {
            updateProcessList(processes);
        })
        .catch(error => {
            console.error('Error sorting processes:', error);
        });
}

function refreshSystemStatus() {
    fetchSystemStatus();
    fetchNetworkStats();
    showSystemSuccess('System status refreshed');
}

function showSystemSuccess(message) {
    showNotification(message, 'success');
}

function showSystemError(message) {
    showNotification(message, 'error');
}

// ============================================================================
// NETKB (Network Knowledge Base) FUNCTIONS
// ============================================================================

let currentNetkbFilter = 'all';
let netkbData = [];

function loadNetkbData() {
    fetchNetkbData();
}

function fetchNetkbData() {
    networkAwareFetch('/api/netkb/data')
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                showNetkbError('Failed to load NetKB data: ' + data.error);
                return;
            }
            netkbData = data.entries || [];
            updateNetkbStatistics(data.statistics || {});
            displayNetkbData(netkbData);
        })
        .catch(error => {
            console.error('Error fetching NetKB data:', error);
            showNetkbError('Failed to load NetKB data');
        });
}

function updateNetkbStatistics(stats) {
    const totalEntries = document.getElementById('netkb-total-entries');
    const vulnerabilities = document.getElementById('netkb-vulnerabilities');
    const services = document.getElementById('netkb-services');
    const hosts = document.getElementById('netkb-hosts');
    
    if (totalEntries) totalEntries.textContent = stats.total_entries || 0;
    if (vulnerabilities) vulnerabilities.textContent = stats.vulnerabilities || 0;
    if (services) services.textContent = stats.services || 0;
    if (hosts) hosts.textContent = stats.unique_hosts || 0;
}

function displayNetkbData(entries) {
    const tableBody = document.getElementById('netkb-table-body');
    if (!tableBody) return;
    
    if (entries.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="7" class="text-center text-gray-400 py-8">No NetKB entries found</td></tr>';
        return;
    }
    
    let html = '';
    entries.forEach(entry => {
        const severityColor = getSeverityColor(entry.severity);
        const typeIcon = getTypeIcon(entry.type);
        const discoveredDate = new Date(entry.discovered * 1000).toLocaleDateString();
        
        html += `
            <tr class="border-b border-gray-800 hover:bg-slate-800 cursor-pointer" onclick="showNetkbEntryDetail('${entry.id}')">
                <td class="p-3">
                    <span class="inline-flex items-center">
                        ${typeIcon}
                        <span class="ml-2 capitalize">${entry.type}</span>
                    </span>
                </td>
                <td class="p-3 font-mono text-sm">${entry.host}</td>
                <td class="p-3 font-mono text-sm">${entry.port || '-'}</td>
                <td class="p-3">
                    <span class="font-medium">${entry.service || entry.description}</span>
                    <div class="text-xs text-gray-400 mt-1">${entry.description}</div>
                </td>
                <td class="p-3">
                    <span class="px-2 py-1 rounded text-xs font-medium ${severityColor}">
                        ${entry.severity}
                    </span>
                </td>
                <td class="p-3 text-sm text-gray-400">${discoveredDate}</td>
                <td class="p-3">
                    <div class="flex space-x-2">
                        <button onclick="event.stopPropagation(); showNetkbEntryDetail('${entry.id}')" 
                                class="text-blue-400 hover:text-blue-300 text-xs">
                            View
                        </button>
                        ${entry.type === 'vulnerability' ? 
                            `<button onclick="event.stopPropagation(); researchVulnerability('${entry.cve || entry.id}')" 
                                     class="text-orange-400 hover:text-orange-300 text-xs">
                                Research
                            </button>` : ''
                        }
                    </div>
                </td>
            </tr>
        `;
    });
    
    tableBody.innerHTML = html;
}

function getSeverityColor(severity) {
    switch (severity.toLowerCase()) {
        case 'critical': return 'bg-red-900 text-red-200';
        case 'high': return 'bg-red-800 text-red-100';
        case 'medium': return 'bg-yellow-800 text-yellow-100';
        case 'low': return 'bg-blue-800 text-blue-100';
        case 'info': return 'bg-gray-700 text-gray-200';
        default: return 'bg-gray-600 text-gray-200';
    }
}

function getTypeIcon(type) {
    switch (type.toLowerCase()) {
        case 'vulnerability':
            return '<svg class="w-4 h-4 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>';
        case 'service':
            return '<svg class="w-4 h-4 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>';
        case 'host':
            return '<svg class="w-4 h-4 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z"></path></svg>';
        case 'exploit':
            return '<svg class="w-4 h-4 text-orange-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>';
        default:
            return '<svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>';
    }
}

function filterNetkbData(filterType) {
    currentNetkbFilter = filterType;
    
    // Update button states
    document.querySelectorAll('.netkb-filter-btn').forEach(btn => {
        if (btn.dataset.filter === filterType) {
            btn.classList.remove('bg-gray-600');
            btn.classList.add('bg-Ragnar-600');
        } else {
            btn.classList.remove('bg-Ragnar-600');
            btn.classList.add('bg-gray-600');
        }
    });
    
    // Filter and display data
    let filteredData = netkbData;
    if (filterType !== 'all') {
        filteredData = netkbData.filter(entry => entry.type === filterType);
    }
    
    displayNetkbData(filteredData);
}

function searchNetkbData(searchTerm) {
    const filtered = netkbData.filter(entry => {
        const searchLower = searchTerm.toLowerCase();
        return entry.host.toLowerCase().includes(searchLower) ||
               entry.service.toLowerCase().includes(searchLower) ||
               entry.description.toLowerCase().includes(searchLower) ||
               entry.type.toLowerCase().includes(searchLower);
    });
    
    displayNetkbData(filtered);
}

function clearNetkbSearch() {
    const searchInput = document.getElementById('netkb-search');
    if (searchInput) {
        searchInput.value = '';
        filterNetkbData(currentNetkbFilter);
    }
}

function showNetkbEntryDetail(entryId) {
    const entry = netkbData.find(e => e.id === entryId);
    if (!entry) return;
    
    const modal = document.getElementById('netkb-detail-modal');
    const title = document.getElementById('netkb-detail-title');
    const content = document.getElementById('netkb-detail-content');
    
    if (!modal || !title || !content) return;
    
    title.textContent = `${entry.type.toUpperCase()}: ${entry.host}`;
    
    const discoveredDate = new Date(entry.discovered * 1000).toLocaleString();
    const severityColor = getSeverityColor(entry.severity);
    
    content.innerHTML = `
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div class="space-y-3">
                <div>
                    <label class="text-sm text-gray-400">Host/Target</label>
                    <div class="font-mono text-lg">${entry.host}</div>
                </div>
                <div>
                    <label class="text-sm text-gray-400">Service/Port</label>
                    <div class="font-mono">${entry.port || 'N/A'} ${entry.service ? '(' + entry.service + ')' : ''}</div>
                </div>
                <div>
                    <label class="text-sm text-gray-400">Type</label>
                    <div class="capitalize">${entry.type}</div>
                </div>
                <div>
                    <label class="text-sm text-gray-400">Severity</label>
                    <div><span class="px-2 py-1 rounded text-sm ${severityColor}">${entry.severity}</span></div>
                </div>
            </div>
            <div class="space-y-3">
                <div>
                    <label class="text-sm text-gray-400">Description</label>
                    <div class="text-sm">${entry.description}</div>
                </div>
                <div>
                    <label class="text-sm text-gray-400">Source</label>
                    <div class="text-sm">${entry.source}</div>
                </div>
                <div>
                    <label class="text-sm text-gray-400">Discovered</label>
                    <div class="text-sm">${discoveredDate}</div>
                </div>
                ${entry.cve ? `
                <div>
                    <label class="text-sm text-gray-400">CVE</label>
                    <div class="font-mono text-sm">${entry.cve}</div>
                </div>
                ` : ''}
            </div>
        </div>
        
        <div class="mt-6 p-4 bg-slate-800 rounded-lg">
            <h4 class="font-medium mb-2">Recommendations</h4>
            <ul class="text-sm text-gray-300 space-y-1">
                <li>• Monitor this ${entry.type} regularly for changes</li>
                <li>• Consider implementing additional security measures</li>
                <li>• Review access controls and firewall rules</li>
                ${entry.type === 'vulnerability' ? '<li>• Apply security patches if available</li>' : ''}
                ${entry.type === 'service' ? '<li>• Ensure service is properly configured and updated</li>' : ''}
            </ul>
        </div>
    `;
    
    // Show/hide exploit button based on entry type
    const exploitBtn = document.getElementById('netkb-exploit-btn');
    if (exploitBtn) {
        if (entry.type === 'vulnerability') {
            exploitBtn.classList.remove('hidden');
            exploitBtn.onclick = () => exploitVulnerability(entry);
        } else {
            exploitBtn.classList.add('hidden');
        }
    }
    
    // Update research button
    const researchBtn = document.getElementById('netkb-research-btn');
    if (researchBtn) {
        researchBtn.onclick = () => researchEntry(entry);
    }
    
    modal.classList.remove('hidden');
    modal.classList.add('flex');
}

function closeNetkbModal() {
    const modal = document.getElementById('netkb-detail-modal');
    if (modal) {
        modal.classList.add('hidden');
        modal.classList.remove('flex');
    }
}

function refreshNetkbData() {
    fetchNetkbData();
    showNetkbSuccess('NetKB data refreshed');
}

function exportNetkbData() {
    const format = prompt('Export format (json/csv):', 'json');
    if (format && (format === 'json' || format === 'csv')) {
        window.open(`/api/netkb/export?format=${format}`, '_blank');
        showNetkbSuccess(`NetKB data exported as ${format.toUpperCase()}`);
    }
}

function exportNetkbEntry() {
    // Export the currently viewed entry
    showNetkbInfo('Individual entry export feature coming soon');
}

function researchEntry(entry) {
    let searchUrl = 'https://www.google.com/search?q=';
    let searchTerm = '';
    
    if (entry.cve) {
        searchTerm = entry.cve;
    } else if (entry.service) {
        searchTerm = `${entry.service} vulnerability exploit`;
    } else {
        searchTerm = `${entry.host} ${entry.description}`;
    }
    
    window.open(searchUrl + encodeURIComponent(searchTerm), '_blank');
    showNetkbInfo(`Researching: ${searchTerm}`);
}

function researchVulnerability(cveOrId) {
    let searchUrl = 'https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=';
    window.open(searchUrl + encodeURIComponent(cveOrId), '_blank');
    showNetkbInfo(`Researching vulnerability: ${cveOrId}`);
}

function exploitVulnerability(entry) {
    const confirmMsg = `Are you sure you want to attempt exploitation of ${entry.cve || entry.description} on ${entry.host}?`;
    if (confirm(confirmMsg)) {
        showNetkbInfo('Exploitation feature not yet implemented - this would trigger automated exploit attempts');
        // TODO: Implement actual exploitation logic
    }
}

function showNetkbSuccess(message) {
    showNotification(message, 'success');
}

function showNetkbError(message) {
    showNotification(message, 'error');
}

function showNetkbInfo(message) {
    showNotification(message, 'info');
}

// ============================================================================
// GLOBAL FUNCTION EXPORTS (for HTML onclick handlers)
// ============================================================================

// Make functions available globally for HTML onclick handlers
window.loadConsoleLogs = loadConsoleLogs;
window.clearConsole = clearConsole;
window.refreshEpaperDisplay = refreshEpaperDisplay;
window.toggleEpaperSize = toggleEpaperSize;
window.checkForUpdates = checkForUpdates;
window.checkForUpdatesQuiet = checkForUpdatesQuiet;
window.performUpdate = performUpdate;
window.handleReleaseGateDecision = handleReleaseGateDecision;
window.restartService = restartService;
window.rebootSystem = rebootSystem;
window.startAPMode = startAPMode;
window.refreshWifiStatus = refreshWifiStatus;
window.updateManualPorts = updateManualPorts;
window.executeManualAttack = executeManualAttack;
window.startOrchestrator = startOrchestrator;
window.stopOrchestrator = stopOrchestrator;
window.triggerNetworkScan = triggerNetworkScan;
window.triggerVulnScan = triggerVulnScan;
window.refreshDashboard = refreshDashboard;

// Headless Mode Functions
window.handleHeadlessMode = handleHeadlessMode;
window.applyHeadlessVisibility = applyHeadlessVisibility;

// Wi-Fi Management Functions
window.loadWifiInterfaces = loadWifiInterfaces;
window.scanWifiNetworks = scanWifiNetworks;
window.openWifiConnectModal = openWifiConnectModal;
window.closeWifiConnectModal = closeWifiConnectModal;
window.togglePasswordVisibility = togglePasswordVisibility;
window.connectToWifiNetwork = connectToWifiNetwork;

// Bluetooth Management Functions
window.refreshBluetoothStatus = refreshBluetoothStatus;
window.toggleBluetoothPower = toggleBluetoothPower;
window.toggleBluetoothDiscoverable = toggleBluetoothDiscoverable;
window.startBluetoothScan = startBluetoothScan;
window.showBluetoothDeviceDetails = showBluetoothDeviceDetails;
window.closeBluetoothDeviceModal = closeBluetoothDeviceModal;
window.pairBluetoothDevice = pairBluetoothDevice;
window.enumerateBluetoothServices = enumerateBluetoothServices;
window.clearBluetoothDevices = clearBluetoothDevices;

// File Management Functions
window.loadFiles = loadFiles;
window.downloadFile = downloadFile;
window.deleteFile = deleteFile;
window.uploadFile = uploadFile;
window.clearFiles = clearFiles;
window.refreshFiles = refreshFiles;
window.closeFileModal = closeFileModal;
window.openLootFile = openLootFile;

// System Monitoring Functions
window.loadSystemData = loadSystemData;
window.sortProcesses = sortProcesses;
window.refreshSystemStatus = refreshSystemStatus;

// Dashboard Functions
window.loadDashboardData = loadDashboardData;
window.updateDashboardStats = updateDashboardStats;

// NetKB Functions
window.loadNetkbData = loadNetkbData;
window.refreshNetkbData = refreshNetkbData;
window.filterNetkbData = filterNetkbData;
window.searchNetkbData = searchNetkbData;
window.clearNetkbSearch = clearNetkbSearch;
window.showNetkbEntryDetail = showNetkbEntryDetail;
window.closeNetkbModal = closeNetkbModal;
window.exportNetkbData = exportNetkbData;
window.exportNetkbEntry = exportNetkbEntry;
window.researchEntry = researchEntry;
window.researchVulnerability = researchVulnerability;
window.exploitVulnerability = exploitVulnerability;

// Deep Scan Functions
window.triggerDeepScan = triggerDeepScan;
window.handleCustomDeepScanRequest = handleCustomDeepScanRequest;
window.testDeepScan = testDeepScan;

// Host Detail Panel Functions
window.openHostPanel = openHostPanel;
window.closeHostPanel = closeHostPanel;
window.renderHostPanel = renderHostPanel;

// Debug Functions
window.debugDeepScanStates = function() {
    console.log('Current deep scan button states:', Object.fromEntries(deepScanButtonStates));
};

// Threat Intelligence Functions
window.loadThreatIntelData = loadThreatIntelData;
window.refreshThreatIntel = refreshThreatIntel;
window.enrichTarget = enrichTarget;
window.updateThreatIntelStats = updateThreatIntelStats;
window.toggleHostDetails = toggleHostDetails;
window.showVulnerabilityDetails = showVulnerabilityDetails;
window.closeVulnerabilityModal = closeVulnerabilityModal;
window.setThreatIntelFilter = setThreatIntelFilter;

// ===========================================
// THREAT INTELLIGENCE FUNCTIONS
// ===========================================

function setThreatIntelFilter(status, options = {}) {
    const validStatuses = ['open', 'resolved', 'all'];
    if (!validStatuses.includes(status)) {
        return;
    }

    threatIntelStatusFilter = status;

    const activeClasses = 'threat-intel-filter-btn px-3 py-2 rounded-lg text-sm font-semibold border border-Ragnar-500 bg-Ragnar-600 text-white shadow-md shadow-Ragnar-500/40';
    const inactiveClasses = 'threat-intel-filter-btn px-3 py-2 rounded-lg text-sm font-semibold border border-slate-700 bg-slate-800 text-slate-300 hover:text-white hover:border-slate-500';

    document.querySelectorAll('.threat-intel-filter-btn').forEach(btn => {
        const isActive = btn.getAttribute('data-status') === status;
        btn.className = isActive ? activeClasses : inactiveClasses;
        btn.setAttribute('aria-pressed', isActive ? 'true' : 'false');
    });

    if (options.skipReload) {
        return;
    }

    const container = document.getElementById('grouped-vulnerabilities-container');
    if (container) {
        const label = status.charAt(0).toUpperCase() + status.slice(1);
        container.innerHTML = `
            <div class="glass rounded-lg p-6 text-center">
                <p class="text-slate-300">Loading ${label} vulnerabilities...</p>
            </div>
        `;
    }

    loadThreatIntelData();
}

// Load threat intelligence data when tab is shown
async function loadThreatIntelData() {
    try {
        const statusParam = encodeURIComponent(threatIntelStatusFilter || 'open');
        // Load grouped vulnerabilities
        const response = await networkAwareFetch(`/api/vulnerabilities/grouped?status=${statusParam}`);
        if (response.ok) {
            const data = await response.json();
            displayGroupedVulnerabilities(data);
        } else {
            // Fallback to regular vulnerabilities endpoint
            const fallbackResponse = await networkAwareFetch(`/api/vulnerabilities?status=${statusParam}`);
            if (fallbackResponse.ok) {
                const vulnData = await fallbackResponse.json();
                displayFallbackVulnerabilities(vulnData);
            }
        }

    } catch (error) {
        console.error('Error loading vulnerability data:', error);
        const container = document.getElementById('grouped-vulnerabilities-container');
        if (container) {
            container.innerHTML = `
                <div class="glass rounded-lg p-6 text-center">
                    <p class="text-red-400">Error loading vulnerabilities</p>
                    <p class="text-slate-400 text-sm mt-2">${error.message}</p>
                </div>
            `;
        }
    }
}

// Display grouped vulnerabilities by host
function displayGroupedVulnerabilities(data) {
    const container = document.getElementById('grouped-vulnerabilities-container');
    
    // Update summary cards
    const threatIntelVulnerableHosts = document.getElementById('threat-intel-vulnerable-hosts-count');
    if (threatIntelVulnerableHosts) {
        threatIntelVulnerableHosts.textContent = data.total_hosts || 0;
    }
    document.getElementById('total-vulnerabilities-count').textContent = data.total_vulnerabilities || 0;
    
    // Calculate severity totals
    let criticalTotal = 0, highTotal = 0;
    if (data.grouped_vulnerabilities) {
        data.grouped_vulnerabilities.forEach(host => {
            criticalTotal += host.severity_counts.critical || 0;
            highTotal += host.severity_counts.high || 0;
        });
    }
    document.getElementById('critical-vuln-count').textContent = criticalTotal;
    document.getElementById('high-vuln-count').textContent = highTotal;
    
    if (!data.grouped_vulnerabilities || data.grouped_vulnerabilities.length === 0) {
        container.innerHTML = `
            <div class="glass rounded-lg p-6 text-center">
                <svg class="w-16 h-16 mx-auto mb-4 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                </svg>
                <h3 class="text-xl font-semibold text-white mb-2">No Vulnerabilities Found</h3>
                <p class="text-slate-400">All discovered hosts appear to be secure!</p>
            </div>
        `;
        return;
    }
    
    // Build HTML for each host group
    let html = '';
    data.grouped_vulnerabilities.forEach((hostData, index) => {
        const severityCounts = hostData.severity_counts;
        const vulnCount = hostData.total_vulnerabilities;
        
        // Determine risk level color
        let riskColor = 'blue';
        let riskLabel = 'Low Risk';
        if (severityCounts.critical > 0) {
            riskColor = 'red';
            riskLabel = 'Critical Risk';
        } else if (severityCounts.high > 5) {
            riskColor = 'orange';
            riskLabel = 'High Risk';
        } else if (severityCounts.high > 0) {
            riskColor = 'yellow';
            riskLabel = 'Medium Risk';
        }
        
        html += `
            <div class="glass rounded-lg p-6">
                <!-- Host Header -->
                <div class="flex items-center justify-between mb-4 pb-4 border-b border-slate-700">
                    <div class="flex items-center space-x-4">
                        <div class="bg-${riskColor}-500/20 p-3 rounded-lg">
                            <svg class="w-8 h-8 text-${riskColor}-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"></path>
                            </svg>
                        </div>
                        <div>
                            <h3 class="text-2xl font-bold text-white">${hostData.ip}</h3>
                            <p class="text-sm text-slate-400">
                                <span class="bg-${riskColor}-500/20 text-${riskColor}-300 px-2 py-1 rounded text-xs font-semibold">${riskLabel}</span>
                                <span class="ml-2">${vulnCount} Vulnerabilities Found</span>
                            </p>
                        </div>
                    </div>
                    <button onclick="toggleHostDetails('host-${index}')" class="bg-Ragnar-600 hover:bg-Ragnar-700 text-white px-4 py-2 rounded-lg transition-colors">
                        <span id="host-${index}-toggle">Show Details</span>
                    </button>
                </div>
                
                <!-- Quick Stats -->
                <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                    <div class="bg-slate-800/50 rounded-lg p-3">
                        <div class="text-red-400 text-2xl font-bold">${severityCounts.critical || 0}</div>
                        <div class="text-xs text-slate-400">Critical</div>
                    </div>
                    <div class="bg-slate-800/50 rounded-lg p-3">
                        <div class="text-orange-400 text-2xl font-bold">${severityCounts.high || 0}</div>
                        <div class="text-xs text-slate-400">High</div>
                    </div>
                    <div class="bg-slate-800/50 rounded-lg p-3">
                        <div class="text-yellow-400 text-2xl font-bold">${severityCounts.medium || 0}</div>
                        <div class="text-xs text-slate-400">Medium</div>
                    </div>
                    <div class="bg-slate-800/50 rounded-lg p-3">
                        <div class="text-blue-400 text-2xl font-bold">${severityCounts.low || 0}</div>
                        <div class="text-xs text-slate-400">Low</div>
                    </div>
                </div>
                
                <!-- Affected Services -->
                <div class="mb-4">
                    <div class="text-sm text-slate-400 mb-2">Affected Services</div>
                    <div class="flex flex-wrap gap-2">
                        ${hostData.affected_services.map(service => 
                            `<span class="bg-slate-700 px-3 py-1 rounded-full text-sm">${service}</span>`
                        ).join('')}
                    </div>
                    <div class="text-sm text-slate-400 mt-2">
                        Ports: ${hostData.affected_ports.join(', ')}
                    </div>
                </div>
                
                <!-- Detailed Vulnerabilities (Initially Hidden) -->
                <div id="host-${index}-details" class="hidden mt-4">
                    <div class="border-t border-slate-700 pt-4">
                        <h4 class="text-lg font-semibold mb-3 text-white">All Vulnerabilities (${vulnCount})</h4>
                        <div class="space-y-2 max-h-96 overflow-y-auto scrollbar-thin">
                            ${hostData.vulnerabilities.map(vuln => {
                                const severityColors = {
                                    'critical': 'red',
                                    'high': 'orange',
                                    'medium': 'yellow',
                                    'low': 'blue'
                                };
                                const color = severityColors[vuln.severity] || 'gray';
                                const vulnText = vuln.vulnerability.length > 100 ? 
                                    vuln.vulnerability.substring(0, 100) + '...' : 
                                    vuln.vulnerability;
                                
                                return `
                                    <div class="bg-slate-800/30 rounded p-3 hover:bg-slate-800/50 transition-colors">
                                        <div class="flex items-start justify-between">
                                            <div class="flex-1">
                                                <div class="flex items-center space-x-2 mb-1">
                                                    <span class="bg-${color}-500/20 text-${color}-300 px-2 py-0.5 rounded text-xs font-semibold uppercase">${vuln.severity}</span>
                                                    <span class="text-slate-400 text-xs">${vuln.service}:${vuln.port}</span>
                                                </div>
                                                <div class="text-sm text-white font-mono">${vulnText}</div>
                                            </div>
                                            <button onclick='showVulnerabilityDetails(${JSON.stringify(vuln).replace(/'/g, "\\'")})' 
                                                    class="ml-2 text-Ragnar-400 hover:text-Ragnar-300 text-xs">
                                                Details
                                            </button>
                                        </div>
                                    </div>
                                `;
                            }).join('')}
                        </div>
                    </div>
                </div>
            </div>
        `;
    });
    
    container.innerHTML = html;
}

// Toggle host details visibility
function toggleHostDetails(hostId) {
    const detailsDiv = document.getElementById(`${hostId}-details`);
    const toggleBtn = document.getElementById(`${hostId}-toggle`);
    
    if (detailsDiv.classList.contains('hidden')) {
        detailsDiv.classList.remove('hidden');
        toggleBtn.textContent = 'Hide Details';
    } else {
        detailsDiv.classList.add('hidden');
        toggleBtn.textContent = 'Show Details';
    }
}

// Show vulnerability details modal
function showVulnerabilityDetails(vuln) {
    const modal = document.getElementById('vulnerability-detail-modal');
    const content = document.getElementById('vuln-detail-content');
    
    const severityColors = {
        'critical': 'text-red-400',
        'high': 'text-orange-400',
        'medium': 'text-yellow-400',
        'low': 'text-blue-400'
    };
    
    // Extract CVE IDs from vulnerability text and create links
    function formatVulnerabilityWithLinks(vulnText) {
        // Match CVE patterns (CVE-YYYY-NNNNN)
        const cvePattern = /(CVE-\d{4}-\d{4,7})/gi;
        const cves = vulnText.match(cvePattern);
        
        if (!cves || cves.length === 0) {
            return `<div class="text-white font-mono text-sm break-all">${vulnText}</div>`;
        }
        
        // Create links section
        let linksHtml = '<div class="mt-3 pt-3 border-t border-slate-700">';
        linksHtml += '<div class="text-sm text-slate-400 mb-2">CVE References:</div>';
        linksHtml += '<div class="flex flex-wrap gap-2">';
        
        const uniqueCVEs = [...new Set(cves)]; // Remove duplicates
        uniqueCVEs.forEach(cve => {
            const nvdUrl = `https://nvd.nist.gov/vuln/detail/${cve}`;
            const mitreUrl = `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve}`;
            
            linksHtml += `
                <div class="bg-slate-700/50 rounded px-3 py-2 flex items-center space-x-2">
                    <span class="text-Ragnar-400 font-mono text-sm">${cve}</span>
                    <a href="${nvdUrl}" target="_blank" rel="noopener noreferrer" 
                       class="text-blue-400 hover:text-blue-300 transition-colors" 
                       title="View on NIST NVD">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                                  d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path>
                        </svg>
                    </a>
                    <a href="${mitreUrl}" target="_blank" rel="noopener noreferrer" 
                       class="text-green-400 hover:text-green-300 transition-colors" 
                       title="View on MITRE">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                                  d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                        </svg>
                    </a>
                </div>
            `;
        });
        
        linksHtml += '</div></div>';
        
        return `<div class="text-white font-mono text-sm break-all">${vulnText}</div>${linksHtml}`;
    }
    
    content.innerHTML = `
        <div class="space-y-4">
            <div class="bg-slate-800/50 rounded-lg p-4">
                <div class="text-sm text-slate-400 mb-1">Severity</div>
                <div class="${severityColors[vuln.severity]} text-2xl font-bold uppercase">${vuln.severity}</div>
            </div>
            
            <div class="bg-slate-800/50 rounded-lg p-4">
                <div class="text-sm text-slate-400 mb-1">Vulnerability</div>
                ${formatVulnerabilityWithLinks(vuln.vulnerability)}
            </div>
            
            <div class="grid grid-cols-2 gap-4">
                <div class="bg-slate-800/50 rounded-lg p-4">
                    <div class="text-sm text-slate-400 mb-1">Service</div>
                    <div class="text-white">${vuln.service}</div>
                </div>
                <div class="bg-slate-800/50 rounded-lg p-4">
                    <div class="text-sm text-slate-400 mb-1">Port</div>
                    <div class="text-white">${vuln.port}</div>
                </div>
            </div>
            
            <div class="bg-slate-800/50 rounded-lg p-4">
                <div class="text-sm text-slate-400 mb-1">Discovered</div>
                <div class="text-white">${new Date(vuln.discovered).toLocaleString()}</div>
            </div>
            
            <div class="bg-slate-800/50 rounded-lg p-4">
                <div class="text-sm text-slate-400 mb-1">Status</div>
                <div class="text-white capitalize">${vuln.status}</div>
            </div>
        </div>
    `;
    
    modal.classList.remove('hidden');
    modal.classList.add('flex');
}

// Close vulnerability modal
function closeVulnerabilityModal() {
    const modal = document.getElementById('vulnerability-detail-modal');
    modal.classList.add('hidden');
    modal.classList.remove('flex');
}

// Fallback display for regular vulnerabilities
function displayFallbackVulnerabilities(data) {
    // Group vulnerabilities by IP manually if grouped endpoint not available
    const grouped = {};
    if (data.vulnerabilities) {
        data.vulnerabilities.forEach(vuln => {
            if (!grouped[vuln.host]) {
                grouped[vuln.host] = {
                    ip: vuln.host,
                    total_vulnerabilities: 0,
                    severity_counts: { critical: 0, high: 0, medium: 0, low: 0 },
                    affected_ports: new Set(),
                    affected_services: new Set(),
                    vulnerabilities: []
                };
            }
            grouped[vuln.host].total_vulnerabilities++;
            grouped[vuln.host].severity_counts[vuln.severity]++;
            grouped[vuln.host].affected_ports.add(vuln.port);
            grouped[vuln.host].affected_services.add(vuln.service);
            grouped[vuln.host].vulnerabilities.push(vuln);
        });
    }
    
    // Convert to array and format
    const groupedArray = Object.values(grouped).map(host => ({
        ...host,
        affected_ports: Array.from(host.affected_ports),
        affected_services: Array.from(host.affected_services)
    }));
    
    displayGroupedVulnerabilities({
        total_hosts: groupedArray.length,
        total_vulnerabilities: data.vulnerabilities?.length || 0,
        grouped_vulnerabilities: groupedArray
    });
}

// Trigger manual vulnerability scan
async function triggerManualVulnScan() {
    try {
        addConsoleMessage('Starting vulnerability scan on all discovered hosts...', 'info');
        const response = await fetchAPI('/api/threat-intelligence/trigger-vuln-scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                target: 'all'
            })
        });
        
        if (response.action === 'vulnerability_scan_triggered') {
            addConsoleMessage(`✅ ${response.message}`, 'success');
            addConsoleMessage(`📋 Scanning ${response.discovered_hosts} discovered hosts`, 'info');
            
            // Show detailed next steps
            if (response.next_steps) {
                response.next_steps.forEach(step => {
                    addConsoleMessage(`   • ${step}`, 'info');
                });
            }
            
            showNotification(`Vulnerability scan started on ${response.discovered_hosts} hosts. Check back in a few minutes!`, 'success');
            
            // Refresh threat intel data in 30 seconds to check for results
            setTimeout(() => {
                if (currentTab === 'threat-intel') {
                    loadThreatIntelData();
                    addConsoleMessage('🔄 Checking for new threat intelligence findings...', 'info');
                }
            }, 30000);
            
            // And again in 2 minutes
            setTimeout(() => {
                if (currentTab === 'threat-intel') {
                    loadThreatIntelData();
                    addConsoleMessage('🔍 Final check for vulnerability scan results...', 'info');
                }
            }, 120000);
        } else {
            addConsoleMessage('❌ Failed to start vulnerability scan', 'error');
            showNotification('Failed to start vulnerability scan', 'error');
        }
    } catch (error) {
        console.error('Error triggering vulnerability scan:', error);
        addConsoleMessage('❌ Error starting vulnerability scan: ' + error.message, 'error');
        showNotification('Error starting vulnerability scan', 'error');
    }
}

// Refresh threat intelligence data
function refreshThreatIntel() {
    showNotification('Refreshing threat intelligence...', 'info');
    if (currentTab === 'threat-intel') {
        setThreatIntelFilter(threatIntelStatusFilter);
    }
}

// Update threat intelligence statistics
function updateThreatIntelStats(data) {
    // Update summary cards
    document.getElementById('threat-sources-count').textContent = data.active_sources || 0;
    document.getElementById('enriched-findings-count').textContent = data.enriched_findings_count || 0;
    document.getElementById('high-risk-count').textContent = data.high_risk_count || 0;
    document.getElementById('active-campaigns-count').textContent = data.active_campaigns || 0;

    // Update risk distribution
    const riskDistribution = data.risk_distribution || {};
    document.getElementById('critical-risk-count').textContent = riskDistribution.critical || 0;
    document.getElementById('high-risk-detail-count').textContent = riskDistribution.high || 0;
    document.getElementById('medium-risk-count').textContent = riskDistribution.medium || 0;
    document.getElementById('low-risk-count').textContent = riskDistribution.low || 0;

    // Update source status indicators
    const sources = data.source_status || {};
    updateSourceStatus('cisa-status', sources.cisa_kev || false);
    updateSourceStatus('nvd-status', sources.nvd_cve || false);
    updateSourceStatus('otx-status', sources.alienvault_otx || false);
    updateSourceStatus('mitre-status', sources.mitre_attack || false);

    updateTopThreatsList(data.top_threats || [], data.last_update || data.last_intelligence_update || null);
}

// Update source status indicator
function updateSourceStatus(elementId, isActive) {
    const element = document.getElementById(elementId);
    if (element) {
        element.className = `w-3 h-3 rounded-full ${isActive ? 'bg-green-400' : 'bg-red-400'}`;
    }
}

// Update enriched findings table
function updateEnrichedFindingsTable(findings) {
    const tableBody = document.getElementById('enriched-findings-table');

    if (!findings || findings.length === 0) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="6" class="text-center py-12 text-slate-400">
                    <div class="space-y-4">
                        <div class="text-xl">🛡️ No Threat Intelligence Findings</div>
                        <div class="text-sm max-w-md mx-auto space-y-2">
                            <p>Threat intelligence enrichment requires vulnerability discoveries first.</p>
                            <p class="text-cyan-400">📋 Steps to generate threat intelligence:</p>
                            <ol class="text-left text-xs space-y-1 mt-2">
                                <li>1. Wait for network discovery to complete (${document.getElementById('target-count')?.textContent || '0'} hosts found)</li>
                                <li>2. Run vulnerability scans on discovered hosts</li>
                                <li>3. Threat intelligence will enrich discovered vulnerabilities</li>
                            </ol>
                            <div class="mt-4">
                                <button onclick="triggerManualVulnScan()" class="bg-cyan-600 hover:bg-cyan-700 px-4 py-2 rounded text-sm transition-colors">
                                    🚀 Start Vulnerability Scan
                                </button>
                            </div>
                        </div>
                    </div>
                </td>
            </tr>
        `;
        return;
    }

    tableBody.innerHTML = findings.map(finding => `
        <tr class="border-b border-slate-700 hover:bg-slate-700/50">
            <td class="py-3 px-4 text-white font-mono">${escapeHtml(finding.target)}</td>
            <td class="py-3 px-4">
                <span class="px-2 py-1 rounded text-xs font-medium ${getRiskScoreClass(finding.risk_score)}">
                    ${finding.risk_score}/100
                </span>
            </td>
            <td class="py-3 px-4 text-slate-300 max-w-xs truncate" title="${escapeHtml(finding.threat_context || 'N/A')}">
                ${escapeHtml(finding.threat_context || 'N/A')}
            </td>
            <td class="py-3 px-4 text-slate-300">${escapeHtml(finding.attribution || 'Unknown')}</td>
            <td class="py-3 px-4 text-slate-400">${formatTimestamp(finding.last_updated)}</td>
            <td class="py-3 px-4">
                <button onclick="downloadThreatReport('${finding.target}')" 
                        class="text-blue-400 hover:text-blue-300 text-sm">
                    Report
                </button>
            </td>
        </tr>
    `).join('');
}

// Update top threats list
function updateTopThreatsList(threats, lastUpdated) {
    const listElement = document.getElementById('top-threats-list');
    const updatedElement = document.getElementById('top-threats-updated');

    if (!listElement) {
        return;
    }

    if (updatedElement) {
        updatedElement.textContent = `Last updated: ${lastUpdated ? formatTimestamp(lastUpdated) : 'N/A'}`;
    }

    if (!threats || threats.length === 0) {
        listElement.innerHTML = `
            <li class="text-slate-400 text-center py-4">
                <div class="space-y-2">
                    <div>🛡️ No active threats detected</div>
                    <div class="text-xs">Threat intelligence will appear here when vulnerabilities are discovered and enriched</div>
                </div>
            </li>
        `;
        return;
    }

    listElement.innerHTML = threats.slice(0, 5).map(threat => `
        <li class="bg-slate-800/60 rounded-lg p-4 flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
            <div class="space-y-1">
                <p class="text-white font-semibold">${escapeHtml(threat.target || 'Unknown Target')}</p>
                <p class="text-slate-400 text-sm">${escapeHtml(threat.summary || 'No summary available')}</p>
                <div class="text-xs text-slate-500 space-x-3">
                    <span>Last Seen: ${formatTimestamp(threat.last_seen)}</span>
                    ${threat.attribution ? `<span>Attributed to: ${escapeHtml(threat.attribution)}</span>` : ''}
                </div>
            </div>
            <span class="self-start sm:self-center px-2 py-1 rounded text-xs font-semibold ${getRiskScoreClass(threat.risk_score)}">
                ${threat.risk_score}/100
            </span>
        </li>
    `).join('');
}

// Get risk score CSS class
function getRiskScoreClass(score) {
    if (score >= 90) return 'bg-red-600 text-white';
    if (score >= 70) return 'bg-orange-600 text-white';
    if (score >= 50) return 'bg-yellow-600 text-black';
    return 'bg-green-600 text-white';
}

// Manual target enrichment
async function enrichTarget() {
    const targetInput = document.getElementById('enrichment-target');
    const target = targetInput.value.trim();
    
    if (!target) {
        showNotification('Please enter a target (IP, domain, or hash)', 'error');
        return;
    }

    try {
        showNotification(`Enriching target: ${target}...`, 'info');
        
        const response = await networkAwareFetch('/api/threat-intelligence/enrich-target', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ target: target })
        });

        if (response.ok) {
            const result = await response.json();
            showNotification(`Target enriched successfully. Risk score: ${result.risk_score}/100`, 'success');
            targetInput.value = '';
            if (currentTab === 'threat-intel') {
                loadThreatIntelData(); // Refresh the data
            }
        } else {
            const error = await response.json();
            showNotification(`Enrichment failed: ${error.error}`, 'error');
        }
    } catch (error) {
        console.error('Error enriching target:', error);
        showNotification('Error enriching target', 'error');
    }
}

// Download threat intelligence report
async function downloadThreatReport(target) {
    try {
        showNotification(`Analyzing ${target} for threat intelligence...`, 'info');
        
        const response = await networkAwareFetch('/api/threat-intelligence/download-report', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ target: target })
        });

        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            
            // Generate filename with current date
            const now = new Date();
            const dateStr = now.toISOString().slice(0, 19).replace(/:/g, '-');
            a.download = `Threat_Intelligence_Report_${target.replace(/[^a-zA-Z0-9.-]/g, '_')}_${dateStr}.txt`;
            
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            
            showNotification(`Threat intelligence report downloaded for ${target}`, 'success');
        } else {
            const error = await response.json();
            if (error.target_type === 'no_findings') {
                showNotification(`No vulnerability findings detected for ${target} - run network scans first to discover vulnerabilities for threat intelligence enrichment`, 'warning');
            } else {
                showNotification(`Failed to generate report: ${error.error}`, 'error');
            }
        }
    } catch (error) {
        console.error('Error downloading threat report:', error);
        showNotification('Error downloading threat intelligence report', 'error');
    }
}

// Format timestamp for display
function formatTimestamp(timestamp) {
    if (!timestamp) return 'N/A';
    
    try {
        const date = new Date(timestamp);
        return date.toLocaleString();
    } catch (error) {
        return 'Invalid date';
    }
}

// HTML escape utility
function escapeHtml(text) {
    if (typeof text !== 'string') return text;
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Format AI text with proper line breaks and structure
function formatAIText(text) {
    if (!text || typeof text !== 'string') return '';
    
    // Escape HTML to prevent XSS
    const escaped = escapeHtml(text);
    
    // Split into lines for processing
    const lines = escaped.split('\n');
    const output = [];
    let inList = false;
    
    for (let i = 0; i < lines.length; i++) {
        let line = lines[i].trim();
        
        if (!line) {
            // Close any open list
            if (inList) {
                output.push('</ul>');
                inList = false;
            }
            // Add spacing between sections
            output.push('<div class="mb-3"></div>');
            continue;
        }
        
        // Convert **Bold Headers** to styled headers
        if (line.match(/^\*\*(.+?)\*\*:?$/)) {
            if (inList) {
                output.push('</ul>');
                inList = false;
            }
            const headerText = line.replace(/^\*\*(.+?)\*\*:?$/, '$1');
            output.push(`<div class="font-bold text-sky-300 mt-4 mb-2">${headerText}</div>`);
            continue;
        }
        
        // Handle bullet points (-, *, •)
        if (line.match(/^[\-\*\•]\s+(.+)$/)) {
            if (!inList) {
                output.push('<ul class="list-disc list-inside space-y-1 ml-4 text-gray-300">');
                inList = true;
            }
            const content = line.replace(/^[\-\*\•]\s+(.+)$/, '$1');
            output.push(`<li>${content}</li>`);
            continue;
        }
        
        // Handle numbered lists (1., 2., 3. or 1. **Title**)
        if (line.match(/^\d+\.\s+/)) {
            if (!inList) {
                output.push('<ul class="list-decimal list-inside space-y-2 ml-4 text-gray-300">');
                inList = true;
            }
            let content = line.replace(/^\d+\.\s+/, '');
            // Handle bold within numbered items
            content = content.replace(/\*\*(.+?)\*\*/g, '<strong class="text-sky-200">$1</strong>');
            output.push(`<li class="mb-1">${content}</li>`);
            continue;
        }
        
        // Close list if we hit regular text
        if (inList) {
            output.push('</ul>');
            inList = false;
        }
        
        // Handle inline **bold** text in regular paragraphs
        line = line.replace(/\*\*(.+?)\*\*/g, '<strong class="text-sky-200">$1</strong>');
        
        // Regular paragraph
        output.push(`<p class="mb-2 text-gray-300">${line}</p>`);
    }
    
    // Close any unclosed list
    if (inList) {
        output.push('</ul>');
    }
    
    return output.join('');
}

// ============================================================================
// AI INSIGHTS FUNCTIONS
// ============================================================================

// Client-side AI insights cache (1 hour TTL to match server-side cache)
let aiInsightsCache = {
    data: null,
    timestamp: null,
    ttl: 3600000 // 1 hour in milliseconds
};

// Load AI status and insights
async function loadAIInsights() {
    try {
        // Check client-side cache first
        const now = Date.now();
        if (aiInsightsCache.data && aiInsightsCache.timestamp) {
            const age = now - aiInsightsCache.timestamp;
            if (age < aiInsightsCache.ttl) {
                // Use cached data - don't make API call
                console.log(`AI insights cached (${Math.floor(age / 1000)}s old, refreshes in ${Math.floor((aiInsightsCache.ttl - age) / 1000)}s)`);
                displayAIInsights(aiInsightsCache.data);
                return;
            }
        }
        
        // First check AI status
    const statusResponse = await networkAwareFetch('/api/ai/status');
        const status = await statusResponse.json();
        
        const aiSection = document.getElementById('ai-insights-section');
        const aiNotConfigured = document.getElementById('ai-not-configured');
        
        if (!status.enabled || !status.configured) {
            // Show configuration message
            if (aiSection) aiSection.style.display = 'none';
            if (aiNotConfigured) aiNotConfigured.style.display = 'block';
            // Clear cache
            aiInsightsCache.data = null;
            aiInsightsCache.timestamp = null;
            return;
        }
        
        // Show AI insights section
        if (aiSection) aiSection.style.display = 'block';
        if (aiNotConfigured) aiNotConfigured.style.display = 'none';
        
        // Update model name
        const modelName = document.getElementById('ai-model-name');
        if (modelName && status.model) {
            modelName.textContent = status.model;
        }
        
        // Load comprehensive insights
        console.log('Fetching fresh AI insights from server...');
    const insightsResponse = await networkAwareFetch('/api/ai/insights');
        const insights = await insightsResponse.json();
        
        // Cache the insights
        aiInsightsCache.data = insights;
        aiInsightsCache.timestamp = now;
        
        displayAIInsights(insights);
        
    } catch (error) {
        console.error('Error loading AI insights:', error);
        // Silently fail - don't disrupt the dashboard if AI is unavailable
    }
}

// Display AI insights (separated for reuse with cache)
function displayAIInsights(insights) {
    if (insights.enabled) {
        // Update network summary
        const networkSummary = document.getElementById('ai-network-summary');
        if (networkSummary) {
            networkSummary.innerHTML = formatAIText(insights.network_summary || 'Analyzing network...');
        }
        
        // Update vulnerability analysis with summary/details split
        const vulnSection = document.getElementById('ai-vuln-section');
        const vulnSummary = document.getElementById('ai-vuln-summary');
        const vulnDetails = document.getElementById('ai-vuln-details');
        const vulnToggle = document.getElementById('ai-vuln-toggle');
        
        if (vulnSummary && vulnDetails) {
            if (insights.vulnerability_analysis) {
                const { summary, details } = splitAIContent(insights.vulnerability_analysis);
                vulnSummary.innerHTML = formatAIText(summary);
                vulnDetails.innerHTML = formatAIText(details);
                
                // Show toggle button if there are details
                if (vulnToggle && details.trim()) {
                    vulnToggle.style.display = 'flex';
                } else if (vulnToggle) {
                    vulnToggle.style.display = 'none';
                }
                
                if (vulnSection) vulnSection.style.display = 'block';
            } else {
                vulnSummary.textContent = 'No vulnerabilities detected';
                vulnDetails.innerHTML = '';
                if (vulnToggle) vulnToggle.style.display = 'none';
                if (vulnSection) vulnSection.style.display = 'block';
            }
        }
        
        // Update weakness analysis with summary/details split
        const weaknessSection = document.getElementById('ai-weakness-section');
        const weaknessSummary = document.getElementById('ai-weakness-summary');
        const weaknessDetails = document.getElementById('ai-weakness-details');
        const weaknessToggle = document.getElementById('ai-weakness-toggle');
        
        if (weaknessSummary && weaknessDetails) {
            if (insights.weakness_analysis) {
                const { summary, details } = splitAIContent(insights.weakness_analysis);
                weaknessSummary.innerHTML = formatAIText(summary);
                weaknessDetails.innerHTML = formatAIText(details);
                
                // Show toggle button if there are details
                if (weaknessToggle && details.trim()) {
                    weaknessToggle.style.display = 'flex';
                } else if (weaknessToggle) {
                    weaknessToggle.style.display = 'none';
                }
                
                if (weaknessSection) weaknessSection.style.display = 'block';
            } else {
                weaknessSummary.textContent = 'Analyzing network topology...';
                weaknessDetails.innerHTML = '';
                if (weaknessToggle) weaknessToggle.style.display = 'none';
                if (weaknessSection) weaknessSection.style.display = 'block';
            }
        }
        
        // Update last update time
        const lastUpdate = document.getElementById('ai-last-update');
        if (lastUpdate && aiInsightsCache.timestamp) {
            const age = Math.floor((Date.now() - aiInsightsCache.timestamp) / 1000);
            const nextRefresh = Math.floor((aiInsightsCache.ttl - (Date.now() - aiInsightsCache.timestamp)) / 1000);
            if (age < 60) {
                lastUpdate.textContent = `Updated ${age}s ago (next refresh in ${Math.floor(nextRefresh / 60)}m)`;
            } else {
                lastUpdate.textContent = `Updated ${Math.floor(age / 60)}m ago (next refresh in ${Math.floor(nextRefresh / 60)}m)`;
            }
        }
    }
}

// Refresh AI insights (force refresh, clear both client and server cache)
async function refreshAIInsights() {
    try {
        // Clear client-side cache
        aiInsightsCache.data = null;
        aiInsightsCache.timestamp = null;
        
        // Clear server-side cache
    await networkAwareFetch('/api/ai/clear-cache', { method: 'POST' });
        
        // Show loading state
        const networkSummary = document.getElementById('ai-network-summary');
        const vulnSummary = document.getElementById('ai-vuln-summary');
        const weaknessSummary = document.getElementById('ai-weakness-summary');
        
        if (networkSummary) networkSummary.textContent = 'Generating new AI analysis...';
        if (vulnSummary) vulnSummary.textContent = 'Analyzing vulnerabilities...';
        if (weaknessSummary) weaknessSummary.textContent = 'Identifying network weaknesses...';
        
        // Reload insights (will fetch fresh data since cache is cleared)
        await loadAIInsights();
        
        showNotification('AI insights refreshed successfully', 'success');
    } catch (error) {
        console.error('Error refreshing AI insights:', error);
        showNotification('Failed to refresh AI insights', 'error');
    }
}

// Split AI content into summary and details
function splitAIContent(content) {
    if (!content || typeof content !== 'string') {
        return { summary: '', details: '' };
    }
    
    // Split by double newlines or major headers to find logical sections
    const sections = content.split(/\n\n+/);
    
    if (sections.length <= 1) {
        // If no clear sections, just show first 200 chars as summary
        if (content.length <= 200) {
            return { summary: content, details: '' };
        }
        return {
            summary: content.substring(0, 200) + '...',
            details: content
        };
    }
    
    // First section is summary, rest is details
    const summary = sections[0];
    const details = sections.slice(1).join('\n\n');
    
    return { summary, details };
}

// Toggle AI section expansion
function toggleAISection(section) {
    const detailsId = `ai-${section}-details`;
    const toggleTextId = `ai-${section}-toggle-text`;
    const toggleIconId = `ai-${section}-toggle-icon`;
    
    const details = document.getElementById(detailsId);
    const toggleText = document.getElementById(toggleTextId);
    const toggleIcon = document.getElementById(toggleIconId);
    
    if (!details) return;
    
    const isHidden = details.style.display === 'none';
    
    if (isHidden) {
        // Expand
        details.style.display = 'block';
        if (toggleText) toggleText.textContent = 'Show Less';
        if (toggleIcon) toggleIcon.classList.add('rotate-180');
    } else {
        // Collapse
        details.style.display = 'none';
        if (toggleText) toggleText.textContent = 'Show More';
        if (toggleIcon) toggleIcon.classList.remove('rotate-180');
    }
}

// ============================================================================
// SERVER MODE & ADVANCED FEATURES
// ============================================================================

let serverModeEnabled = false;
let trafficCaptureRunning = false;
let trafficRefreshInterval = null;
let advVulnRefreshInterval = null;

// Traffic Analysis Chart Data
let trafficBandwidthHistory = [];
let trafficBandwidthChart = null;
let trafficProtocolChart = null;
const TRAFFIC_HISTORY_SIZE = 60; // 60 seconds of history

// Ragnar's local IPs (to identify self-traffic in UI)
let ragnarLocalIps = new Set(['127.0.0.1', 'localhost']);

/**
 * Check server capabilities and enable advanced features if available
 */
async function checkServerCapabilities() {
    try {
        const response = await fetch('/api/server/capabilities');
        const data = await response.json();
        
        console.log('[ServerMode] Capability check response:', data);
        
        if (data.success && data.features) {
            serverModeEnabled = data.features.server_mode;
            
            // Show/hide server mode features in navigation
            const serverModeElements = document.querySelectorAll('.server-mode-feature');
            console.log(`[ServerMode] Found ${serverModeElements.length} server-mode UI elements`);
            
            serverModeElements.forEach(el => {
                if (serverModeEnabled) {
                    el.classList.remove('hidden');
                } else {
                    el.classList.add('hidden');
                }
            });
            
            if (serverModeEnabled) {
                console.log('[ServerMode] ✅ Server mode enabled - unlocking advanced features');
                console.log('[ServerMode] Capabilities:', data.capabilities);
            } else {
                console.log('[ServerMode] ⚠️ Server mode NOT enabled. Reasons:');
                console.log('[ServerMode]   - Architecture:', data.capabilities?.architecture);
                console.log('[ServerMode]   - RAM:', data.capabilities?.total_ram_gb?.toFixed(2), 'GB (need 7.5GB+)');
                console.log('[ServerMode]   - Cores:', data.capabilities?.cpu_cores, '(need 2+)');
                console.log('[ServerMode]   - Is Pi Zero:', data.capabilities?.is_pi_zero);
                console.log('[ServerMode]   - Full capabilities:', data.capabilities);
            }
            
            return data;
        } else if (!data.success) {
            console.error('[ServerMode] API error:', data.error);
        }
        if (window._updateNavMode) window._updateNavMode();
    } catch (error) {
        console.warn('[ServerMode] Could not check server capabilities:', error);
    }
    return null;
}

// Initialize server mode on page load
document.addEventListener('DOMContentLoaded', function() {
    // Delay server mode check slightly to not block initial load
    setTimeout(() => {
        checkServerCapabilities();
    }, 2000);
});

// ============================================================================
// TRAFFIC ANALYSIS FUNCTIONS
// ============================================================================

async function loadTrafficAnalysisData() {
    try {
        // Fire status and all sub-data calls in parallel for faster load
        const [statusResponse, ...subResults] = await Promise.all([
            fetch('/api/traffic/status'),
            loadTrafficHosts().catch(err => console.warn('Traffic hosts failed:', err)),
            loadTrafficConnections().catch(err => console.warn('Traffic connections failed:', err)),
            loadTrafficAlerts().catch(err => console.warn('Traffic alerts failed:', err)),
            loadTrafficProtocols().catch(err => console.warn('Traffic protocols failed:', err)),
            loadTrafficDnsAnalysis().catch(err => console.warn('Traffic DNS failed:', err)),
            loadTrafficTopTalkers().catch(err => console.warn('Traffic top talkers failed:', err)),
            loadTrafficPortActivity().catch(err => console.warn('Traffic ports failed:', err))
        ]);

        const data = await statusResponse.json();

        if (!data.success || !data.available) {
            showTrafficNotAvailable();
            return;
        }

        hideTrafficNotAvailable();
        updateTrafficSummary(data.summary);
        updateTrafficSecurityMetrics(data.summary);
        updateTrafficBandwidthChart(data.summary);

        // Update capture button state
        trafficCaptureRunning = data.summary?.status === 'running';
        updateTrafficCaptureButton();

    } catch (error) {
        console.error('Error loading traffic analysis:', error);
        showTrafficNotAvailable();
    }
}

function showTrafficNotAvailable() {
    const notice = document.getElementById('traffic-not-available');
    if (notice) notice.classList.remove('hidden');
}

function hideTrafficNotAvailable() {
    const notice = document.getElementById('traffic-not-available');
    if (notice) notice.classList.add('hidden');
}

function updateTrafficSummary(summary) {
    if (!summary) return;

    updateElement('traffic-packets-sec', summary.packets_per_second || 0);
    updateElement('traffic-mbps', (summary.throughput_mbps || summary.mbps || 0).toFixed(2));
    updateElement('traffic-hosts', summary.unique_hosts || summary.active_hosts || 0);
    updateElement('traffic-connections', summary.active_connections || 0);
    updateElement('traffic-alerts', summary.unacknowledged_alerts || summary.total_alerts || summary.alert_count || 0);

    // Extended stats
    updateElement('traffic-packets-total', formatNumber(summary.total_packets || 0) + ' total');
    updateElement('traffic-bytes-total', formatBytes(summary.total_bytes || 0) + ' total');
    updateElement('traffic-dns-queries', (summary.dns_queries_captured || summary.dns_queries_logged || 0) + ' DNS');

    // Store local IPs for UI labeling
    const localIps = summary.excluded_local_ips || summary.local_ips;
    if (localIps && Array.isArray(localIps)) {
        ragnarLocalIps = new Set(localIps);
        console.log('[Traffic] Ragnar local IPs:', Array.from(ragnarLocalIps));
    }
}

/**
 * Update security metrics and risk score
 */
function updateTrafficSecurityMetrics(summary) {
    if (!summary) return;

    // Calculate risk score based on alerts and suspicious activity
    const alertCount = summary.unacknowledged_alerts || summary.total_alerts || summary.alert_count || 0;
    const riskScore = Math.min(100, alertCount * 10);

    // Determine risk level
    let riskColor, riskLabel, riskIcon;
    if (riskScore === 0) {
        riskColor = '#22c55e'; // green
        riskLabel = 'No threats detected';
        riskIcon = 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z';
    } else if (riskScore < 30) {
        riskColor = '#eab308'; // yellow
        riskLabel = 'Low risk activity';
        riskIcon = 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z';
    } else if (riskScore < 60) {
        riskColor = '#f97316'; // orange
        riskLabel = 'Moderate risk detected';
        riskIcon = 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z';
    } else {
        riskColor = '#ef4444'; // red
        riskLabel = 'High risk - investigate';
        riskIcon = 'M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z';
    }

    // Update risk score display
    const scoreEl = document.getElementById('traffic-risk-score');
    const labelEl = document.getElementById('traffic-risk-label');
    const circleEl = document.getElementById('traffic-risk-circle');
    const iconEl = document.getElementById('traffic-risk-icon');
    const cardEl = document.getElementById('traffic-risk-card');

    if (scoreEl) {
        scoreEl.textContent = riskScore;
        scoreEl.style.color = riskColor;
    }
    if (labelEl) labelEl.textContent = riskLabel;
    if (circleEl) {
        circleEl.setAttribute('stroke', riskColor);
        circleEl.setAttribute('stroke-dasharray', `${riskScore}, 100`);
    }
    if (iconEl) {
        iconEl.setAttribute('stroke', riskColor);
        iconEl.querySelector('path').setAttribute('d', riskIcon);
    }
    if (cardEl) cardEl.style.borderColor = riskColor;
}

/**
 * Update bandwidth timeline chart
 */
function updateTrafficBandwidthChart(summary) {
    if (!summary) return;

    // Add current data point
    trafficBandwidthHistory.push({
        timestamp: Date.now(),
        mbps: summary.throughput_mbps || summary.mbps || 0,
        packetsPerSec: summary.packets_per_second || 0
    });

    // Keep only last 60 data points
    while (trafficBandwidthHistory.length > TRAFFIC_HISTORY_SIZE) {
        trafficBandwidthHistory.shift();
    }

    // Draw chart
    const canvas = document.getElementById('traffic-bandwidth-chart');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const width = canvas.parentElement.offsetWidth;
    const height = 128;

    canvas.width = width;
    canvas.height = height;

    // Clear canvas
    ctx.clearRect(0, 0, width, height);

    if (trafficBandwidthHistory.length < 2) return;

    // Find max value for scaling
    const maxMbps = Math.max(...trafficBandwidthHistory.map(d => d.mbps), 0.1);
    const chartMaxEl = document.getElementById('traffic-chart-max');
    if (chartMaxEl) chartMaxEl.textContent = maxMbps.toFixed(2) + ' Mbps';

    // Draw grid lines
    ctx.strokeStyle = 'rgba(100, 116, 139, 0.2)';
    ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
        const y = (height / 4) * i;
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
    }

    // Draw bandwidth line
    const stepX = width / (TRAFFIC_HISTORY_SIZE - 1);

    // Gradient fill
    const gradient = ctx.createLinearGradient(0, 0, 0, height);
    gradient.addColorStop(0, 'rgba(34, 211, 238, 0.3)');
    gradient.addColorStop(1, 'rgba(34, 211, 238, 0)');

    ctx.beginPath();
    ctx.moveTo(0, height);

    trafficBandwidthHistory.forEach((data, index) => {
        const x = index * stepX;
        const y = height - (data.mbps / maxMbps) * (height - 10);
        if (index === 0) {
            ctx.lineTo(x, y);
        } else {
            ctx.lineTo(x, y);
        }
    });

    ctx.lineTo((trafficBandwidthHistory.length - 1) * stepX, height);
    ctx.closePath();
    ctx.fillStyle = gradient;
    ctx.fill();

    // Draw line on top
    ctx.beginPath();
    ctx.strokeStyle = '#22d3ee';
    ctx.lineWidth = 2;

    trafficBandwidthHistory.forEach((data, index) => {
        const x = index * stepX;
        const y = height - (data.mbps / maxMbps) * (height - 10);
        if (index === 0) {
            ctx.moveTo(x, y);
        } else {
            ctx.lineTo(x, y);
        }
    });
    ctx.stroke();

    // Draw current value dot
    if (trafficBandwidthHistory.length > 0) {
        const lastData = trafficBandwidthHistory[trafficBandwidthHistory.length - 1];
        const lastX = (trafficBandwidthHistory.length - 1) * stepX;
        const lastY = height - (lastData.mbps / maxMbps) * (height - 10);

        ctx.beginPath();
        ctx.fillStyle = '#22d3ee';
        ctx.arc(lastX, lastY, 4, 0, Math.PI * 2);
        ctx.fill();
    }
}

/**
 * Format large numbers with K, M, B suffixes
 */
function formatNumber(num) {
    if (num >= 1000000000) return (num / 1000000000).toFixed(1) + 'B';
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
    if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
    return num.toString();
}

async function loadTrafficHosts() {
    try {
        const response = await fetch('/api/traffic/hosts?limit=15&sort=bytes');
        const data = await response.json();

        const container = document.getElementById('traffic-top-hosts');
        if (!container) return;

        if (!data.success || !data.hosts?.length) {
            container.innerHTML = '<p class="text-gray-400 text-center py-8">No host data available</p>';
            updateTrafficDirectionChart(0, 0);
            return;
        }

        // Calculate total inbound/outbound for traffic direction chart
        let totalBytesIn = 0;
        let totalBytesOut = 0;

        data.hosts.forEach(host => {
            totalBytesIn += host.bytes_in || 0;
            totalBytesOut += host.bytes_out || 0;
        });

        // Update traffic direction chart
        updateTrafficDirectionChart(totalBytesIn, totalBytesOut);

        container.innerHTML = data.hosts.map(host => {
            const isLocalIp = ragnarLocalIps.has(host.ip);
            const localBadge = isLocalIp ? '<span class="ml-1 px-1 py-0.5 text-xs bg-purple-600 text-purple-100 rounded">RAGNAR</span>' : '';
            const bgClass = isLocalIp ? 'bg-purple-900 bg-opacity-30 border border-purple-600 border-opacity-30' : 'bg-slate-700 bg-opacity-50 hover:bg-slate-600 hover:bg-opacity-50';
            const portsCount = host.ports_contacted?.length || 0;
            const protocolsCount = Object.keys(host.protocols || {}).length;

            return `
                <div class="flex items-center justify-between p-2 ${bgClass} rounded-lg cursor-pointer transition-colors"
                     onclick="showTrafficHostDetail('${escapeHtml(host.ip)}')" title="Click for details">
                    <div class="flex items-center space-x-3">
                        <div class="w-2 h-2 rounded-full ${host.packets_in > host.packets_out ? 'bg-green-400' : 'bg-blue-400'}"></div>
                        <div>
                            <div class="font-mono text-sm flex items-center">${escapeHtml(host.ip)}${localBadge}</div>
                            <div class="text-xs text-gray-400">
                                ${formatBytes(host.total_bytes)} | ${portsCount} ports | ${protocolsCount} protocols
                            </div>
                        </div>
                    </div>
                    <div class="text-right flex items-center gap-2">
                        <div>
                            <div class="text-xs text-green-400">↓ ${formatBytes(host.bytes_in)}</div>
                            <div class="text-xs text-blue-400">↑ ${formatBytes(host.bytes_out)}</div>
                        </div>
                        <svg class="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
                        </svg>
                    </div>
                </div>
            `;
        }).join('');

    } catch (error) {
        console.error('Error loading traffic hosts:', error);
    }
}

/**
 * Update the traffic direction mini chart
 */
function updateTrafficDirectionChart(bytesIn, bytesOut) {
    const total = bytesIn + bytesOut;
    let inPercent = 50;
    let outPercent = 50;

    if (total > 0) {
        inPercent = Math.round((bytesIn / total) * 100);
        outPercent = 100 - inPercent;
    }

    // Update the bar widths
    const inBar = document.getElementById('traffic-direction-in');
    const outBar = document.getElementById('traffic-direction-out');
    const inPercentEl = document.getElementById('traffic-in-percent');
    const outPercentEl = document.getElementById('traffic-out-percent');

    if (inBar) inBar.style.width = `${inPercent}%`;
    if (outBar) outBar.style.width = `${outPercent}%`;
    if (inPercentEl) inPercentEl.textContent = inPercent;
    if (outPercentEl) outPercentEl.textContent = outPercent;
}

async function loadTrafficConnections() {
    try {
        const response = await fetch('/api/traffic/connections?limit=20');
        const data = await response.json();
        
        const container = document.getElementById('traffic-connections-list');
        if (!container) return;
        
        if (!data.success || !data.connections?.length) {
            container.innerHTML = '<p class="text-gray-400 text-center py-8">No active connections</p>';
            return;
        }
        
        container.innerHTML = data.connections.map((conn, index) => {
            const duration = conn.duration_seconds ? formatDuration(conn.duration_seconds) : 'N/A';
            const connData = encodeURIComponent(JSON.stringify(conn));
            return `
                <div class="p-2 bg-slate-700 bg-opacity-50 hover:bg-slate-600 hover:bg-opacity-50 rounded-lg text-xs font-mono cursor-pointer transition-colors"
                     onclick="showTrafficConnectionDetail(decodeURIComponent('${connData}'))" title="Click for details">
                    <div class="flex items-center justify-between">
                        <span class="text-cyan-400">${escapeHtml(conn.src_ip)}:${conn.src_port}</span>
                        <span class="text-gray-500 mx-1">→</span>
                        <span class="text-green-400">${escapeHtml(conn.dst_ip)}:${conn.dst_port}</span>
                        <svg class="w-3 h-3 text-gray-500 ml-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
                        </svg>
                    </div>
                    <div class="text-gray-400 mt-1 flex justify-between">
                        <span>${conn.protocol.toUpperCase()} | ${conn.packets_sent} pkts | ${formatBytes(conn.bytes_sent)}</span>
                        <span class="text-gray-500">${duration}</span>
                    </div>
                </div>
            `;
        }).join('');
        
    } catch (error) {
        console.error('Error loading traffic connections:', error);
    }
}

async function loadTrafficAlerts() {
    try {
        const response = await fetch('/api/traffic/alerts?limit=20');
        const data = await response.json();

        const container = document.getElementById('traffic-alerts-list');
        if (!container) return;

        if (!data.success || !data.alerts?.length) {
            container.innerHTML = '<p class="text-gray-400 text-center py-8">No alerts - network appears clean</p>';
            return;
        }

        // Count alerts by category for threat indicators
        const alertCategories = {};
        data.alerts.forEach(alert => {
            alertCategories[alert.category] = (alertCategories[alert.category] || 0) + 1;
        });

        container.innerHTML = data.alerts.map(alert => {
            const levelColors = {
                'critical': 'border-red-600 bg-red-900',
                'high': 'border-orange-500 bg-orange-900',
                'medium': 'border-yellow-500 bg-yellow-900',
                'low': 'border-blue-500 bg-blue-900',
                'info': 'border-gray-500 bg-gray-800'
            };
            const levelBadges = {
                'critical': 'bg-red-600 text-white',
                'high': 'bg-orange-600 text-white',
                'medium': 'bg-yellow-600 text-black',
                'low': 'bg-blue-600 text-white',
                'info': 'bg-gray-600 text-white'
            };
            const colorClass = levelColors[alert.level] || levelColors.info;
            const badgeClass = levelBadges[alert.level] || levelBadges.info;

            // Format timestamp
            const timestamp = alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : '';

            return `
                <div class="p-2 ${colorClass} bg-opacity-30 border-l-4 rounded-lg hover:bg-opacity-50 transition-colors">
                    <div class="flex items-center justify-between mb-1">
                        <div class="flex items-center space-x-2">
                            <span class="px-1.5 py-0.5 ${badgeClass} text-xs rounded uppercase font-semibold">${alert.level}</span>
                            <span class="font-medium text-sm">${escapeHtml(formatAlertCategory(alert.category))}</span>
                        </div>
                        <span class="text-xs text-gray-500">${timestamp}</span>
                    </div>
                    <div class="text-xs text-gray-300">${escapeHtml(alert.message)}</div>
                    ${alert.src_ip ? `
                        <div class="text-xs text-gray-400 mt-1 font-mono flex items-center justify-between">
                            <span>Source: ${escapeHtml(alert.src_ip)}${alert.dst_ip ? ' → ' + escapeHtml(alert.dst_ip) : ''}</span>
                            <button onclick="event.stopPropagation(); showTrafficHostDetail('${escapeHtml(alert.src_ip)}')"
                                    class="px-2 py-0.5 bg-slate-600 hover:bg-slate-500 text-gray-200 rounded text-xs transition-colors"
                                    title="View source host details">
                                Investigate
                            </button>
                        </div>
                    ` : ''}
                    ${alert.details ? `<div class="text-xs text-gray-500 mt-1">${formatAlertDetails(alert.details)}</div>` : ''}
                </div>
            `;
        }).join('');

    } catch (error) {
        console.error('Error loading traffic alerts:', error);
    }
}

/**
 * Format alert category for display
 */
function formatAlertCategory(category) {
    const categoryLabels = {
        'suspicious_port': 'Suspicious Port',
        'port_scan': 'Port Scan Detected',
        'c2_beacon': 'C2 Beacon Pattern',
        'dns_tunnel': 'DNS Tunneling Suspect',
        'high_traffic': 'High Traffic Volume',
        'unknown_protocol': 'Unknown Protocol'
    };
    return categoryLabels[category] || category.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

/**
 * Format alert details for display
 */
function formatAlertDetails(details) {
    if (!details || typeof details !== 'object') return '';
    return Object.entries(details)
        .map(([key, value]) => `${key.replace(/_/g, ' ')}: ${value}`)
        .join(' | ');
}

async function loadTrafficProtocols() {
    try {
        const response = await fetch('/api/traffic/summary');
        const data = await response.json();

        const container = document.getElementById('traffic-protocols');
        const totalEl = document.getElementById('traffic-protocol-total');
        if (!container) return;

        if (!data.success || !data.protocols || Object.keys(data.protocols).length === 0) {
            container.innerHTML = '<p class="text-gray-400 text-center py-4 text-xs">No protocol data</p>';
            drawProtocolDonutChart({});
            return;
        }

        const protocols = data.protocols;
        const total = Object.values(protocols).reduce((a, b) => a + b, 0);

        if (totalEl) totalEl.textContent = formatNumber(total);

        // Protocol colors
        const protoColors = {
            'tcp': '#22d3ee',    // cyan
            'udp': '#a855f7',    // purple
            'icmp': '#f97316',   // orange
            'ip': '#3b82f6',     // blue
            'arp': '#eab308',    // yellow
            'other': '#6b7280'   // gray
        };

        // Draw donut chart
        drawProtocolDonutChart(protocols, protoColors);

        // Update list
        container.innerHTML = Object.entries(protocols)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 6)
            .map(([proto, count]) => {
                const percent = total > 0 ? (count / total * 100).toFixed(1) : 0;
                const color = protoColors[proto.toLowerCase()] || protoColors.other;
                return `
                    <div class="flex items-center justify-between text-xs">
                        <div class="flex items-center space-x-2">
                            <span class="w-2 h-2 rounded-full" style="background-color: ${color}"></span>
                            <span class="uppercase font-mono text-gray-300">${escapeHtml(proto)}</span>
                        </div>
                        <span class="text-gray-400">${percent}%</span>
                    </div>
                `;
            }).join('');

    } catch (error) {
        console.error('Error loading traffic protocols:', error);
    }
}

/**
 * Draw protocol distribution donut chart
 */
function drawProtocolDonutChart(protocols, colors = {}) {
    const canvas = document.getElementById('traffic-protocol-chart');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const width = 128;
    const height = 128;
    const centerX = width / 2;
    const centerY = height / 2;
    const outerRadius = 55;
    const innerRadius = 35;

    ctx.clearRect(0, 0, width, height);

    const entries = Object.entries(protocols).sort((a, b) => b[1] - a[1]);
    const total = Object.values(protocols).reduce((a, b) => a + b, 0);

    if (total === 0) {
        // Draw empty ring
        ctx.beginPath();
        ctx.arc(centerX, centerY, outerRadius, 0, Math.PI * 2);
        ctx.arc(centerX, centerY, innerRadius, 0, Math.PI * 2, true);
        ctx.fillStyle = 'rgba(100, 116, 139, 0.3)';
        ctx.fill();
        return;
    }

    const defaultColors = ['#22d3ee', '#a855f7', '#f97316', '#3b82f6', '#eab308', '#6b7280'];
    let startAngle = -Math.PI / 2;

    entries.forEach(([proto, count], index) => {
        const sliceAngle = (count / total) * Math.PI * 2;
        const color = colors[proto.toLowerCase()] || defaultColors[index % defaultColors.length];

        ctx.beginPath();
        ctx.moveTo(centerX, centerY);
        ctx.arc(centerX, centerY, outerRadius, startAngle, startAngle + sliceAngle);
        ctx.closePath();
        ctx.fillStyle = color;
        ctx.fill();

        startAngle += sliceAngle;
    });

    // Draw inner circle (donut hole)
    ctx.beginPath();
    ctx.arc(centerX, centerY, innerRadius, 0, Math.PI * 2);
    ctx.fillStyle = '#1e293b';
    ctx.fill();
}

/**
 * Load DNS query analysis data
 */
async function loadTrafficDnsAnalysis() {
    try {
        const response = await fetch('/api/traffic/summary');
        const data = await response.json();

        const listContainer = document.getElementById('traffic-dns-list');
        const totalEl = document.getElementById('traffic-dns-total');
        const uniqueEl = document.getElementById('traffic-dns-unique');
        const suspiciousEl = document.getElementById('traffic-dns-suspicious');

        if (!data.success) {
            if (listContainer) listContainer.innerHTML = '<p class="text-gray-400 text-center py-4">No DNS data</p>';
            return;
        }

        // Update stats - dns count is inside summary object
        const summary = data.summary || {};
        const dnsCount = summary.dns_queries_captured || summary.dns_queries_logged || data.dns_queries_logged || 0;
        if (totalEl) totalEl.textContent = dnsCount;

        // Try to get DNS details from hosts
        const hostsResponse = await fetch('/api/traffic/hosts?limit=50&sort=bytes');
        const hostsData = await hostsResponse.json();

        if (!hostsData.success || !hostsData.hosts) {
            if (listContainer) listContainer.innerHTML = '<p class="text-gray-400 text-center py-4">No DNS queries logged</p>';
            return;
        }

        // Collect all DNS queries from hosts
        const allDnsQueries = [];
        const uniqueDomains = new Set();
        let suspiciousCount = 0;

        hostsData.hosts.forEach(host => {
            if (host.dns_queries && host.dns_queries.length > 0) {
                host.dns_queries.forEach(query => {
                    allDnsQueries.push({ ip: host.ip, query: query });
                    // Extract domain from query if possible
                    const domainMatch = query.match(/([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}/);
                    if (domainMatch) {
                        uniqueDomains.add(domainMatch[0].toLowerCase());
                        // Check for suspicious patterns (long subdomains, hex-like, high entropy)
                        if (domainMatch[0].length > 50 || /^[a-f0-9]{16,}\./.test(domainMatch[0].toLowerCase())) {
                            suspiciousCount++;
                        }
                    }
                });
            }
        });

        if (uniqueEl) uniqueEl.textContent = uniqueDomains.size;
        if (suspiciousEl) suspiciousEl.textContent = suspiciousCount;

        // Update threat indicators
        updateElement('traffic-threat-c2', suspiciousCount > 0 ? suspiciousCount : 0);

        if (allDnsQueries.length === 0) {
            if (listContainer) listContainer.innerHTML = '<p class="text-gray-400 text-center py-4">No DNS queries logged</p>';
            return;
        }

        // Display recent DNS queries
        if (listContainer) {
            listContainer.innerHTML = allDnsQueries.slice(-20).reverse().map(item => {
                const isSuspicious = item.query.length > 100 || /[a-f0-9]{16,}/.test(item.query);
                return `
                    <div class="flex items-center justify-between p-1 ${isSuspicious ? 'bg-red-900 bg-opacity-20 border-l-2 border-red-500' : 'bg-slate-700 bg-opacity-30'} rounded hover:bg-slate-600 hover:bg-opacity-50 transition-colors cursor-pointer" onclick="showTrafficHostDetail('${escapeHtml(item.ip)}')" title="Click to view host details">
                        <span class="text-gray-300 truncate flex-1" title="${escapeHtml(item.query)}">${escapeHtml(item.query.substring(0, 60))}${item.query.length > 60 ? '...' : ''}</span>
                        <span class="text-cyan-400 ml-2 font-mono hover:underline">${escapeHtml(item.ip)}</span>
                    </div>
                `;
            }).join('');
        }

    } catch (error) {
        console.error('Error loading DNS analysis:', error);
    }
}

/**
 * Load top talkers / connection matrix
 */
async function loadTrafficTopTalkers() {
    try {
        const response = await fetch('/api/traffic/connections?limit=50');
        const data = await response.json();

        const container = document.getElementById('traffic-top-talkers');
        if (!container) return;

        if (!data.success || !data.connections?.length) {
            container.innerHTML = '<p class="text-gray-400 text-center py-4">No connection data</p>';
            return;
        }

        // Aggregate connections by src-dst pair
        const pairs = {};
        data.connections.forEach(conn => {
            const key = `${conn.src_ip}→${conn.dst_ip}`;
            if (!pairs[key]) {
                pairs[key] = {
                    src: conn.src_ip,
                    dst: conn.dst_ip,
                    bytes: 0,
                    packets: 0,
                    connections: 0,
                    protocols: new Set()
                };
            }
            pairs[key].bytes += conn.bytes_sent || 0;
            pairs[key].packets += conn.packets_sent || 0;
            pairs[key].connections++;
            pairs[key].protocols.add(conn.protocol);
        });

        // Sort by bytes
        const sortedPairs = Object.values(pairs).sort((a, b) => b.bytes - a.bytes).slice(0, 10);
        const maxBytes = sortedPairs[0]?.bytes || 1;

        container.innerHTML = sortedPairs.map(pair => {
            const percent = (pair.bytes / maxBytes) * 100;
            const protocols = Array.from(pair.protocols).join(', ').toUpperCase();
            return `
                <div class="relative p-2 bg-slate-700 bg-opacity-30 rounded overflow-hidden hover:bg-slate-600 hover:bg-opacity-40 transition-colors">
                    <div class="absolute inset-0 bg-gradient-to-r from-cyan-600 to-transparent opacity-20" style="width: ${percent}%"></div>
                    <div class="relative flex items-center justify-between">
                        <div class="flex-1 min-w-0">
                            <div class="flex items-center space-x-2 text-xs">
                                <span class="text-cyan-400 font-mono truncate cursor-pointer hover:underline" onclick="showTrafficHostDetail('${escapeHtml(pair.src)}')" title="View source host details">${escapeHtml(pair.src)}</span>
                                <span class="text-gray-500">→</span>
                                <span class="text-green-400 font-mono truncate cursor-pointer hover:underline" onclick="showTrafficHostDetail('${escapeHtml(pair.dst)}')" title="View destination host details">${escapeHtml(pair.dst)}</span>
                            </div>
                            <div class="text-xs text-gray-500 mt-1">
                                ${protocols} | ${pair.connections} conn | ${pair.packets} pkts
                            </div>
                        </div>
                        <div class="text-right text-xs ml-2">
                            <div class="text-white font-semibold">${formatBytes(pair.bytes)}</div>
                        </div>
                    </div>
                </div>
            `;
        }).join('');

    } catch (error) {
        console.error('Error loading top talkers:', error);
    }
}

/**
 * Load port activity analysis
 */
/**
 * Suspicious port definitions with security context
 */
const SUSPICIOUS_PORT_INFO = {
    4444: { name: 'Metasploit Default', reason: 'Default Metasploit reverse shell listener port', severity: 'critical', category: 'Exploit Framework' },
    5555: { name: 'Android ADB', reason: 'Android Debug Bridge - often exploited for unauthorized device access', severity: 'high', category: 'Remote Access' },
    6666: { name: 'IRC/Backdoor', reason: 'Commonly used by IRC botnets and backdoor trojans', severity: 'high', category: 'Botnet/C2' },
    1234: { name: 'Common Backdoor', reason: 'Frequently used by malware for reverse shells', severity: 'medium', category: 'Backdoor' },
    31337: { name: 'Elite/Back Orifice', reason: 'Historic "elite" port used by Back Orifice and many trojans', severity: 'critical', category: 'Trojan' },
    12345: { name: 'NetBus Trojan', reason: 'Default port for NetBus remote administration trojan', severity: 'critical', category: 'Trojan' },
    65535: { name: 'Max Port Backdoor', reason: 'Maximum port number - often used by malware to avoid detection', severity: 'medium', category: 'Evasion' },
    1337: { name: 'Leet Port', reason: 'Common hacker culture port used by various malware', severity: 'medium', category: 'Backdoor' },
    9001: { name: 'Tor/Hidden Service', reason: 'Default Tor ORPort - may indicate anonymization or C2', severity: 'medium', category: 'Anonymization' },
    6667: { name: 'IRC Default', reason: 'IRC server port - commonly used for botnet C2 communication', severity: 'high', category: 'Botnet/C2' },
    6697: { name: 'IRC SSL', reason: 'IRC over SSL - used by botnets for encrypted C2', severity: 'high', category: 'Botnet/C2' },
    8080: { name: 'Alt HTTP/Proxy', reason: 'Alternative HTTP port - check for unauthorized web services', severity: 'low', category: 'Web Service' },
    3128: { name: 'Squid Proxy', reason: 'Default Squid proxy port - may indicate data exfiltration', severity: 'medium', category: 'Proxy' },
    1080: { name: 'SOCKS Proxy', reason: 'SOCKS proxy port - often used for tunneling and evasion', severity: 'medium', category: 'Proxy' },
    7777: { name: 'Game/Backdoor', reason: 'Used by various trojans and game servers', severity: 'medium', category: 'Backdoor' },
    5900: { name: 'VNC', reason: 'VNC remote desktop - verify if authorized', severity: 'medium', category: 'Remote Access' },
    5901: { name: 'VNC Display 1', reason: 'VNC remote desktop display 1', severity: 'medium', category: 'Remote Access' },
    27374: { name: 'Sub7 Trojan', reason: 'Default port for Sub7 remote access trojan', severity: 'critical', category: 'Trojan' },
    20: { name: 'FTP Data', reason: 'FTP data transfer - unencrypted, credentials may leak', severity: 'low', category: 'Legacy Protocol' },
    23: { name: 'Telnet', reason: 'Unencrypted remote access - credentials sent in plaintext', severity: 'high', category: 'Legacy Protocol' },
    69: { name: 'TFTP', reason: 'Trivial FTP - no authentication, often used in attacks', severity: 'medium', category: 'Legacy Protocol' },
    111: { name: 'RPCBind', reason: 'RPC portmapper - can expose internal services', severity: 'medium', category: 'Service Exposure' },
    135: { name: 'MS-RPC', reason: 'Microsoft RPC endpoint mapper - common attack vector', severity: 'medium', category: 'Windows Service' },
    137: { name: 'NetBIOS-NS', reason: 'NetBIOS Name Service - information disclosure risk', severity: 'low', category: 'Windows Service' },
    138: { name: 'NetBIOS-DGM', reason: 'NetBIOS Datagram - legacy Windows networking', severity: 'low', category: 'Windows Service' },
    139: { name: 'NetBIOS-SSN', reason: 'NetBIOS Session - SMB over NetBIOS', severity: 'medium', category: 'Windows Service' },
    445: { name: 'SMB', reason: 'Server Message Block - common ransomware propagation vector', severity: 'high', category: 'Windows Service' },
    512: { name: 'rexec', reason: 'Remote execution - no encryption, easily exploited', severity: 'high', category: 'Legacy Protocol' },
    513: { name: 'rlogin', reason: 'Remote login - no encryption, trust-based auth', severity: 'high', category: 'Legacy Protocol' },
    514: { name: 'rsh/syslog', reason: 'Remote shell or syslog - no encryption', severity: 'high', category: 'Legacy Protocol' },
    2049: { name: 'NFS', reason: 'Network File System - verify authorization', severity: 'medium', category: 'File Sharing' }
};

async function loadTrafficPortActivity() {
    try {
        const response = await fetch('/api/traffic/hosts?limit=100&sort=bytes');
        const data = await response.json();

        if (!data.success || !data.hosts) return;

        // Aggregate port activity with host tracking
        const portCounts = {};
        const portHosts = {}; // Track which hosts contacted each port
        const suspiciousPortsSet = new Set(Object.keys(SUSPICIOUS_PORT_INFO).map(p => parseInt(p)));
        const detectedSuspiciousPorts = {}; // port -> {count, hosts, info}
        let portScanCount = 0;

        data.hosts.forEach(host => {
            if (host.ports_contacted) {
                host.ports_contacted.forEach(port => {
                    portCounts[port] = (portCounts[port] || 0) + 1;

                    // Track hosts per port
                    if (!portHosts[port]) portHosts[port] = new Set();
                    portHosts[port].add(host.ip);

                    // Track suspicious ports with details
                    if (suspiciousPortsSet.has(port)) {
                        if (!detectedSuspiciousPorts[port]) {
                            detectedSuspiciousPorts[port] = {
                                count: 0,
                                hosts: new Set(),
                                info: SUSPICIOUS_PORT_INFO[port]
                            };
                        }
                        detectedSuspiciousPorts[port].count++;
                        detectedSuspiciousPorts[port].hosts.add(host.ip);
                    }
                });

                // Check for port scan behavior (many ports from single host)
                if (host.ports_contacted.length > 50) {
                    portScanCount++;
                }
            }
        });

        const suspiciousCount = Object.keys(detectedSuspiciousPorts).length;

        // Update common port counts
        updateElement('port-80-count', portCounts[80] || 0);
        updateElement('port-443-count', portCounts[443] || 0);
        updateElement('port-53-count', portCounts[53] || 0);
        updateElement('port-22-count', portCounts[22] || 0);
        updateElement('port-3389-count', portCounts[3389] || 0);
        updateElement('port-suspicious-count', suspiciousCount);

        // Update threat indicators
        updateElement('traffic-threat-port-scans', portScanCount);
        updateElement('traffic-threat-suspicious', suspiciousCount);

        // Update unique ports count
        updateElement('traffic-unique-ports', Object.keys(portCounts).length + ' ports');

        // Display suspicious ports detail section
        const suspiciousSection = document.getElementById('suspicious-ports-section');
        const suspiciousList = document.getElementById('suspicious-ports-list');

        if (suspiciousSection && suspiciousList) {
            if (suspiciousCount > 0) {
                suspiciousSection.style.display = 'block';

                // Sort by severity (critical > high > medium > low)
                const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
                const sortedSuspicious = Object.entries(detectedSuspiciousPorts)
                    .sort((a, b) => severityOrder[a[1].info.severity] - severityOrder[b[1].info.severity]);

                suspiciousList.innerHTML = sortedSuspicious.map(([port, data]) => {
                    const info = data.info;
                    const hosts = Array.from(data.hosts).slice(0, 3);
                    const moreHosts = data.hosts.size > 3 ? ` +${data.hosts.size - 3} more` : '';

                    const severityColors = {
                        critical: 'bg-red-600 text-white',
                        high: 'bg-orange-600 text-white',
                        medium: 'bg-yellow-600 text-black',
                        low: 'bg-blue-600 text-white'
                    };
                    const severityClass = severityColors[info.severity] || severityColors.medium;

                    // Make hosts clickable
                    const clickableHosts = hosts.map(h => `<span class="cursor-pointer hover:underline" onclick="event.stopPropagation(); showTrafficHostDetail('${escapeHtml(h)}')">${escapeHtml(h)}</span>`).join(', ');

                    return `
                        <div class="p-2 bg-slate-800 bg-opacity-50 rounded border-l-4 ${info.severity === 'critical' ? 'border-red-500' : info.severity === 'high' ? 'border-orange-500' : info.severity === 'medium' ? 'border-yellow-500' : 'border-blue-500'} hover:bg-slate-700 hover:bg-opacity-50 transition-colors">
                            <div class="flex items-center justify-between mb-1">
                                <div class="flex items-center space-x-2">
                                    <span class="font-mono font-bold text-red-400 cursor-pointer hover:underline" onclick="showTrafficPortDetail(${port})" title="View port details">${port}</span>
                                    <span class="text-xs px-1.5 py-0.5 ${severityClass} rounded uppercase font-semibold">${info.severity}</span>
                                    <span class="text-xs text-gray-400">${escapeHtml(info.name)}</span>
                                </div>
                                <span class="text-xs px-2 py-0.5 bg-slate-700 rounded text-gray-300">${escapeHtml(info.category)}</span>
                            </div>
                            <div class="text-xs text-gray-400 mb-1">${escapeHtml(info.reason)}</div>
                            <div class="text-xs text-gray-500">
                                <span class="text-yellow-400">${data.count}</span> connections from
                                <span class="font-mono text-cyan-400">${clickableHosts}${moreHosts}</span>
                            </div>
                        </div>
                    `;
                }).join('');
            } else {
                suspiciousSection.style.display = 'none';
                suspiciousList.innerHTML = '';
            }
        }

        // Display all active ports
        const allPortsContainer = document.getElementById('traffic-all-ports');
        if (allPortsContainer) {
            const sortedPorts = Object.entries(portCounts)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 50);

            if (sortedPorts.length === 0) {
                allPortsContainer.innerHTML = '<span class="text-xs text-gray-500 px-2 py-1 bg-slate-700 rounded">No port data</span>';
            } else {
                allPortsContainer.innerHTML = sortedPorts.map(([port, count]) => {
                    const portNum = parseInt(port);
                    const isSuspicious = suspiciousPortsSet.has(portNum);
                    const isCommon = [80, 443, 22, 53, 25, 21, 3389, 8443].includes(portNum);
                    let colorClass = 'bg-slate-600 text-gray-300 hover:bg-slate-500';
                    let tooltip = `${count} connections - Click for details`;

                    if (isSuspicious) {
                        colorClass = 'bg-red-900 text-red-400 border border-red-600 hover:bg-red-800';
                        const info = SUSPICIOUS_PORT_INFO[portNum];
                        tooltip = `${info.name}: ${info.reason} (${count} connections) - Click for details`;
                    } else if (isCommon) {
                        colorClass = 'bg-cyan-900 text-cyan-400 hover:bg-cyan-800';
                    }

                    return `<span class="text-xs px-2 py-1 ${colorClass} rounded font-mono cursor-pointer transition-colors" title="${escapeHtml(tooltip)}" onclick="showTrafficPortDetail(${port})">${port}</span>`;
                }).join('');
            }
        }

    } catch (error) {
        console.error('Error loading port activity:', error);
    }
}

async function toggleTrafficCapture() {
    try {
        const endpoint = trafficCaptureRunning ? '/api/traffic/stop' : '/api/traffic/start';
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        });
        const data = await response.json();
        
        if (data.success) {
            trafficCaptureRunning = !trafficCaptureRunning;
            updateTrafficCaptureButton();
            
            if (trafficCaptureRunning) {
                // Start refresh interval
                trafficRefreshInterval = setInterval(refreshTrafficData, 3000);
                showNotification('Traffic capture started', 'success');
            } else {
                // Stop refresh interval
                if (trafficRefreshInterval) {
                    clearInterval(trafficRefreshInterval);
                    trafficRefreshInterval = null;
                }
                showNotification('Traffic capture stopped', 'info');
            }
        } else {
            showNotification(data.error || 'Failed to toggle capture', 'error');
        }
    } catch (error) {
        console.error('Error toggling traffic capture:', error);
        showNotification('Failed to toggle traffic capture', 'error');
    }
}

function updateTrafficCaptureButton() {
    const btn = document.getElementById('traffic-toggle-btn');
    if (!btn) return;
    
    if (trafficCaptureRunning) {
        btn.innerHTML = `
            <svg class="w-4 h-4 inline mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 10a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1h-4a1 1 0 01-1-1v-4z"></path>
            </svg>
            Stop Capture
        `;
        btn.classList.remove('bg-green-600', 'hover:bg-green-700');
        btn.classList.add('bg-red-600', 'hover:bg-red-700');
    } else {
        btn.innerHTML = `
            <svg class="w-4 h-4 inline mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"></path>
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
            </svg>
            Start Capture
        `;
        btn.classList.remove('bg-red-600', 'hover:bg-red-700');
        btn.classList.add('bg-green-600', 'hover:bg-green-700');
    }
}

async function refreshTrafficData() {
    if (currentTab !== 'traffic') return;
    await loadTrafficAnalysisData();
}

/**
 * Show traffic host detail modal
 */
async function showTrafficHostDetail(ip) {
    const modal = document.getElementById('traffic-host-modal');
    const ipTitle = document.getElementById('traffic-host-modal-ip');
    const content = document.getElementById('traffic-host-modal-content');

    if (!modal || !content) return;

    ipTitle.textContent = ip;
    content.innerHTML = '<div class="text-center py-8"><div class="animate-spin w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full mx-auto"></div><p class="text-gray-400 mt-2">Loading host details...</p></div>';

    modal.classList.remove('hidden');
    modal.classList.add('flex');

    try {
        const response = await fetch(`/api/traffic/host/${encodeURIComponent(ip)}`);
        const data = await response.json();

        if (!data.success || !data.host) {
            content.innerHTML = '<p class="text-red-400 text-center py-8">Failed to load host details</p>';
            return;
        }

        const host = data.host;
        const isLocal = ragnarLocalIps.has(host.ip);
        const protocols = Object.entries(host.protocols || {});
        const ports = host.ports_contacted || [];
        const dnsQueries = host.dns_queries || [];

        // Format timestamps
        const firstSeen = host.first_seen ? new Date(host.first_seen).toLocaleString() : 'N/A';
        const lastSeen = host.last_seen ? new Date(host.last_seen).toLocaleString() : 'N/A';

        // Get service names for common ports
        const getServiceName = (port) => {
            const services = {
                21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP',
                80: 'HTTP', 110: 'POP3', 123: 'NTP', 135: 'RPC', 137: 'NetBIOS', 138: 'NetBIOS',
                139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP', 162: 'SNMP', 389: 'LDAP', 443: 'HTTPS',
                445: 'SMB', 465: 'SMTPS', 514: 'Syslog', 587: 'SMTP', 631: 'IPP', 636: 'LDAPS',
                993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle', 1883: 'MQTT',
                1900: 'UPnP', 2049: 'NFS', 2181: 'ZooKeeper', 2375: 'Docker', 3005: 'Services',
                3306: 'MySQL', 3389: 'RDP', 5000: 'Services', 5060: 'SIP', 5061: 'SIPS',
                5353: 'mDNS', 5432: 'PostgreSQL', 5631: 'pcAnywhere', 5632: 'pcAnywhere',
                5672: 'AMQP', 5900: 'VNC', 6379: 'Redis', 6667: 'IRC', 6881: 'BitTorrent',
                7844: 'Services', 8080: 'HTTP-Alt', 8081: 'HTTP-Alt', 8086: 'InfluxDB',
                8181: 'HTTP-Alt', 8443: 'HTTPS-Alt', 9000: 'Services', 9090: 'Prometheus',
                9100: 'Printing', 9418: 'Git', 9999: 'Services', 25565: 'Minecraft', 27017: 'MongoDB'
            };
            return services[port] || '';
        };

        content.innerHTML = `
            <!-- Host Header -->
            <div class="p-4 bg-slate-800 rounded-lg">
                <div class="flex items-center justify-between mb-2">
                    <div class="flex items-center gap-2">
                        <span class="font-mono text-lg text-white">${escapeHtml(host.ip)}</span>
                        ${isLocal ? '<span class="px-2 py-0.5 text-xs bg-purple-600 text-purple-100 rounded">RAGNAR</span>' : ''}
                        ${host.hostname ? `<span class="text-gray-400">(${escapeHtml(host.hostname)})</span>` : ''}
                    </div>
                    ${host.mac ? `<span class="font-mono text-xs text-gray-500">${escapeHtml(host.mac)}</span>` : ''}
                </div>
                <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center text-sm">
                    <div class="bg-slate-700 rounded p-2">
                        <div class="text-cyan-400 font-bold">${formatBytes(host.total_bytes)}</div>
                        <div class="text-xs text-gray-500">Total Traffic</div>
                    </div>
                    <div class="bg-slate-700 rounded p-2">
                        <div class="text-green-400 font-bold">${host.total_packets || 0}</div>
                        <div class="text-xs text-gray-500">Packets</div>
                    </div>
                    <div class="bg-slate-700 rounded p-2">
                        <div class="text-blue-400 font-bold">${ports.length}</div>
                        <div class="text-xs text-gray-500">Ports</div>
                    </div>
                    <div class="bg-slate-700 rounded p-2">
                        <div class="text-purple-400 font-bold">${host.connections_active || 0}</div>
                        <div class="text-xs text-gray-500">Active Conns</div>
                    </div>
                </div>
            </div>

            <!-- Traffic Direction -->
            <div class="p-4 bg-slate-800 rounded-lg">
                <h4 class="text-sm font-semibold text-gray-300 mb-3">Traffic Direction</h4>
                <div class="grid grid-cols-2 gap-4">
                    <div class="text-center">
                        <div class="text-2xl font-bold text-green-400">↓ ${formatBytes(host.bytes_in || 0)}</div>
                        <div class="text-xs text-gray-500">${host.packets_in || 0} packets inbound</div>
                    </div>
                    <div class="text-center">
                        <div class="text-2xl font-bold text-blue-400">↑ ${formatBytes(host.bytes_out || 0)}</div>
                        <div class="text-xs text-gray-500">${host.packets_out || 0} packets outbound</div>
                    </div>
                </div>
            </div>

            <!-- Protocols -->
            <div class="p-4 bg-slate-800 rounded-lg">
                <h4 class="text-sm font-semibold text-gray-300 mb-3">Protocols (${protocols.length})</h4>
                <div class="flex flex-wrap gap-2">
                    ${protocols.length > 0 ? protocols.map(([proto, count]) => `
                        <span class="px-3 py-1 bg-slate-700 rounded-full text-sm">
                            <span class="text-purple-400 font-semibold">${escapeHtml(proto.toUpperCase())}</span>
                            <span class="text-gray-400 ml-1">${count}</span>
                        </span>
                    `).join('') : '<span class="text-gray-500">No protocol data</span>'}
                </div>
            </div>

            <!-- Ports Contacted -->
            <div class="p-4 bg-slate-800 rounded-lg">
                <h4 class="text-sm font-semibold text-gray-300 mb-3">Ports Contacted (${ports.length})</h4>
                <div class="flex flex-wrap gap-2 max-h-32 overflow-y-auto">
                    ${ports.length > 0 ? ports.sort((a, b) => a - b).map(port => {
                        const service = getServiceName(port);
                        const isSuspicious = [4444, 5555, 6666, 31337, 12345, 54321].includes(port);
                        const colorClass = isSuspicious ? 'bg-red-900 text-red-300 border border-red-600' :
                                          service ? 'bg-cyan-900 bg-opacity-50 text-cyan-300' : 'bg-slate-700 text-gray-300';
                        return `<span class="px-2 py-1 ${colorClass} rounded text-xs font-mono" title="${service || 'Unknown'}">${port}${service ? ` (${service})` : ''}</span>`;
                    }).join('') : '<span class="text-gray-500">No port data</span>'}
                </div>
            </div>

            <!-- DNS Queries -->
            ${dnsQueries.length > 0 ? `
            <div class="p-4 bg-slate-800 rounded-lg">
                <h4 class="text-sm font-semibold text-gray-300 mb-3">DNS Queries (${dnsQueries.length})</h4>
                <div class="space-y-1 max-h-32 overflow-y-auto text-xs font-mono">
                    ${dnsQueries.map(query => `
                        <div class="p-2 bg-slate-700 rounded text-yellow-300 break-all">${escapeHtml(query)}</div>
                    `).join('')}
                </div>
            </div>
            ` : ''}

            <!-- Timestamps -->
            <div class="p-4 bg-slate-800 rounded-lg">
                <h4 class="text-sm font-semibold text-gray-300 mb-3">Timeline</h4>
                <div class="grid grid-cols-2 gap-4 text-sm">
                    <div>
                        <div class="text-gray-500">First Seen</div>
                        <div class="text-white">${firstSeen}</div>
                    </div>
                    <div>
                        <div class="text-gray-500">Last Seen</div>
                        <div class="text-white">${lastSeen}</div>
                    </div>
                </div>
            </div>
        `;

    } catch (error) {
        console.error('Error loading host details:', error);
        content.innerHTML = '<p class="text-red-400 text-center py-8">Error loading host details</p>';
    }
}

/**
 * Close traffic host detail modal
 */
function closeTrafficHostModal() {
    const modal = document.getElementById('traffic-host-modal');
    if (modal) {
        modal.classList.add('hidden');
        modal.classList.remove('flex');
    }
}

/**
 * Show traffic connection detail modal
 */
function showTrafficConnectionDetail(connDataStr) {
    const modal = document.getElementById('traffic-connection-modal');
    const content = document.getElementById('traffic-connection-modal-content');

    if (!modal || !content) return;

    let conn;
    try {
        conn = typeof connDataStr === 'string' ? JSON.parse(connDataStr) : connDataStr;
    } catch (e) {
        console.error('Error parsing connection data:', e);
        return;
    }

    const duration = conn.duration_seconds ? formatDuration(conn.duration_seconds) : 'N/A';
    const firstSeen = conn.first_seen ? new Date(conn.first_seen).toLocaleString() : 'N/A';
    const lastSeen = conn.last_seen ? new Date(conn.last_seen).toLocaleString() : 'N/A';

    content.innerHTML = `
        <!-- Connection Header -->
        <div class="p-4 bg-slate-800 rounded-lg">
            <div class="flex items-center justify-center gap-3 text-lg font-mono mb-4">
                <span class="text-cyan-400">${escapeHtml(conn.src_ip)}:${conn.src_port}</span>
                <span class="text-gray-500">→</span>
                <span class="text-green-400">${escapeHtml(conn.dst_ip)}:${conn.dst_port}</span>
            </div>
            <div class="flex justify-center">
                <span class="px-3 py-1 bg-blue-900 text-blue-300 rounded-full text-sm font-semibold">
                    ${escapeHtml(conn.protocol?.toUpperCase() || 'UNKNOWN')}
                </span>
            </div>
        </div>

        <!-- Statistics -->
        <div class="p-4 bg-slate-800 rounded-lg">
            <h4 class="text-sm font-semibold text-gray-300 mb-3">Statistics</h4>
            <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center text-sm">
                <div class="bg-slate-700 rounded p-2">
                    <div class="text-cyan-400 font-bold">${formatBytes(conn.bytes_sent || 0)}</div>
                    <div class="text-xs text-gray-500">Bytes Sent</div>
                </div>
                <div class="bg-slate-700 rounded p-2">
                    <div class="text-green-400 font-bold">${formatBytes(conn.bytes_recv || 0)}</div>
                    <div class="text-xs text-gray-500">Bytes Received</div>
                </div>
                <div class="bg-slate-700 rounded p-2">
                    <div class="text-blue-400 font-bold">${conn.packets_sent || 0}</div>
                    <div class="text-xs text-gray-500">Packets Sent</div>
                </div>
                <div class="bg-slate-700 rounded p-2">
                    <div class="text-purple-400 font-bold">${conn.packets_recv || 0}</div>
                    <div class="text-xs text-gray-500">Packets Received</div>
                </div>
            </div>
        </div>

        <!-- Duration -->
        <div class="p-4 bg-slate-800 rounded-lg">
            <h4 class="text-sm font-semibold text-gray-300 mb-3">Duration</h4>
            <div class="text-center">
                <div class="text-2xl font-bold text-yellow-400">${duration}</div>
                <div class="text-xs text-gray-500 mt-1">Connection duration</div>
            </div>
        </div>

        <!-- Flags -->
        ${conn.flags && conn.flags.length > 0 ? `
        <div class="p-4 bg-slate-800 rounded-lg">
            <h4 class="text-sm font-semibold text-gray-300 mb-3">TCP Flags</h4>
            <div class="flex flex-wrap gap-2">
                ${conn.flags.map(flag => `
                    <span class="px-2 py-1 bg-orange-900 text-orange-300 rounded text-xs font-mono">${escapeHtml(flag)}</span>
                `).join('')}
            </div>
        </div>
        ` : ''}

        <!-- Timeline -->
        <div class="p-4 bg-slate-800 rounded-lg">
            <h4 class="text-sm font-semibold text-gray-300 mb-3">Timeline</h4>
            <div class="grid grid-cols-2 gap-4 text-sm">
                <div>
                    <div class="text-gray-500">First Seen</div>
                    <div class="text-white">${firstSeen}</div>
                </div>
                <div>
                    <div class="text-gray-500">Last Seen</div>
                    <div class="text-white">${lastSeen}</div>
                </div>
            </div>
        </div>

        <!-- Quick Actions -->
        <div class="flex gap-2">
            <button onclick="showTrafficHostDetail('${escapeHtml(conn.src_ip)}')"
                    class="flex-1 px-3 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg text-sm transition-colors">
                View Source Host
            </button>
            <button onclick="showTrafficHostDetail('${escapeHtml(conn.dst_ip)}')"
                    class="flex-1 px-3 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg text-sm transition-colors">
                View Dest Host
            </button>
        </div>
    `;

    modal.classList.remove('hidden');
    modal.classList.add('flex');
}

/**
 * Close traffic connection detail modal
 */
function closeTrafficConnectionModal() {
    const modal = document.getElementById('traffic-connection-modal');
    if (modal) {
        modal.classList.add('hidden');
        modal.classList.remove('flex');
    }
}

/**
 * Show traffic port detail modal
 */
async function showTrafficPortDetail(port, portHosts) {
    const modal = document.getElementById('traffic-port-modal');
    const portTitle = document.getElementById('traffic-port-modal-port');
    const serviceTitle = document.getElementById('traffic-port-modal-service');
    const content = document.getElementById('traffic-port-modal-content');

    if (!modal || !content) return;

    const portNum = parseInt(port);
    portTitle.textContent = port;

    // Get service name
    const commonPorts = {
        20: 'FTP Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
        53: 'DNS', 67: 'DHCP Server', 68: 'DHCP Client', 69: 'TFTP',
        80: 'HTTP', 110: 'POP3', 119: 'NNTP', 123: 'NTP', 135: 'MS-RPC',
        137: 'NetBIOS-NS', 138: 'NetBIOS-DGM', 139: 'NetBIOS-SSN',
        143: 'IMAP', 161: 'SNMP', 162: 'SNMP Trap', 389: 'LDAP',
        443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 514: 'Syslog',
        587: 'SMTP Submission', 636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S',
        1080: 'SOCKS', 1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL',
        3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
        8080: 'HTTP Proxy', 8443: 'HTTPS Alt', 27017: 'MongoDB'
    };

    const suspiciousInfo = SUSPICIOUS_PORT_INFO[portNum];
    const serviceName = suspiciousInfo ? suspiciousInfo.name : (commonPorts[portNum] || 'Unknown Service');
    serviceTitle.textContent = serviceName;

    content.innerHTML = '<div class="text-center py-8"><div class="animate-spin w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full mx-auto"></div><p class="text-gray-400 mt-2">Loading port details...</p></div>';

    modal.classList.remove('hidden');
    modal.classList.add('flex');

    try {
        // Fetch hosts data to get more info about connections on this port
        const response = await fetch('/api/traffic/hosts?limit=100&sort=bytes');
        const data = await response.json();

        if (!data.success || !data.hosts) {
            content.innerHTML = '<p class="text-red-400 text-center py-8">Failed to load port details</p>';
            return;
        }

        // Find hosts using this port
        const hostsUsingPort = data.hosts.filter(h => h.ports_contacted && h.ports_contacted.includes(portNum));

        let html = '';

        // Security warning if suspicious
        if (suspiciousInfo) {
            const severityColors = {
                critical: 'bg-red-900 border-red-500 text-red-300',
                high: 'bg-orange-900 border-orange-500 text-orange-300',
                medium: 'bg-yellow-900 border-yellow-500 text-yellow-300',
                low: 'bg-blue-900 border-blue-500 text-blue-300'
            };
            html += `
                <div class="p-3 ${severityColors[suspiciousInfo.severity]} border-l-4 rounded">
                    <div class="flex items-center space-x-2 mb-1">
                        <span class="text-lg">⚠️</span>
                        <span class="font-semibold uppercase text-xs">${suspiciousInfo.severity} Severity</span>
                        <span class="text-xs px-2 py-0.5 bg-black bg-opacity-30 rounded">${escapeHtml(suspiciousInfo.category)}</span>
                    </div>
                    <p class="text-sm">${escapeHtml(suspiciousInfo.reason)}</p>
                </div>
            `;
        }

        // Port statistics
        html += `
            <div class="grid grid-cols-2 gap-3">
                <div class="bg-slate-800 bg-opacity-50 p-3 rounded">
                    <div class="text-xs text-gray-400 uppercase">Total Hosts</div>
                    <div class="text-2xl font-bold text-cyan-400">${hostsUsingPort.length}</div>
                </div>
                <div class="bg-slate-800 bg-opacity-50 p-3 rounded">
                    <div class="text-xs text-gray-400 uppercase">Service</div>
                    <div class="text-lg font-semibold text-white">${escapeHtml(serviceName)}</div>
                </div>
            </div>
        `;

        // Hosts using this port
        if (hostsUsingPort.length > 0) {
            html += `
                <div>
                    <h4 class="text-sm font-semibold text-gray-300 mb-2">Hosts Using This Port</h4>
                    <div class="space-y-1 max-h-60 overflow-y-auto">
                        ${hostsUsingPort.map(host => {
                            const totalBytes = host.total_bytes || 0;
                            return `
                                <div class="flex items-center justify-between p-2 bg-slate-700 bg-opacity-30 rounded hover:bg-slate-600 hover:bg-opacity-50 transition-colors cursor-pointer" onclick="closeTrafficPortModal(); showTrafficHostDetail('${escapeHtml(host.ip)}')">
                                    <div class="flex items-center space-x-2">
                                        <span class="font-mono text-cyan-400">${escapeHtml(host.ip)}</span>
                                        ${host.hostname ? `<span class="text-gray-500 text-xs">(${escapeHtml(host.hostname)})</span>` : ''}
                                    </div>
                                    <div class="text-xs text-gray-400">
                                        ${formatBytes(totalBytes)}
                                    </div>
                                </div>
                            `;
                        }).join('')}
                    </div>
                </div>
            `;
        } else {
            html += '<p class="text-gray-400 text-center py-4">No active hosts on this port</p>';
        }

        content.innerHTML = html;

    } catch (error) {
        console.error('Error loading port details:', error);
        content.innerHTML = '<p class="text-red-400 text-center py-8">Error loading port details</p>';
    }
}

/**
 * Close traffic port detail modal
 */
function closeTrafficPortModal() {
    const modal = document.getElementById('traffic-port-modal');
    if (modal) {
        modal.classList.add('hidden');
        modal.classList.remove('flex');
    }
}

// ============================================================================
// ADVANCED VULNERABILITY SCANNING FUNCTIONS
// ============================================================================

async function loadAdvancedVulnData() {
    try {
        // Fetch status and findings in parallel for faster load
        const [statusResponse, findingsResponse] = await Promise.all([
            fetch('/api/vuln-advanced/status'),
            fetch('/api/vuln-advanced/findings?limit=1000')
        ]);
        const data = await statusResponse.json();

        if (!data.success || !data.available) {
            showAdvVulnNotAvailable();
            return;
        }

        hideAdvVulnNotAvailable();
        updateScannerStatus(data.scanners);
        updateVulnSummary(data.summary);

        // Parse findings (already fetched in parallel)
        try {
            const findingsData = await findingsResponse.json();
            if (findingsData.success) {
                advVulnFindingsCache = findingsData.findings || [];
            }
        } catch (e) {
            console.warn('Error parsing findings:', e);
        }

        updateActiveScans(data.active_scans);

        // Update stats after findings are loaded
        updateVulnStats(data.active_scans, advVulnFindingsCache);

        // Auto-start polling if any scans are running (handles page refresh / tab switch)
        const hasRunning = (data.active_scans || []).some(s => s.status === 'running');
        if (hasRunning && !advVulnRefreshInterval) {
            startAdvVulnPolling();
        }

    } catch (error) {
        console.error('Error loading advanced vuln data:', error);
        showAdvVulnNotAvailable();
    }
}

function updateActiveScans(scans, options = {}) {
    const container = document.getElementById('adv-vuln-active-scans');
    if (!container) return;

    advVulnScansCache = scans || [];

    // Control the spinner animation based on running scans
    const spinner = document.getElementById('adv-vuln-scans-spinner');
    const hasRunningScans = advVulnScansCache.some(scan => scan.status === 'running');
    if (spinner) {
        spinner.classList.toggle('animate-spin', hasRunningScans);
    }

    if (!advVulnScansCache.length) {
        container.innerHTML = '<p class="text-gray-400 text-center py-4 text-sm">No active scans</p>';
        updateScansToggleButton(0);
        return;
    }

    const scanFindingsMap = buildAdvVulnScanFindingsMap(advVulnScansCache);
    advVulnScanFindingsMap = scanFindingsMap;

    // Clean up expanded IDs for scans that no longer exist
    const validIds = new Set(advVulnScansCache.map(s => s.scan_id));
    advVulnExpandedScanIds.forEach(id => {
        if (!validIds.has(id)) advVulnExpandedScanIds.delete(id);
    });

    const scansToRender = advVulnShowAllScans ? advVulnScansCache : advVulnScansCache.slice(0, 3);
    updateScansToggleButton(advVulnScansCache.length);

    const statusLabels = {
        running: 'Running',
        completed: 'Completed',
        failed: 'Failed',
        cancelled: 'Cancelled'
    };

    const severityBadgeClasses = {
        critical: 'bg-red-600 text-white',
        high: 'bg-orange-500 text-white',
        medium: 'bg-yellow-500 text-black',
        low: 'bg-blue-500 text-white',
        info: 'bg-gray-500 text-white'
    };

    // Save log panel scroll positions before re-render
    const logScrollPositions = new Map();
    for (const logScanId of advVulnExpandedLogIds) {
        const logPanel = document.getElementById(`scan-logs-${logScanId}`);
        if (logPanel) {
            logScrollPositions.set(logScanId, logPanel.scrollTop);
        }
    }

    container.innerHTML = scansToRender.map(scan => {
        const scanId = scan.scan_id;
        const mapEntry = scanFindingsMap.get(scanId) || { findings: [], counts: {} };
        const counts = mapEntry.counts || {};
        const findingsCount = scan.findings_count || mapEntry.findings.length || 0;
        const riskScore = (counts.critical || 0) * 10 + (counts.high || 0) * 7 + (counts.medium || 0) * 4 + (counts.low || 0) * 1;
        const riskColor = riskScore >= 50 ? 'text-red-400' : riskScore >= 30 ? 'text-orange-400' : riskScore >= 15 ? 'text-yellow-400' : 'text-green-400';
        const durationSeconds = getScanDurationSeconds(scan);
        const status = scan.status || 'unknown';
        const progress = scan.progress_percent || scan.progress || 0;
        const currentPhase = scan.current_check || scan.current_phase || 'Processing...';
        const errorMessage = scan.error_message || '';
        const authType = scan.auth_type || '';
        const authStatus = scan.auth_status || '';
        const performedAt = scan.completed_at || scan.started_at;
        const performedLabel = scan.completed_at ? 'Completed' : 'Started';
        const isExpanded = advVulnExpandedScanIds.has(scanId);
        const isLogsExpanded = advVulnExpandedLogIds.has(scanId);
        const hasExpandedPanel = isExpanded || isLogsExpanded;

        return `
            <div>
                <div class="p-4 rounded-lg border ${hasExpandedPanel ? (isExpanded ? 'border-cyan-500/50' : 'border-green-500/50') + ' rounded-b-none' : 'border-slate-700'} bg-slate-800/60 hover:bg-slate-700/70 transition cursor-pointer"
                     onclick="toggleAdvVulnScanFindings('${scanId}')">
                    <div class="flex items-start justify-between gap-3">
                        <div>
                            <div class="text-sm font-semibold text-white">${escapeHtml(formatScanType(scan.scan_type))}</div>
                            <div class="text-xs text-gray-400 mt-1">${escapeHtml(scan.target || 'Unknown target')}</div>
                        </div>
                        <span class="text-[11px] uppercase px-2 py-1 rounded-full bg-slate-700 text-gray-300">${escapeHtml(statusLabels[status] || status)}</span>
                    </div>

                    <div class="mt-3 grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs text-gray-300">
                        <div>${performedLabel}: <span class="text-gray-100">${performedAt ? escapeHtml(formatScanTimestamp(performedAt)) : 'N/A'}</span></div>
                        <div>Duration: <span class="text-gray-100">${durationSeconds ? formatDuration(durationSeconds) : 'N/A'}</span></div>
                        <div>Findings: <span class="text-cyan-300 font-semibold">${findingsCount}</span></div>
                        <div>Method: <span class="text-gray-100">${escapeHtml(formatScanType(scan.scan_type))}</span></div>
                    </div>

                    <div class="mt-3 flex flex-wrap items-center gap-2 text-[11px]">
                        ${['critical', 'high', 'medium', 'low', 'info'].map(severity => `
                            <span class="px-2 py-0.5 rounded ${severityBadgeClasses[severity]}">
                                ${severity.toUpperCase()}: ${counts[severity] || 0}
                            </span>
                        `).join('')}
                        ${findingsCount > 0 ? `<span class="ml-auto text-xs font-semibold ${riskColor}">Risk: ${riskScore}</span>` : ''}
                    </div>

                    ${authType ? `
                        <div class="flex items-center gap-1 text-xs mt-2">
                            <span class="px-1.5 py-0.5 rounded ${
                                authStatus.startsWith('verified') ? 'bg-green-900 text-green-400' :
                                authStatus.startsWith('failed') ? 'bg-red-900 text-red-400' :
                                'bg-yellow-900 text-yellow-400'
                            }">
                                ${authStatus.startsWith('verified') ? '✓' : authStatus.startsWith('failed') ? '✗' : '🔐'} ${escapeHtml(authType)} ${authStatus ? `- ${escapeHtml(authStatus)}` : ''}
                            </span>
                        </div>
                    ` : ''}

                    ${status === 'running' ? `
                        <div class="mt-3">
                            <div class="flex justify-between text-xs text-gray-400 mb-1">
                                <span>${escapeHtml(currentPhase)}</span>
                                <span>${progress}%</span>
                            </div>
                            <div class="h-1.5 bg-slate-700 rounded-full overflow-hidden">
                                <div class="h-full bg-blue-500 transition-all duration-500 ${progress === 0 ? 'animate-pulse !w-full opacity-30' : ''}" style="${progress > 0 ? `width: ${progress}%` : ''}"></div>
                            </div>
                        </div>
                    ` : ''}
                    ${errorMessage ? `<div class="text-xs text-red-400 mt-2">${escapeHtml(errorMessage)}</div>` : ''}
                    ${status === 'completed' && findingsCount === 0 && !errorMessage ? `
                        <div class="text-xs text-yellow-400 mt-2">0 findings - check server logs for details</div>
                    ` : ''}

                    <div class="mt-3 flex items-center justify-between">
                        <div class="flex gap-3 flex-wrap text-xs">
                            ${status === 'running' ? `
                                <button onclick="event.stopPropagation(); cancelAdvScan('${scanId}')" class="text-red-400 hover:text-red-300 flex items-center gap-1">
                                    <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                                    Cancel
                                </button>
                            ` : `
                                <button onclick="event.stopPropagation(); downloadScanReport('${scanId}')" class="text-cyan-400 hover:text-cyan-300 flex items-center gap-1">
                                    <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
                                    Report
                                </button>
                                <button onclick="event.stopPropagation(); deleteAdvScan('${scanId}')" class="text-gray-400 hover:text-red-400 flex items-center gap-1">
                                    <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
                                    Delete
                                </button>
                            `}
                        </div>
                        <div class="flex items-center gap-3">
                            <button onclick="event.stopPropagation(); toggleAdvVulnScanLogs('${scanId}')"
                                    class="flex items-center gap-1 text-xs ${advVulnExpandedLogIds.has(scanId) ? 'text-green-400' : 'text-gray-400 hover:text-gray-200'} transition-colors">
                                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                                </svg>
                                <span>${advVulnExpandedLogIds.has(scanId) ? 'Hide' : 'Show'} Logs</span>
                            </button>
                            <button onclick="event.stopPropagation(); toggleAdvVulnScanFindings('${scanId}')"
                                    class="flex items-center gap-1 text-xs ${isExpanded ? 'text-cyan-400' : 'text-gray-400 hover:text-gray-200'} transition-colors">
                                <span>${isExpanded ? 'Hide' : 'Show'} Findings</span>
                                <svg class="w-4 h-4 transition-transform ${isExpanded ? 'rotate-180' : ''}" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
                                </svg>
                            </button>
                        </div>
                    </div>
                </div>
                ${isLogsExpanded ? renderInlineScanLogs(scanId, isExpanded) : ''}
                ${isExpanded ? renderInlineScanFindings(scanId, scan) : ''}
            </div>
        `;
    }).join('');

    // Restore log panel scroll positions after re-render
    for (const [logScanId, scrollTop] of logScrollPositions) {
        const logPanel = document.getElementById(`scan-logs-${logScanId}`);
        if (logPanel) {
            logPanel.scrollTop = scrollTop;
        }
    }
}

function toggleAdvVulnScansExpanded() {
    advVulnShowAllScans = !advVulnShowAllScans;
    updateActiveScans(advVulnScansCache, { preserveSelection: true });
}

function updateScansToggleButton(totalScans) {
    const toggleBtn = document.getElementById('adv-vuln-scans-toggle');
    const toggleIcon = document.getElementById('adv-vuln-scans-toggle-icon');
    if (!toggleBtn) return;

    if (totalScans <= 3) {
        toggleBtn.classList.add('hidden');
        return;
    }

    toggleBtn.classList.remove('hidden');
    toggleBtn.querySelector('span').textContent = advVulnShowAllScans ? 'Show fewer scans' : `Show all scans (${totalScans})`;
    if (toggleIcon) {
        toggleIcon.classList.toggle('rotate-180', advVulnShowAllScans);
    }
}

function buildAdvVulnScanFindingsMap(scans) {
    const scanIds = scans.map(scan => scan.scan_id).filter(Boolean);
    const map = new Map();

    scans.forEach(scan => {
        map.set(scan.scan_id, {
            findings: [],
            counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
        });
    });

    advVulnFindingsCache.forEach(finding => {
        const scanId = getFindingScanId(finding, scanIds);
        if (!scanId || !map.has(scanId)) return;
        const entry = map.get(scanId);
        entry.findings.push(finding);
        if (entry.counts.hasOwnProperty(finding.severity)) {
            entry.counts[finding.severity]++;
        }
    });

    return map;
}

function getFindingScanId(finding, scanIds = []) {
    if (!finding) return null;
    if (finding.scan_id) return finding.scan_id;
    if (!finding.finding_id) return null;
    return scanIds.find(scanId => finding.finding_id.startsWith(`${scanId}-`)) || null;
}

function formatScanType(scanType) {
    if (!scanType) return 'Unknown';
    return scanType
        .replace(/_/g, ' ')
        .replace(/\b\w/g, match => match.toUpperCase());
}

function formatScanTimestamp(timestamp) {
    if (!timestamp) return 'N/A';
    const date = new Date(timestamp);
    if (Number.isNaN(date.getTime())) return timestamp;
    return date.toLocaleString(undefined, {
        weekday: 'short',
        month: 'short',
        day: 'numeric',
        hour: 'numeric',
        minute: '2-digit'
    });
}

function getScanDurationSeconds(scan) {
    if (!scan) return 0;
    if (scan.duration_seconds) return scan.duration_seconds;
    if (!scan.started_at) return 0;
    const started = new Date(scan.started_at);
    if (Number.isNaN(started.getTime())) return 0;
    return Math.max(0, (Date.now() - started.getTime()) / 1000);
}

function toggleAdvVulnScanFindings(scanId) {
    if (advVulnExpandedScanIds.has(scanId)) {
        advVulnExpandedScanIds.delete(scanId);
    } else {
        advVulnExpandedScanIds.add(scanId);
    }
    updateActiveScans(advVulnScansCache, { preserveSelection: true });
}

function renderInlineScanFindings(scanId, scan) {
    const mapEntry = advVulnScanFindingsMap.get(scanId) || { findings: [], counts: {} };
    const findings = mapEntry.findings || [];

    const severityBadgeClasses = {
        critical: 'bg-red-600 text-white',
        high: 'bg-orange-500 text-white',
        medium: 'bg-yellow-500 text-black',
        low: 'bg-blue-500 text-white',
        info: 'bg-gray-500 text-white'
    };

    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const sortedFindings = [...findings].sort((a, b) => {
        return (severityOrder[a.severity] || 5) - (severityOrder[b.severity] || 5);
    });

    const findingsHtml = sortedFindings.length ? sortedFindings.map(finding => {
        const timestamp = finding.timestamp ? formatScanTimestamp(finding.timestamp) : 'N/A';
        const detailsJson = finding.details ? JSON.stringify(finding.details, null, 2) : '';

        return `
            <div class="p-4 rounded-lg border border-slate-700 bg-slate-800/60">
                <div class="flex flex-wrap items-center justify-between gap-2">
                    <div class="flex items-center gap-2">
                        <span class="px-2 py-1 rounded text-xs uppercase ${severityBadgeClasses[finding.severity] || 'bg-gray-600 text-white'}">
                            ${escapeHtml(finding.severity || 'info')}
                        </span>
                        <span class="text-sm font-semibold text-white">${escapeHtml(finding.title || 'Untitled Finding')}</span>
                    </div>
                    <span class="text-xs text-gray-400">${timestamp}</span>
                </div>
                <div class="mt-2 text-xs text-gray-300 flex flex-wrap gap-3">
                    <span>Host: <span class="font-mono text-gray-100">${escapeHtml(finding.host || 'N/A')}${finding.port ? ':' + finding.port : ''}</span></span>
                    <span>Scanner: <span class="text-gray-100">${escapeHtml(finding.scanner || 'Unknown')}</span></span>
                    ${finding.cvss_score ? `<span>CVSS: <span class="text-gray-100">${escapeHtml(finding.cvss_score)}</span></span>` : ''}
                    ${finding.matched_at ? `<span>URL: <span class="text-gray-100 break-all">${escapeHtml(finding.matched_at)}</span></span>` : ''}
                </div>
                ${finding.description ? `<div class="mt-3 text-sm text-gray-200">${escapeHtml(finding.description)}</div>` : ''}
                ${finding.remediation ? `<div class="mt-3 text-sm text-yellow-200"><span class="font-semibold">Remediation:</span> ${escapeHtml(finding.remediation)}</div>` : ''}
                ${finding.evidence ? `
                    <div class="mt-3">
                        <div class="text-xs text-cyan-300 font-semibold">Evidence</div>
                        <pre class="mt-1 text-xs text-green-300 bg-slate-900/80 rounded p-3 overflow-x-auto whitespace-pre-wrap">${escapeHtml(finding.evidence)}</pre>
                    </div>
                ` : ''}
                ${finding.cve_ids?.length || finding.cwe_ids?.length ? `
                    <div class="mt-3 text-xs text-gray-300 flex flex-wrap gap-2">
                        ${finding.cve_ids?.length ? `<span>CVEs: ${finding.cve_ids.map(cve => `<span class="text-cyan-300">${escapeHtml(cve)}</span>`).join(', ')}</span>` : ''}
                        ${finding.cwe_ids?.length ? `<span>CWEs: ${finding.cwe_ids.map(cwe => `<span class="text-cyan-300">${escapeHtml(cwe)}</span>`).join(', ')}</span>` : ''}
                    </div>
                ` : ''}
                ${finding.references?.length ? `
                    <div class="mt-3 text-xs text-gray-300">
                        <div class="text-cyan-300 font-semibold mb-1">References</div>
                        <ul class="space-y-1">
                            ${finding.references.map(ref => `<li><a href="${escapeHtml(ref)}" target="_blank" class="text-blue-400 hover:underline break-all">${escapeHtml(ref)}</a></li>`).join('')}
                        </ul>
                    </div>
                ` : ''}
                ${finding.tags?.length ? `
                    <div class="mt-3 text-xs text-gray-400">Tags: ${finding.tags.map(tag => `<span class="px-2 py-0.5 bg-slate-700 rounded">${escapeHtml(tag)}</span>`).join(' ')}</div>
                ` : ''}
                ${detailsJson ? `
                    <div class="mt-3">
                        <div class="text-xs text-cyan-300 font-semibold">Details</div>
                        <pre class="mt-1 text-xs text-gray-300 bg-slate-900/80 rounded p-3 overflow-x-auto whitespace-pre-wrap">${escapeHtml(detailsJson)}</pre>
                    </div>
                ` : ''}
            </div>
        `;
    }).join('') : '<p class="text-gray-400 text-sm py-2">No findings for this scan yet.</p>';

    return `
        <div class="border border-t-0 border-cyan-500/50 rounded-b-lg bg-slate-900/50 p-3 space-y-3 max-h-[600px] overflow-y-auto">
            ${findingsHtml}
        </div>
    `;
}

// ============================================================================
// SCAN LIVE LOGS FUNCTIONS
// ============================================================================

function toggleAdvVulnScanLogs(scanId) {
    if (advVulnExpandedLogIds.has(scanId)) {
        advVulnExpandedLogIds.delete(scanId);
    } else {
        advVulnExpandedLogIds.add(scanId);
        // Immediately fetch logs
        fetchScanLogs(scanId);
    }
    updateActiveScans(advVulnScansCache, { preserveSelection: true });
}

async function fetchScanLogs(scanId) {
    try {
        const cache = advVulnLogCache.get(scanId) || { entries: [], lastIndex: 0 };
        const response = await fetch(`/api/vuln-advanced/scan/${scanId}/logs?since=${cache.lastIndex}`);
        const data = await response.json();

        if (data.success && data.logs.length > 0) {
            cache.entries = cache.entries.concat(data.logs);
            cache.lastIndex = data.total;
            advVulnLogCache.set(scanId, cache);

            // Update the log panel if it's visible
            const logPanel = document.getElementById(`scan-logs-${scanId}`);
            if (logPanel) {
                // Only auto-scroll if user is already near the bottom
                const isNearBottom = (logPanel.scrollHeight - logPanel.scrollTop - logPanel.clientHeight) < 50;
                logPanel.innerHTML = renderLogEntries(cache.entries);
                if (isNearBottom) {
                    logPanel.scrollTop = logPanel.scrollHeight;
                }
            }
        }
    } catch (error) {
        console.error('Error fetching scan logs:', error);
    }
}

function renderLogEntries(entries) {
    if (!entries.length) {
        return '<p class="text-gray-500 text-xs font-mono">Waiting for log entries...</p>';
    }

    const levelColors = {
        'info': 'text-blue-400',
        'warning': 'text-yellow-400',
        'error': 'text-red-400',
        'debug': 'text-gray-500'
    };

    return entries.map(entry => {
        const time = new Date(entry.timestamp).toLocaleTimeString();
        const levelClass = levelColors[entry.level] || 'text-gray-300';
        return `<div class="text-xs font-mono py-0.5 leading-relaxed">
            <span class="text-gray-500">${escapeHtml(time)}</span>
            <span class="${levelClass} uppercase font-semibold">[${escapeHtml(entry.level)}]</span>
            <span class="text-gray-200">${escapeHtml(entry.message)}</span>
        </div>`;
    }).join('');
}

function renderInlineScanLogs(scanId, findingsAlsoExpanded = false) {
    const cache = advVulnLogCache.get(scanId) || { entries: [] };
    return `
        <div class="border border-t-0 border-green-500/50 ${findingsAlsoExpanded ? '' : 'rounded-b-lg'} bg-slate-950/80 p-3 max-h-[300px] overflow-y-auto scrollbar-thin"
             id="scan-logs-${scanId}">
            ${renderLogEntries(cache.entries)}
        </div>
    `;
}

async function deleteAdvScan(scanId) {
    if (!confirm('Delete this scan and its findings?')) return;

    try {
        const response = await fetch(`/api/vuln-advanced/scan/${scanId}`, {
            method: 'DELETE'
        });
        const data = await response.json();

        if (data.success) {
            showNotification('Scan deleted', 'info');
            await refreshAdvVulnData();
        } else {
            showNotification(data.error || 'Failed to delete scan', 'error');
        }
    } catch (error) {
        console.error('Error deleting scan:', error);
        showNotification('Failed to delete scan', 'error');
    }
}

async function deleteAllAdvScans() {
    if (!confirm('Delete ALL scans and findings? This cannot be undone.')) return;

    try {
        const response = await fetch('/api/vuln-advanced/scans', {
            method: 'DELETE'
        });
        const data = await response.json();

        if (data.success) {
            showNotification(data.message, 'info');
            await refreshAdvVulnData();
        } else {
            showNotification(data.error || 'Failed to delete scans', 'error');
        }
    } catch (error) {
        console.error('Error deleting all scans:', error);
        showNotification('Failed to delete scans', 'error');
    }
}

function downloadZapReport(format = 'html') {
    window.open(`/api/zap/report?format=${format}`, '_blank');
}

function downloadScanReport(scanId) {
    window.open(`/api/vuln-advanced/scan/${scanId}/report?format=html`, '_blank');
}

async function exportScanReport() {
    const btn = document.getElementById('export-report-btn');
    if (btn) { btn.disabled = true; btn.textContent = 'Generating...'; }
    try {
        const url = resolveNetworkAwareEndpoint('/api/report/export');
        const a = document.createElement('a');
        a.href = url;
        a.download = '';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        addConsoleMessage('Report download started', 'success');
    } catch(err) {
        addConsoleMessage('Report export failed: ' + err.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.innerHTML = '<svg class="w-4 h-4 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-4-4m4 4l4-4m6 4H6"></path></svg>Export Report'; }
    }
}

async function cancelAdvScan(scanId) {
    try {
        const response = await fetch(`/api/vuln-advanced/scan/${scanId}/cancel`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        const data = await response.json();

        if (data.success) {
            showNotification('Scan cancelled', 'info');
            await refreshAdvVulnData();
        } else {
            showNotification(data.error || 'Failed to cancel scan', 'error');
        }
    } catch (error) {
        console.error('Error cancelling scan:', error);
        showNotification('Failed to cancel scan', 'error');
    }
}

function showAdvVulnNotAvailable() {
    const notice = document.getElementById('adv-vuln-not-available');
    if (notice) notice.classList.remove('hidden');
}

function hideAdvVulnNotAvailable() {
    const notice = document.getElementById('adv-vuln-not-available');
    if (notice) notice.classList.add('hidden');
}

function updateScannerStatus(scanners) {
    if (!scanners) return;

    const scannerIds = ['nuclei', 'nikto', 'sqlmap', 'nmap_vuln', 'whatweb', 'zap'];

    scannerIds.forEach(id => {
        const statusEl = document.getElementById(`scanner-${id.replace('_', '-')}-status`);
        const cardEl = document.getElementById(`scanner-${id.replace('_', '-')}`);

        if (statusEl) {
            const available = scanners[id];
            if (id === 'zap') {
                // ZAP has special status (installed vs running)
                if (scanners.zap_running) {
                    statusEl.textContent = 'Running';
                    statusEl.classList.remove('text-gray-400', 'text-green-400');
                    statusEl.classList.add('text-cyan-400');
                } else if (available) {
                    statusEl.textContent = 'Installed';
                    statusEl.classList.remove('text-gray-400', 'text-cyan-400');
                    statusEl.classList.add('text-green-400');
                } else {
                    statusEl.textContent = 'Not installed';
                    statusEl.classList.remove('text-green-400', 'text-cyan-400');
                    statusEl.classList.add('text-gray-400');
                }
            } else {
                statusEl.textContent = available ? 'Available' : 'Not installed';
                statusEl.classList.toggle('text-green-400', available);
                statusEl.classList.toggle('text-gray-400', !available);
            }
        }

        if (cardEl) {
            cardEl.classList.toggle('opacity-50', !scanners[id]);
        }
    });

    // Update ZAP control panel visibility and status
    updateZapControlPanel(scanners);

    // Show AJAX spider browser warning if no real browser detected
    const browserWarning = document.getElementById('ajax-spider-browser-warning');
    if (browserWarning) {
        if (!scanners.ajax_spider_browser || scanners.ajax_spider_browser === 'htmlunit') {
            browserWarning.classList.remove('hidden');
            browserWarning.innerHTML = `
                <div class="flex items-center gap-2 text-xs text-yellow-400 bg-yellow-900/20 border border-yellow-700/30 rounded px-3 py-2 mt-3">
                    <svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z"></path>
                    </svg>
                    <span>No browser detected for AJAX spider. Install Chrome/Chromium or Firefox for better JavaScript crawling during scans. On Raspberry Pi, Chromium is usually pre-installed.</span>
                </div>
            `;
        } else {
            browserWarning.classList.add('hidden');
        }
    }
}

function updateVulnSummary(summary) {
    if (!summary?.severity_counts) return;

    // Update total findings and scans
    updateElement('vuln-total-findings', summary.total_findings || 0);
    updateElement('vuln-total-scans', summary.total_scans || 0);
}

function updateVulnStats(scans, findings) {
    // Count unique hosts
    const hosts = new Set();
    if (scans) {
        scans.forEach(s => hosts.add(s.target));
    }
    if (findings) {
        findings.forEach(f => hosts.add(f.host));
    }
    updateElement('vuln-hosts-count', hosts.size);

    // Find last scan time
    if (scans?.length) {
        const completedScans = scans.filter(s => s.completed_at);
        if (completedScans.length) {
            const lastScan = completedScans.reduce((a, b) => {
                const timeA = new Date(a.completed_at).getTime();
                const timeB = new Date(b.completed_at).getTime();
                return timeA > timeB ? a : b;
            });
            const lastTime = new Date(lastScan.completed_at);
            const now = new Date();
            const diffMins = Math.floor((now - lastTime) / 60000);
            let timeText;
            if (diffMins < 1) timeText = 'Just now';
            else if (diffMins < 60) timeText = `${diffMins}m ago`;
            else if (diffMins < 1440) timeText = `${Math.floor(diffMins / 60)}h ago`;
            else timeText = lastTime.toLocaleDateString();
            updateElement('vuln-last-scan-time', timeText);
        }
    }
}

// Store findings globally for detail view
let advVulnFindingsCache = [];
let advVulnShowAllScans = false;
let advVulnExpandedScanIds = new Set();
let advVulnExpandedLogIds = new Set();
let advVulnLogCache = new Map(); // Map<scanId, {entries: [], lastIndex: 0}>
let advVulnScansCache = [];
let advVulnScanFindingsMap = new Map();

async function loadAdvVulnFindings() {
    try {
        const response = await fetch('/api/vuln-advanced/findings?limit=1000');
        const data = await response.json();

        if (!data.success) return;

        advVulnFindingsCache = data.findings || [];

    } catch (error) {
        console.error('Error loading vuln findings:', error);
    }
}

async function quickRescanHost(host) {
    const scannerSelect = document.getElementById('adv-vuln-scanner');
    const scanType = scannerSelect ? scannerSelect.value : 'nmap_vuln';

    try {
        const response = await fetch('/api/vuln-advanced/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target: host, scan_type: scanType })
        });

        const data = await response.json();

        if (data.success) {
            showNotification(`Started ${scanType} rescan of ${host}`, 'success');
            startAdvVulnPolling();
        } else {
            showNotification(data.error || 'Failed to start rescan', 'error');
        }
    } catch (error) {
        console.error('Error starting rescan:', error);
        showNotification('Failed to start rescan', 'error');
    }
}

function updateAdvVulnRecentFindings(findings) {
    const container = document.getElementById('adv-vuln-findings');
    if (!container) return;

    if (!findings?.length) {
        container.innerHTML = '<p class="text-gray-400 text-center py-4">No findings yet</p>';
        return;
    }

    const severityColors = {
        'critical': 'border-red-600',
        'high': 'border-orange-500',
        'medium': 'border-yellow-500',
        'low': 'border-blue-500',
        'info': 'border-gray-500'
    };

    const severityBgColors = {
        'critical': 'bg-red-900',
        'high': 'bg-orange-900',
        'medium': 'bg-yellow-900',
        'low': 'bg-blue-900',
        'info': 'bg-gray-800'
    };

    container.innerHTML = findings.map((f, idx) => {
        // Format time ago
        let timeAgo = '';
        if (f.timestamp) {
            const then = new Date(f.timestamp);
            const now = new Date();
            const diffMins = Math.floor((now - then) / 60000);
            if (diffMins < 1) timeAgo = 'just now';
            else if (diffMins < 60) timeAgo = `${diffMins}m ago`;
            else if (diffMins < 1440) timeAgo = `${Math.floor(diffMins / 60)}h ago`;
            else timeAgo = `${Math.floor(diffMins / 1440)}d ago`;
        }

        const scanId = getFindingScanId(f, advVulnScansCache.map(s => s.scan_id));
        return `
            <div class="p-2 ${severityBgColors[f.severity] || 'bg-slate-800'} bg-opacity-50 rounded-lg border-l-4 ${severityColors[f.severity] || 'border-gray-500'} cursor-pointer hover:bg-opacity-70 transition-colors"
                 onclick="${scanId ? `toggleAdvVulnScanFindings('${scanId}')` : ''}"
                <div class="flex items-start justify-between gap-2">
                    <div class="flex-1 min-w-0">
                        <div class="font-medium text-sm truncate">${escapeHtml(f.title)}</div>
                        <div class="text-xs text-gray-400">${escapeHtml(f.host)} | ${escapeHtml(f.scanner)}</div>
                    </div>
                    ${timeAgo ? `<span class="text-xs text-gray-500 shrink-0">${timeAgo}</span>` : ''}
                </div>
                ${f.cve_ids?.length ? `
                    <div class="mt-1 flex flex-wrap gap-1">
                        ${f.cve_ids.slice(0, 3).map(cve => `<span class="text-xs text-cyan-400">${cve}</span>`).join('')}
                        ${f.cve_ids.length > 3 ? `<span class="text-xs text-gray-500">+${f.cve_ids.length - 3}</span>` : ''}
                    </div>
                ` : ''}
            </div>
        `;
    }).join('');
}

function formatDuration(seconds) {
    if (!seconds || seconds < 1) return '<1s';
    if (seconds < 60) return `${Math.round(seconds)}s`;
    if (seconds < 3600) {
        const mins = Math.floor(seconds / 60);
        const secs = Math.round(seconds % 60);
        return secs > 0 ? `${mins}m ${secs}s` : `${mins}m`;
    }
    const hours = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    return mins > 0 ? `${hours}h ${mins}m` : `${hours}h`;
}

async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        showNotification('Copied to clipboard', 'success');
    } catch (err) {
        // Fallback for older browsers
        const textarea = document.createElement('textarea');
        textarea.value = text;
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
        showNotification('Copied to clipboard', 'success');
    }
}

let advVulnScanMode = 'web';

function toggleScanMode(mode) {
    advVulnScanMode = mode;
    const webBtn = document.getElementById('scan-mode-web');
    const apiBtn = document.getElementById('scan-mode-api');
    const apiFields = document.getElementById('api-scan-fields');

    if (mode === 'api') {
        webBtn?.classList.remove('bg-blue-600', 'text-white', 'font-medium');
        webBtn?.classList.add('text-gray-400');
        apiBtn?.classList.add('bg-blue-600', 'text-white', 'font-medium');
        apiBtn?.classList.remove('text-gray-400');
        apiFields?.classList.remove('hidden');
    } else {
        apiBtn?.classList.remove('bg-blue-600', 'text-white', 'font-medium');
        apiBtn?.classList.add('text-gray-400');
        webBtn?.classList.add('bg-blue-600', 'text-white', 'font-medium');
        webBtn?.classList.remove('text-gray-400');
        apiFields?.classList.add('hidden');
    }
}

function setScanStrength(strength) {
    document.getElementById('zap-scan-strength').value = strength;
    const descriptions = {
        standard: 'Balanced speed and coverage. Suitable for most scans.',
        thorough: 'Extended coverage with custom fuzzing. 2-3x longer scan time.',
        insane: 'Maximum coverage with aggressive fuzzing. 5-10x longer. May cause target instability.'
    };
    document.getElementById('strength-description').textContent = descriptions[strength] || '';

    ['standard', 'thorough', 'insane'].forEach(s => {
        const btn = document.getElementById('strength-' + s);
        if (s === strength) {
            btn?.classList.add('bg-blue-600', 'text-white', 'font-medium');
            btn?.classList.remove('text-gray-400');
        } else {
            btn?.classList.remove('bg-blue-600', 'text-white', 'font-medium');
            btn?.classList.add('text-gray-400');
        }
    });
}

function toggleRequestBodyField() {
    const method = document.getElementById('api-http-method')?.value;
    const bodyContainer = document.getElementById('api-request-body-container');
    if (!bodyContainer) return;

    const methodsWithBody = ['POST', 'PUT', 'PATCH', 'DELETE'];
    if (methodsWithBody.includes(method)) {
        bodyContainer.classList.remove('hidden');
    } else {
        bodyContainer.classList.add('hidden');
    }
}

async function startAdvancedScan() {
    const targetInput = document.getElementById('adv-vuln-target');
    const scannerSelect = document.getElementById('adv-vuln-scanner');

    if (!targetInput || !scannerSelect) return;

    const target = targetInput.value.trim();
    const scanType = scannerSelect.value;

    if (!target) {
        showNotification('Please enter a target IP or URL', 'warning');
        return;
    }

    // Collect scan strength
    const strengthSelect = document.getElementById('zap-scan-strength');
    const scanStrength = strengthSelect ? strengthSelect.value : 'standard';

    // Collect auth params directly to send with the scan request
    const authType = document.getElementById('zap-auth-type')?.value;
    const options = { scan_strength: scanStrength };

    if (authType) {
        const authParams = getAuthParams(authType);
        if (authParams === null) return; // Validation failed

        // Pass auth params directly in options
        options.auth_type = authType;
        options.auth_params = authParams;
    }

    // Collect API scan mode params
    if (advVulnScanMode === 'api') {
        options.scan_mode = 'api';
        options.http_method = document.getElementById('api-http-method')?.value || 'GET';

        const headersText = document.getElementById('api-custom-headers')?.value.trim();
        if (headersText) {
            options.custom_headers = headersText;
        }

        const bodyText = document.getElementById('api-request-body')?.value.trim();
        if (bodyText) {
            options.request_body = bodyText;
        }

        const openApiUrl = document.getElementById('zap-openapi-url')?.value.trim();
        if (openApiUrl) {
            options.openapi_url = openApiUrl;
        }
    }

    try {
        const response = await fetch('/api/vuln-advanced/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, scan_type: scanType, options })
        });

        const data = await response.json();

        if (data.success) {
            showNotification(`Started ${scanType} scan: ${data.scan_id}`, 'success');
            targetInput.value = '';

            // Start polling for updates
            startAdvVulnPolling();

        } else {
            showNotification(data.error || 'Failed to start scan', 'error');
        }

    } catch (error) {
        console.error('Error starting advanced scan:', error);
        showNotification('Failed to start scan', 'error');
    }
}

/**
 * Collect and validate auth parameters based on auth type
 * Returns auth params object or null if validation fails
 */
function getAuthParams(authType) {
    const loginUrl = document.getElementById('zap-login-url')?.value.trim();
    const username = document.getElementById('zap-username')?.value.trim();
    const password = document.getElementById('zap-password')?.value.trim();
    const loginData = document.getElementById('zap-login-data')?.value.trim();
    const bearerToken = document.getElementById('zap-bearer-token')?.value.trim();
    const apiKey = document.getElementById('zap-api-key')?.value.trim();
    const apiKeyHeader = document.getElementById('zap-api-key-header')?.value.trim() || 'X-API-Key';
    const cookieValue = document.getElementById('zap-cookie-value')?.value.trim();
    const waitForUrl = document.getElementById('zap-wait-for-url')?.value.trim();
    const loginPageWait = document.getElementById('zap-login-page-wait')?.value || '5';
    const scriptName = document.getElementById('zap-script-name')?.value.trim();

    const authParams = {};

    if (authType === 'form') {
        if (!username || !password) {
            showNotification('Please enter username and password', 'warning');
            return null;
        }
        if (!loginUrl) {
            showNotification('Login URL is required for form authentication', 'warning');
            return null;
        }
        authParams.username = username;
        authParams.password = password;
        authParams.login_url = loginUrl;
        authParams.login_request_data = loginData || `username={%username%}&password={%password%}`;
    } else if (authType === 'http_basic') {
        if (!username || !password) {
            showNotification('Please enter username and password', 'warning');
            return null;
        }
        authParams.username = username;
        authParams.password = password;
        authParams.http_basic_auth = `${username}:${password}`;
    } else if (authType === 'oauth2_bba') {
        if (!username || !password) {
            showNotification('Please enter username and password for OAuth2 login', 'warning');
            return null;
        }
        if (!loginUrl) {
            showNotification('Login URL is required for OAuth2/BBA authentication', 'warning');
            return null;
        }
        authParams.username = username;
        authParams.password = password;
        authParams.login_url = loginUrl;
        authParams.wait_for_url = waitForUrl || '';
        authParams.login_page_wait = parseInt(loginPageWait) || 5;
    } else if (authType === 'script_auth') {
        if (!username || !password) {
            showNotification('Please enter username and password for script authentication', 'warning');
            return null;
        }
        if (!loginUrl) {
            showNotification('Login URL is required for script-based authentication', 'warning');
            return null;
        }
        authParams.username = username;
        authParams.password = password;
        authParams.login_url = loginUrl;
        authParams.script_name = scriptName || '';
    } else if (authType === 'oauth2_client_creds') {
        const clientId = document.getElementById('zap-oauth2-client-id')?.value.trim();
        const clientSecret = document.getElementById('zap-oauth2-client-secret')?.value.trim();
        const tokenUrl = document.getElementById('zap-oauth2-token-url')?.value.trim();
        const scope = document.getElementById('zap-oauth2-scope')?.value.trim();
        if (!clientId || !clientSecret) {
            showNotification('Please enter Client ID and Client Secret', 'warning');
            return null;
        }
        if (!tokenUrl) {
            showNotification('Token URL is required for OAuth2 Client Credentials', 'warning');
            return null;
        }
        authParams.client_id = clientId;
        authParams.client_secret = clientSecret;
        authParams.token_url = tokenUrl;
        if (scope) authParams.scope = scope;
    } else if (authType === 'bearer_token') {
        if (!bearerToken) {
            showNotification('Please enter a bearer token', 'warning');
            return null;
        }
        authParams.bearer_token = bearerToken;
    } else if (authType === 'api_key') {
        if (!apiKey) {
            showNotification('Please enter an API key', 'warning');
            return null;
        }
        authParams.api_key = apiKey;
        authParams.api_key_header = apiKeyHeader;
    } else if (authType === 'cookie') {
        if (!cookieValue) {
            showNotification('Please enter a cookie string', 'warning');
            return null;
        }
        authParams.cookie_value = cookieValue;
    }

    return authParams;
}

function startAdvVulnPolling() {
    if (advVulnRefreshInterval) {
        clearInterval(advVulnRefreshInterval);
    }

    // Poll every 2 seconds for better real-time feedback during scans
    advVulnRefreshInterval = setInterval(async () => {
        if (currentTab !== 'adv-vuln') {
            clearInterval(advVulnRefreshInterval);
            advVulnRefreshInterval = null;
            return;
        }
        await refreshAdvVulnData();

        // Fetch logs for any expanded log panels
        for (const scanId of advVulnExpandedLogIds) {
            fetchScanLogs(scanId);
        }

        // Auto-stop polling if no scans are running anymore
        const stillRunning = (advVulnScansCache || []).some(s => s.status === 'running');
        if (!stillRunning) {
            clearInterval(advVulnRefreshInterval);
            advVulnRefreshInterval = null;
        }
    }, 2000);
}

async function refreshAdvVulnData() {
    await loadAdvancedVulnData();
}

// ============================================================================
// OWASP ZAP CONTROL FUNCTIONS
// ============================================================================

function updateZapControlPanel(scanners) {
    const panel = document.getElementById('zap-control-panel');
    const daemonStatus = document.getElementById('zap-daemon-status');
    const startBtn = document.getElementById('zap-start-btn');
    const stopBtn = document.getElementById('zap-stop-btn');

    if (!panel) return;

    // Show/hide panel based on ZAP availability
    if (!scanners.zap) {
        panel.classList.add('opacity-50');
        if (daemonStatus) {
            daemonStatus.textContent = 'Not Installed';
            daemonStatus.className = 'text-xs px-2 py-1 rounded-full bg-gray-700 text-gray-400';
        }
        return;
    }

    panel.classList.remove('opacity-50');

    if (scanners.zap_running) {
        if (daemonStatus) {
            daemonStatus.textContent = 'Running';
            daemonStatus.className = 'text-xs px-2 py-1 rounded-full bg-green-900 text-green-400';
        }
        if (startBtn) startBtn.disabled = true;
        if (stopBtn) stopBtn.disabled = false;
    } else {
        if (daemonStatus) {
            daemonStatus.textContent = 'Stopped';
            daemonStatus.className = 'text-xs px-2 py-1 rounded-full bg-slate-700 text-gray-400';
        }
        if (startBtn) startBtn.disabled = false;
        if (stopBtn) stopBtn.disabled = true;
    }

    // Fetch detailed ZAP status if running
    if (scanners.zap_running) {
        fetchZapStatus();
    }
}

async function fetchZapStatus() {
    try {
        const response = await fetch('/api/zap/status');
        const data = await response.json();

        if (data.success && data.status) {
            updateElement('zap-hosts-count', data.status.hosts_accessed || 0);
            updateElement('zap-alerts-count', data.status.alerts_count || 0);

            // Also check auth status when ZAP is running
            if (data.status.running) {
                zapCheckAuthStatus();
            }
        }
    } catch (error) {
        console.error('Error fetching ZAP status:', error);
    }
}

async function startZapDaemon() {
    try {
        showNotification('Starting ZAP daemon...', 'info');

        const response = await fetch('/api/zap/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        const data = await response.json();

        if (data.success) {
            showNotification('ZAP daemon started successfully', 'success');
            await refreshAdvVulnData();
        } else {
            showNotification(data.error || 'Failed to start ZAP daemon', 'error');
        }
    } catch (error) {
        console.error('Error starting ZAP daemon:', error);
        showNotification('Failed to start ZAP daemon', 'error');
    }
}

async function stopZapDaemon() {
    try {
        showNotification('Stopping ZAP daemon...', 'info');

        const response = await fetch('/api/zap/stop', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        const data = await response.json();

        if (data.success) {
            showNotification('ZAP daemon stopped', 'success');
            await refreshAdvVulnData();
        } else {
            showNotification(data.error || 'Failed to stop ZAP daemon', 'error');
        }
    } catch (error) {
        console.error('Error stopping ZAP daemon:', error);
        showNotification('Failed to stop ZAP daemon', 'error');
    }
}

async function zapClearSession() {
    try {
        const response = await fetch('/api/zap/clear-session', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        const data = await response.json();

        if (data.success) {
            showNotification('ZAP session cleared', 'success');
            await fetchZapStatus();
        } else {
            showNotification(data.error || 'Failed to clear ZAP session', 'error');
        }
    } catch (error) {
        console.error('Error clearing ZAP session:', error);
        showNotification('Failed to clear ZAP session', 'error');
    }
}

async function zapImportOpenAPI() {
    const urlInput = document.getElementById('zap-openapi-url');
    if (!urlInput) return;

    const specUrl = urlInput.value.trim();
    if (!specUrl) {
        showNotification('Please enter an OpenAPI/Swagger URL', 'warning');
        return;
    }

    const targetInput = document.getElementById('adv-vuln-target');
    const targetUrl = targetInput ? targetInput.value.trim() : '';

    try {
        const payload = { spec_url: specUrl };
        if (targetUrl) {
            payload.target_url = targetUrl;
        }
        const response = await fetch('/api/zap/import-openapi', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const data = await response.json();

        if (data.success) {
            showNotification('OpenAPI spec imported successfully', 'success');
            urlInput.value = '';
        } else {
            showNotification(data.error || 'Failed to import OpenAPI spec', 'error');
        }
    } catch (error) {
        console.error('Error importing OpenAPI spec:', error);
        showNotification('Failed to import OpenAPI spec', 'error');
    }
}

// zapSetAuthentication is no longer used - auth is passed directly with each scan request
// Keeping as a no-op for backwards compatibility
async function zapSetAuthentication() {
    return true;
}

/**
 * Check ZAP authentication status - simplified since auth is now per-scan
 */
async function zapCheckAuthStatus() {
    const banner = document.getElementById('zap-auth-status-banner');
    const clearBtn = document.getElementById('zap-clear-auth-btn');

    // Hide the auth banner - auth is now sent with each scan, not persisted
    if (banner) banner.classList.add('hidden');
    if (clearBtn) clearBtn.classList.add('hidden');
}

/**
 * Clear ZAP authentication configuration - no longer needed but kept for compatibility
 */
async function zapClearAuthentication() {
    showNotification('Auth is now per-scan - no persistent auth to clear', 'info');
}

// ============================================================================
// TARGET CREDENTIAL MANAGEMENT FUNCTIONS
// ============================================================================

// Cache for credential check results (to avoid excessive API calls)
let _credentialCheckCache = {};
let _credentialCheckTimeout = null;

/**
 * Check if credentials exist for a target (debounced)
 */
function checkTargetCredentials(target) {
    if (!target || target.length < 3) {
        hideCredentialBadge();
        return;
    }

    // Debounce the check
    if (_credentialCheckTimeout) {
        clearTimeout(_credentialCheckTimeout);
    }

    _credentialCheckTimeout = setTimeout(async () => {
        await _doCredentialCheck(target);
    }, 500);
}

async function _doCredentialCheck(target) {
    // Check cache first
    const cacheKey = target.toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
    if (_credentialCheckCache[cacheKey] !== undefined) {
        updateCredentialBadge(_credentialCheckCache[cacheKey]);
        return;
    }

    try {
        const response = await fetch(`/api/zap/credentials/check?target=${encodeURIComponent(target)}`);
        const data = await response.json();

        _credentialCheckCache[cacheKey] = data;
        updateCredentialBadge(data);
    } catch (error) {
        console.error('Error checking target credentials:', error);
        hideCredentialBadge();
    }
}

function updateCredentialBadge(data) {
    const badge = document.getElementById('target-cred-badge');
    const infoDiv = document.getElementById('target-cred-info');
    const infoText = document.getElementById('target-cred-text');

    if (!badge || !infoDiv) return;

    if (data.exists) {
        badge.classList.remove('hidden');
        infoDiv.classList.remove('hidden');

        const authType = data.auth_type === 'form' ? 'Form-based' :
                        data.auth_type === 'http_basic' ? 'HTTP Basic' : data.auth_type;
        const username = data.username || '(no username)';

        if (infoText) {
            infoText.textContent = `Auth saved: ${authType} login as "${username}"`;
        }
    } else {
        hideCredentialBadge();
    }
}

function hideCredentialBadge() {
    const badge = document.getElementById('target-cred-badge');
    const infoDiv = document.getElementById('target-cred-info');

    if (badge) badge.classList.add('hidden');
    if (infoDiv) infoDiv.classList.add('hidden');
}

/**
 * Show the credentials management modal
 */
function showCredentialsModal() {
    const modal = document.getElementById('zap-credentials-modal');
    if (modal) {
        modal.classList.remove('hidden');
        modal.classList.add('flex');

        // Pre-fill target from scan input if available
        const targetInput = document.getElementById('adv-vuln-target');
        const credTargetInput = document.getElementById('cred-target-host');
        if (targetInput && credTargetInput && targetInput.value) {
            credTargetInput.value = targetInput.value.replace(/^https?:\/\//, '').split('/')[0];
        }

        // Load saved credentials list
        loadSavedCredentialsList();
    }
}

function closeCredentialsModal() {
    const modal = document.getElementById('zap-credentials-modal');
    if (modal) {
        modal.classList.add('hidden');
        modal.classList.remove('flex');
    }
}

/**
 * Toggle credential form fields based on auth type
 */
function toggleCredentialFields() {
    const authType = document.getElementById('cred-auth-type');
    const loginUrlContainer = document.getElementById('cred-login-url-container');
    const realmContainer = document.getElementById('cred-realm-container');
    const usernameContainer = document.getElementById('cred-username-container');
    const passwordContainer = document.getElementById('cred-password-container');
    const loginDataContainer = document.getElementById('cred-login-data-container');
    const bearerTokenContainer = document.getElementById('cred-bearer-token-container');
    const apiKeyContainer = document.getElementById('cred-api-key-container');
    const apiKeyHeaderContainer = document.getElementById('cred-api-key-header-container');
    const cookieContainer = document.getElementById('cred-cookie-container');

    if (!authType) return;

    const type = authType.value;

    // Hide all optional containers first
    if (loginUrlContainer) loginUrlContainer.classList.add('hidden');
    if (realmContainer) realmContainer.classList.add('hidden');
    if (usernameContainer) usernameContainer.classList.add('hidden');
    if (passwordContainer) passwordContainer.classList.add('hidden');
    if (loginDataContainer) loginDataContainer.classList.add('hidden');
    if (bearerTokenContainer) bearerTokenContainer.classList.add('hidden');
    if (apiKeyContainer) apiKeyContainer.classList.add('hidden');
    if (apiKeyHeaderContainer) apiKeyHeaderContainer.classList.add('hidden');
    if (cookieContainer) cookieContainer.classList.add('hidden');

    // Show relevant fields based on auth type
    if (type === 'form') {
        if (loginUrlContainer) loginUrlContainer.classList.remove('hidden');
        if (usernameContainer) usernameContainer.classList.remove('hidden');
        if (passwordContainer) passwordContainer.classList.remove('hidden');
        if (loginDataContainer) loginDataContainer.classList.remove('hidden');
    } else if (type === 'http_basic') {
        if (realmContainer) realmContainer.classList.remove('hidden');
        if (usernameContainer) usernameContainer.classList.remove('hidden');
        if (passwordContainer) passwordContainer.classList.remove('hidden');
    } else if (type === 'oauth2_bba') {
        // OAuth2 / Microsoft Login (Browser-Based Authentication)
        if (loginUrlContainer) loginUrlContainer.classList.remove('hidden');
        if (usernameContainer) usernameContainer.classList.remove('hidden');
        if (passwordContainer) passwordContainer.classList.remove('hidden');
    } else if (type === 'script_auth') {
        // Script-Based Authentication
        if (loginUrlContainer) loginUrlContainer.classList.remove('hidden');
        if (usernameContainer) usernameContainer.classList.remove('hidden');
        if (passwordContainer) passwordContainer.classList.remove('hidden');
    } else if (type === 'bearer_token') {
        if (bearerTokenContainer) bearerTokenContainer.classList.remove('hidden');
    } else if (type === 'api_key') {
        if (apiKeyContainer) apiKeyContainer.classList.remove('hidden');
        if (apiKeyHeaderContainer) apiKeyHeaderContainer.classList.remove('hidden');
    } else if (type === 'cookie') {
        if (cookieContainer) cookieContainer.classList.remove('hidden');
    }
    // 'none' - all fields stay hidden
}

/**
 * Toggle scan form auth fields based on selected auth type
 */
function toggleScanAuthFields() {
    const authType = document.getElementById('zap-auth-type');
    const authFieldsWrapper = document.getElementById('zap-auth-fields-wrapper');
    const loginUrlContainer = document.getElementById('zap-login-url-container');
    const usernameContainer = document.getElementById('zap-username-container');
    const passwordContainer = document.getElementById('zap-password-container');
    const loginDataContainer = document.getElementById('zap-login-data-container');
    const bearerTokenContainer = document.getElementById('zap-bearer-token-container');
    const apiKeyContainer = document.getElementById('zap-api-key-container');
    const apiKeyHeaderContainer = document.getElementById('zap-api-key-header-container');
    const cookieContainer = document.getElementById('zap-cookie-container');
    const oauth2BbaContainer = document.getElementById('zap-oauth2-bba-container');
    const oauth2CcContainer = document.getElementById('zap-oauth2-cc-container');
    const scriptAuthContainer = document.getElementById('zap-script-auth-container');

    if (!authType) return;

    const type = authType.value;

    // Hide all optional containers first
    if (loginUrlContainer) loginUrlContainer.classList.add('hidden');
    if (usernameContainer) usernameContainer.classList.add('hidden');
    if (passwordContainer) passwordContainer.classList.add('hidden');
    if (loginDataContainer) loginDataContainer.classList.add('hidden');
    if (bearerTokenContainer) bearerTokenContainer.classList.add('hidden');
    if (apiKeyContainer) apiKeyContainer.classList.add('hidden');
    if (apiKeyHeaderContainer) apiKeyHeaderContainer.classList.add('hidden');
    if (cookieContainer) cookieContainer.classList.add('hidden');
    if (oauth2BbaContainer) oauth2BbaContainer.classList.add('hidden');
    if (oauth2CcContainer) oauth2CcContainer.classList.add('hidden');
    if (scriptAuthContainer) scriptAuthContainer.classList.add('hidden');

    // Hide/show the auth fields wrapper based on whether an auth type is selected
    if (!type) {
        if (authFieldsWrapper) authFieldsWrapper.classList.add('hidden');
        return;
    }
    if (authFieldsWrapper) authFieldsWrapper.classList.remove('hidden');

    // Show relevant fields based on auth type
    if (type === 'form') {
        if (loginUrlContainer) loginUrlContainer.classList.remove('hidden');
        if (usernameContainer) usernameContainer.classList.remove('hidden');
        if (passwordContainer) passwordContainer.classList.remove('hidden');
        if (loginDataContainer) loginDataContainer.classList.remove('hidden');
    } else if (type === 'http_basic') {
        if (usernameContainer) usernameContainer.classList.remove('hidden');
        if (passwordContainer) passwordContainer.classList.remove('hidden');
    } else if (type === 'oauth2_bba') {
        if (loginUrlContainer) loginUrlContainer.classList.remove('hidden');
        if (usernameContainer) usernameContainer.classList.remove('hidden');
        if (passwordContainer) passwordContainer.classList.remove('hidden');
        if (oauth2BbaContainer) oauth2BbaContainer.classList.remove('hidden');
    } else if (type === 'oauth2_client_creds') {
        if (oauth2CcContainer) oauth2CcContainer.classList.remove('hidden');
    } else if (type === 'script_auth') {
        if (loginUrlContainer) loginUrlContainer.classList.remove('hidden');
        if (usernameContainer) usernameContainer.classList.remove('hidden');
        if (passwordContainer) passwordContainer.classList.remove('hidden');
        if (scriptAuthContainer) scriptAuthContainer.classList.remove('hidden');
    } else if (type === 'bearer_token') {
        if (bearerTokenContainer) bearerTokenContainer.classList.remove('hidden');
    } else if (type === 'api_key') {
        if (apiKeyContainer) apiKeyContainer.classList.remove('hidden');
        if (apiKeyHeaderContainer) apiKeyHeaderContainer.classList.remove('hidden');
    } else if (type === 'cookie') {
        if (cookieContainer) cookieContainer.classList.remove('hidden');
    }
}

/**
 * Save credentials for a target
 */
async function saveTargetCredentials() {
    const targetHost = document.getElementById('cred-target-host')?.value?.trim();
    const authType = document.getElementById('cred-auth-type')?.value;
    const loginUrl = document.getElementById('cred-login-url')?.value?.trim();
    const username = document.getElementById('cred-username')?.value?.trim();
    const password = document.getElementById('cred-password')?.value;
    const loginData = document.getElementById('cred-login-data')?.value?.trim();
    const httpRealm = document.getElementById('cred-http-realm')?.value?.trim();
    const notes = document.getElementById('cred-notes')?.value?.trim();
    const bearerToken = document.getElementById('cred-bearer-token')?.value?.trim();
    const apiKey = document.getElementById('cred-api-key')?.value?.trim();
    const apiKeyHeader = document.getElementById('cred-api-key-header')?.value?.trim() || 'X-API-Key';
    const cookieValue = document.getElementById('cred-cookie-value')?.value?.trim();

    if (!targetHost) {
        showNotification('Target host is required', 'warning');
        return;
    }

    // Validate required fields based on auth type
    if (authType === 'form' || authType === 'http_basic' || authType === 'oauth2_bba' || authType === 'script_auth') {
        if (!username || !password) {
            showNotification('Username and password are required', 'warning');
            return;
        }
        if ((authType === 'oauth2_bba' || authType === 'script_auth') && !loginUrl) {
            showNotification('Login URL is required for OAuth2/BBA or Script-based authentication', 'warning');
            return;
        }
    } else if (authType === 'bearer_token') {
        if (!bearerToken) {
            showNotification('Bearer token is required', 'warning');
            return;
        }
    } else if (authType === 'api_key') {
        if (!apiKey) {
            showNotification('API key is required', 'warning');
            return;
        }
    } else if (authType === 'cookie') {
        if (!cookieValue) {
            showNotification('Cookie string is required', 'warning');
            return;
        }
    }

    try {
        const response = await fetch('/api/zap/credentials', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target_host: targetHost,
                auth_type: authType,
                login_url: loginUrl,
                username: username,
                password: password,
                login_request_data: loginData,
                http_realm: httpRealm,
                notes: notes,
                bearer_token: bearerToken,
                api_key: apiKey,
                api_key_header: apiKeyHeader,
                cookie_value: cookieValue
            })
        });

        const data = await response.json();

        if (data.success) {
            showNotification(data.message || 'Credentials saved successfully', 'success');
            clearCredentialForm();
            loadSavedCredentialsList();

            // Clear cache so the badge updates
            _credentialCheckCache = {};

            // Re-check the current target
            const targetInput = document.getElementById('adv-vuln-target');
            if (targetInput && targetInput.value) {
                checkTargetCredentials(targetInput.value);
            }
        } else {
            showNotification(data.error || 'Failed to save credentials', 'error');
        }
    } catch (error) {
        console.error('Error saving credentials:', error);
        showNotification('Failed to save credentials', 'error');
    }
}

/**
 * Clear the credential form
 */
function clearCredentialForm() {
    const fields = ['cred-target-host', 'cred-login-url', 'cred-username', 'cred-password',
                    'cred-login-data', 'cred-http-realm', 'cred-notes', 'cred-bearer-token',
                    'cred-api-key', 'cred-cookie-value'];
    fields.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.value = '';
    });

    // Reset API key header to default
    const apiKeyHeader = document.getElementById('cred-api-key-header');
    if (apiKeyHeader) apiKeyHeader.value = 'X-API-Key';

    const authType = document.getElementById('cred-auth-type');
    if (authType) authType.value = 'form';

    toggleCredentialFields();
}

/**
 * Load the list of saved credentials
 */
async function loadSavedCredentialsList() {
    const listContainer = document.getElementById('saved-credentials-list');
    if (!listContainer) return;

    listContainer.innerHTML = '<div class="text-gray-400 text-sm text-center py-4">Loading...</div>';

    try {
        const response = await fetch('/api/zap/credentials');
        const data = await response.json();

        if (data.success && data.credentials && data.credentials.length > 0) {
            let html = '';
            for (const cred of data.credentials) {
                let authTypeBadge;
                switch (cred.auth_type) {
                    case 'form':
                        authTypeBadge = '<span class="px-2 py-0.5 bg-blue-600 text-xs rounded">Form</span>';
                        break;
                    case 'http_basic':
                        authTypeBadge = '<span class="px-2 py-0.5 bg-purple-600 text-xs rounded">HTTP Basic</span>';
                        break;
                    case 'bearer_token':
                        authTypeBadge = '<span class="px-2 py-0.5 bg-green-600 text-xs rounded">Bearer Token</span>';
                        break;
                    case 'api_key':
                        authTypeBadge = '<span class="px-2 py-0.5 bg-yellow-600 text-xs rounded">API Key</span>';
                        break;
                    case 'cookie':
                        authTypeBadge = '<span class="px-2 py-0.5 bg-orange-600 text-xs rounded">Cookie</span>';
                        break;
                    default:
                        authTypeBadge = '<span class="px-2 py-0.5 bg-gray-600 text-xs rounded">None</span>';
                }

                html += `
                    <div class="flex items-center justify-between p-3 bg-slate-800 rounded-lg">
                        <div class="flex-1">
                            <div class="flex items-center gap-2">
                                <span class="font-mono text-sm text-white">${escapeHtml(cred.target_host)}</span>
                                ${authTypeBadge}
                            </div>
                            <div class="text-xs text-gray-400 mt-1">
                                ${cred.username ? `User: ${escapeHtml(cred.username)}` :
                                  cred.auth_type === 'bearer_token' ? 'Token configured' :
                                  cred.auth_type === 'api_key' ? `Header: ${escapeHtml(cred.api_key_header || 'X-API-Key')}` :
                                  cred.auth_type === 'cookie' ? 'Cookie configured' : 'No username'}
                                ${cred.notes ? ` | ${escapeHtml(cred.notes)}` : ''}
                            </div>
                        </div>
                        <div class="flex gap-2">
                            <button onclick="editTargetCredential('${escapeHtml(cred.target_host)}')"
                                    class="text-blue-400 hover:text-blue-300 text-sm" title="Edit">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path>
                                </svg>
                            </button>
                            <button onclick="deleteTargetCredential('${escapeHtml(cred.target_host)}')"
                                    class="text-red-400 hover:text-red-300 text-sm" title="Delete">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path>
                                </svg>
                            </button>
                        </div>
                    </div>
                `;
            }
            listContainer.innerHTML = html;
        } else {
            listContainer.innerHTML = '<div class="text-gray-400 text-sm text-center py-4">No saved credentials. Add credentials above to use authenticated ZAP scans.</div>';
        }
    } catch (error) {
        console.error('Error loading credentials:', error);
        listContainer.innerHTML = '<div class="text-red-400 text-sm text-center py-4">Failed to load credentials</div>';
    }
}

/**
 * Edit credentials for a target (loads into form)
 */
async function editTargetCredential(targetHost) {
    try {
        const response = await fetch(`/api/zap/credentials/${encodeURIComponent(targetHost)}`);
        const data = await response.json();

        if (data.success && data.credentials) {
            const cred = data.credentials;

            document.getElementById('cred-target-host').value = cred.target_host || '';
            document.getElementById('cred-auth-type').value = cred.auth_type || 'form';
            document.getElementById('cred-login-url').value = cred.login_url || '';
            document.getElementById('cred-username').value = cred.username || '';
            document.getElementById('cred-password').value = cred.password || '';
            document.getElementById('cred-login-data').value = cred.login_request_data || '';
            document.getElementById('cred-http-realm').value = cred.http_realm || '';
            document.getElementById('cred-notes').value = cred.notes || '';
            document.getElementById('cred-bearer-token').value = cred.bearer_token || '';
            document.getElementById('cred-api-key').value = cred.api_key || '';
            document.getElementById('cred-api-key-header').value = cred.api_key_header || 'X-API-Key';
            document.getElementById('cred-cookie-value').value = cred.cookie_value || '';

            toggleCredentialFields();

            // Scroll to form
            document.getElementById('cred-target-host')?.scrollIntoView({ behavior: 'smooth', block: 'center' });
            showNotification('Loaded credentials for editing', 'info');
        } else {
            showNotification('Failed to load credentials', 'error');
        }
    } catch (error) {
        console.error('Error loading credential for edit:', error);
        showNotification('Failed to load credentials', 'error');
    }
}

/**
 * Delete credentials for a target
 */
async function deleteTargetCredential(targetHost) {
    if (!confirm(`Delete saved credentials for "${targetHost}"?`)) {
        return;
    }

    try {
        const response = await fetch(`/api/zap/credentials/${encodeURIComponent(targetHost)}`, {
            method: 'DELETE'
        });

        const data = await response.json();

        if (data.success) {
            showNotification(data.message || 'Credentials deleted', 'success');
            loadSavedCredentialsList();

            // Clear cache
            _credentialCheckCache = {};

            // Re-check current target
            const targetInput = document.getElementById('adv-vuln-target');
            if (targetInput && targetInput.value) {
                checkTargetCredentials(targetInput.value);
            }
        } else {
            showNotification(data.error || 'Failed to delete credentials', 'error');
        }
    } catch (error) {
        console.error('Error deleting credentials:', error);
        showNotification('Failed to delete credentials', 'error');
    }
}

// ── Network Map (D3 force graph with topology API) ──────────────
let _mapSimulation = null;
let _mapInitialized = false;
let _mapAiAvailable = false;   // AI service ready on server
let _mapAiEnabled = false;     // user toggle state
let _mapNetworkHash = null;    // last-known host fingerprint for change detection
let _mapAiCacheValid = false;  // true when AI results are cached for current hash

function riskColor(score) {
    if (score === 0) return '#64748b';
    if (score <= 3) return '#22c55e';
    if (score <= 8) return '#f59e0b';
    return '#ef4444';
}

function _buildMapLegend(deviceColors, deviceLabels) {
    const el = document.getElementById('map-legend');
    if (!el) return;
    el.innerHTML = '';
    const order = ['router', 'access_point', 'extender', 'switch', 'ragnar', 'laptop', 'workstation', 'server', 'nas', 'sbc', 'phone', 'tablet', 'wearable', 'printer', 'camera', 'smart_tv', 'speaker', 'doorbell', 'thermostat', 'appliance', 'iot', 'media', 'gaming', 'vehicle', 'apple', 'unknown'];
    order.forEach(t => {
        const color = deviceColors[t];
        const label = deviceLabels[t];
        if (!color || !label) return;
        const span = document.createElement('span');
        span.className = 'flex items-center gap-1';
        span.innerHTML = `<span class="inline-block w-3 h-3 rounded-full" style="background:${color}"></span> ${escapeHtml(label)}`;
        el.appendChild(span);
    });
}

// ── AI toggle helpers ──
async function _checkMapAiStatus() {
    try {
        const resp = await networkAwareFetch('/api/ai/status');
        const data = await resp.json();
        // enabled=true means the AI service is up and working
        // config_enabled=true means the user wants AI on
        // Either field being true is sufficient — if AI Insights works, so should classification
        _mapAiAvailable = !!(data.enabled || (data.config_enabled && data.configured));
        const track = document.getElementById('map-ai-toggle-track');
        if (track) {
            if (_mapAiAvailable) {
                track.classList.remove('disabled');
            } else {
                track.classList.add('disabled');
                track.classList.remove('active');
                _mapAiEnabled = false;
            }
        }
        const wrapper = document.getElementById('map-ai-toggle-wrapper');
        if (wrapper) {
            wrapper.title = _mapAiAvailable ? 'Use GPT-5 Nano to improve device classification' : 'AI not available – enable in Settings';
        }
    } catch(e) { console.warn('AI status check failed:', e); _mapAiAvailable = false; }
}

function onMapAiToggleClick() {
    if (!_mapAiAvailable) return;
    const track = document.getElementById('map-ai-toggle-track');
    if (!track) return;
    _mapAiEnabled = !_mapAiEnabled;
    track.classList.toggle('active', _mapAiEnabled);
    if (_mapAiEnabled) {
        _mapAiCacheValid = false;
        refreshNetworkMap();
    }
}

function _showMapAiSpinner(show) {
    const el = document.getElementById('map-ai-spinner');
    if (el) el.classList.toggle('hidden', !show);
}

async function loadNetworkMap() {
    if (typeof d3 === 'undefined') {
        document.getElementById('network-map-loading').innerHTML = '<p class="text-red-400">D3.js failed to load. Check your internet connection.</p>';
        return;
    }

    // Check AI availability on first load
    if (!_mapInitialized) {
        _mapInitialized = true;     // set flag early to prevent re-entry
        await _checkMapAiStatus();
        loadScanSubnets();          // populate subnet badge / panel
    }

    document.getElementById('network-map-loading').style.display = 'flex';
    document.getElementById('network-map-svg').style.display = 'none';

    // Determine whether to ask the server for AI classification
    const wantAi = _mapAiEnabled && _mapAiAvailable;
    const useAiParam = wantAi && !_mapAiCacheValid ? '1' : '0';
    if (wantAi) _showMapAiSpinner(true);

    try {
        const resp = await networkAwareFetch(`/api/network/topology?use_ai=${useAiParam}`);
        const topo = await resp.json();
        if (topo.error) throw new Error(topo.error);

        // Track network hash for change detection
        if (topo.network_hash) {
            if (_mapNetworkHash && _mapNetworkHash !== topo.network_hash) {
                // Network changed — invalidate AI cache so next refresh re-runs AI
                _mapAiCacheValid = false;
            }
            if (topo.ai_used) {
                // Server ran AI for this response — mark cache valid
                _mapAiCacheValid = true;
            }
            _mapNetworkHash = topo.network_hash;
        }

        // Build legend
        _buildMapLegend(topo.device_colors || {}, topo.device_labels || {});

        // Build D3-compatible nodes (topology API already provides structured data)
        const nodes = topo.nodes.map(n => ({
            id: n.ip,
            ip: n.ip,
            label: n.hostname || n.ip,
            mac: n.mac,
            vendor: n.vendor,
            type: n.type,
            type_label: n.type_label,
            confidence: n.confidence,
            ports: n.ports || [],
            status: n.status,
            risk: n.risk || 0,
            last_seen: n.last_seen,
            is_gateway: n.is_gateway,
            is_ragnar: n.is_ragnar,
        }));

        const links = topo.links.map(l => ({
            source: l.source,
            target: l.target,
            type: l.type,
        }));

        renderNetworkMap(nodes, links, topo.device_colors || {}, topo.device_icons || {});
    } catch(err) {
        document.getElementById('network-map-loading').innerHTML = `<p class="text-red-400">Error loading map: ${escapeHtml(err.message)}</p>`;
    } finally {
        _showMapAiSpinner(false);
    }
}

function renderNetworkMap(nodes, links, deviceColors, deviceIcons) {
    const container = document.getElementById('network-map-container');
    const svgEl = document.getElementById('network-map-svg');
    const loading = document.getElementById('network-map-loading');
    const tooltip = document.getElementById('map-tooltip');

    if (!container || !svgEl) return;

    const W = container.clientWidth || 800;
    const H = container.clientHeight || 600;

    // Stop old simulation
    if (_mapSimulation) _mapSimulation.stop();

    // Clear old SVG
    d3.select(svgEl).selectAll('*').remove();
    svgEl.setAttribute('viewBox', `0 0 ${W} ${H}`);

    const svg = d3.select(svgEl);

    // Zoom
    const g = svg.append('g');
    svg.call(d3.zoom().scaleExtent([0.2, 4]).on('zoom', e => g.attr('transform', e.transform)));

    // Link stroke styles by type
    function linkStroke(d) {
        if (d.type === 'ap_uplink') return '#8b5cf6';
        if (d.type === 'subnet_inferred') return '#06b6d4';
        if (d.type === 'ap_inferred') return '#6366f1';
        return '#334155';
    }
    function linkDash(d) {
        if (d.type === 'ap_inferred') return '4,3';
        if (d.type === 'subnet_inferred') return '6,3';
        return null;
    }

    // Links
    const link = g.append('g')
        .selectAll('line')
        .data(links)
        .join('line')
        .attr('stroke', linkStroke)
        .attr('stroke-width', d => d.type === 'ap_uplink' ? 2 : 1.5)
        .attr('stroke-opacity', 0.6)
        .attr('stroke-dasharray', linkDash);

    // Node radius based on type
    function nodeRadius(d) {
        if (d.is_gateway) return 22;
        if (d.is_ragnar) return 20;
        if (d.type === 'access_point') return 16;
        if (d.type === 'server') return 15;
        return 13;
    }

    // Node color from device type
    function nodeColor(d) {
        return deviceColors[d.type] || deviceColors['unknown'] || '#64748b';
    }

    // Node groups
    const node = g.append('g')
        .selectAll('g')
        .data(nodes)
        .join('g')
        .attr('cursor', 'pointer')
        .call(d3.drag()
            .on('start', (event, d) => { if (!event.active) _mapSimulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
            .on('drag',  (event, d) => { d.fx = event.x; d.fy = event.y; })
            .on('end',   (event, d) => { if (!event.active) _mapSimulation.alphaTarget(0); d.fx = null; d.fy = null; }))
        .on('click', (event, d) => { if (d.ip) openHostPanel(d.ip); })
        .on('mouseover', (event, d) => {
            tooltip.classList.remove('hidden');
            const riskBadge = d.risk > 8 ? 'text-red-400' : d.risk > 3 ? 'text-amber-400' : d.risk > 0 ? 'text-green-400' : 'text-gray-400';
            tooltip.innerHTML = `<div class="font-semibold font-mono mb-1">${escapeHtml(d.ip)}</div>
                ${d.label !== d.ip ? `<div class="text-gray-400 text-xs mb-1">${escapeHtml(d.label)}</div>` : ''}
                ${d.vendor ? `<div class="text-xs text-gray-500">${escapeHtml(d.vendor)}</div>` : ''}
                <div class="text-xs mt-1"><span style="color:${nodeColor(d)}">${escapeHtml(d.type_label)}</span>${d.confidence < 0.7 ? ' <span class="text-gray-600">(low conf.)</span>' : ''}</div>
                <div class="text-xs">Status: <span class="${d.status === 'alive' ? 'text-green-400' : 'text-yellow-400'}">${escapeHtml(d.status || 'unknown')}</span></div>
                <div class="text-xs">Ports: ${d.ports.length}${d.ports.length > 0 && d.ports.length <= 8 ? ' (' + d.ports.join(', ') + ')' : ''}</div>
                <div class="text-xs">Risk: <span class="${riskBadge}">${d.risk}</span></div>
                ${d.is_gateway ? '<div class="text-xs text-amber-400 mt-1">Default Gateway</div>' : ''}
                ${d.is_ragnar ? '<div class="text-xs text-sky-400 mt-1">Ragnar Scanner</div>' : ''}
                <div class="text-xs text-blue-400 mt-1">Click to view details</div>`;
        })
        .on('mousemove', (event) => {
            const rect = container.getBoundingClientRect();
            tooltip.style.left = (event.clientX - rect.left + 12) + 'px';
            tooltip.style.top  = (event.clientY - rect.top  - 10) + 'px';
        })
        .on('mouseout', () => tooltip.classList.add('hidden'));

    // Outer ring (risk indicator)
    node.append('circle')
        .attr('r', d => nodeRadius(d) + 3)
        .attr('fill', 'none')
        .attr('stroke', d => d.risk > 8 ? '#ef4444' : d.risk > 3 ? '#f59e0b' : 'none')
        .attr('stroke-width', 2)
        .attr('stroke-opacity', 0.5);

    // Main circle
    node.append('circle')
        .attr('r', nodeRadius)
        .attr('fill', nodeColor)
        .attr('stroke', '#0f172a')
        .attr('stroke-width', 2)
        .attr('fill-opacity', 0.9);

    // Device icon (SVG path inside each node)
    node.each(function(d) {
        const iconPath = deviceIcons[d.is_ragnar ? 'ragnar' : d.type] || deviceIcons['unknown'];
        if (!iconPath) return;
        const r = nodeRadius(d);
        const iconScale = r / 16; // icons are 24x24, scale to fit in radius
        d3.select(this).append('path')
            .attr('d', iconPath)
            .attr('fill', '#0f172a')
            .attr('fill-opacity', 0.6)
            .attr('transform', `translate(${-12 * iconScale},${-12 * iconScale}) scale(${iconScale})`);
    });

    // Labels
    node.append('text')
        .attr('dy', d => nodeRadius(d) + 14)
        .attr('text-anchor', 'middle')
        .attr('fill', '#94a3b8')
        .attr('font-size', '10px')
        .text(d => {
            if (d.is_gateway) return 'Gateway';
            if (d.is_ragnar) return 'Ragnar';
            return d.label || d.ip;
        });

    // Force simulation — gateway (or first node) pinned at center
    const gatewayNode = nodes.find(n => n.is_gateway);
    if (gatewayNode) {
        gatewayNode.fx = W / 2;
        gatewayNode.fy = H / 2;
    }

    _mapSimulation = d3.forceSimulation(nodes)
        .force('link', d3.forceLink(links).id(d => d.id).distance(d => {
            if (d.type === 'ap_uplink') return 80;
            return 120;
        }))
        .force('charge', d3.forceManyBody().strength(-350))
        .force('center', d3.forceCenter(W / 2, H / 2))
        .force('collision', d3.forceCollide(d => nodeRadius(d) + 15))
        .on('tick', () => {
            link
                .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
                .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
            node.attr('transform', d => `translate(${d.x},${d.y})`);
        });

    loading.style.display = 'none';
    svgEl.style.display = 'block';
}

function refreshNetworkMap() {
    _mapInitialized = false;
    loadNetworkMap();
}

// Helper function to escape HTML
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ── Subnet Manager ──────────────────────────────────────────
function toggleSubnetPanel() {
    const panel = document.getElementById('subnet-panel');
    const chevron = document.getElementById('subnet-chevron');
    if (!panel) return;
    const hidden = panel.classList.toggle('hidden');
    if (chevron) chevron.style.transform = hidden ? '' : 'rotate(90deg)';
    if (!hidden) {
        loadScanSubnets();           // refresh subnet list
        _startSubnetLogPolling();    // start live log updates
    } else {
        _stopSubnetLogPolling();     // stop polling when panel closed
    }
}

async function loadScanSubnets() {
    try {
        const resp = await networkAwareFetch('/api/config/scan-subnets');
        const data = await resp.json();

        // primary note
        const primaryEl = document.getElementById('subnet-primary');
        if (primaryEl && data.primary) {
            primaryEl.textContent = `Primary (auto-detected): ${data.primary}`;
        }

        // badge count
        const badge = document.getElementById('subnet-count');
        const subs = data.subnets || [];
        if (badge) badge.textContent = subs.length;

        // list
        const list = document.getElementById('subnet-list');
        if (!list) return;
        if (subs.length === 0) {
            list.innerHTML = '<p class="text-xs text-gray-600 italic">No extra subnets configured.</p>';
            return;
        }
        list.innerHTML = subs.map(cidr => `
            <div class="flex items-center justify-between bg-slate-700/50 rounded px-2 py-1">
                <span class="font-mono text-xs text-gray-300">${escapeHtml(cidr)}</span>
                <button onclick="removeScanSubnet('${escapeHtml(cidr)}')" class="text-red-400 hover:text-red-300 text-xs ml-2">&times;</button>
            </div>`).join('');
    } catch (e) {
        console.error('loadScanSubnets error', e);
    }
}

async function addScanSubnet() {
    const input = document.getElementById('subnet-input');
    const errorEl = document.getElementById('subnet-error');
    if (!input) return;
    const cidr = input.value.trim();
    if (!cidr) return;

    // hide previous error
    if (errorEl) { errorEl.textContent = ''; errorEl.classList.add('hidden'); }

    try {
        const resp = await networkAwareFetch('/api/config/scan-subnets', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ cidr })
        });
        const data = await resp.json();
        if (!resp.ok || data.error) {
            if (errorEl) { errorEl.textContent = data.error || 'Failed to add subnet'; errorEl.classList.remove('hidden'); }
            return;
        }
        input.value = '';
        await loadScanSubnets();
        // Trigger an immediate scan of the newly added subnet
        triggerSubnetScan(data.subnets ? data.subnets[data.subnets.length - 1] : cidr);
    } catch (e) {
        if (errorEl) { errorEl.textContent = e.message; errorEl.classList.remove('hidden'); }
    }
}

async function triggerSubnetScan(cidr) {
    try {
        await networkAwareFetch('/api/config/scan-subnets/trigger', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ cidr })
        });
        // Start polling the scan log so user sees live progress
        _startSubnetLogPolling();
    } catch (e) {
        console.error('triggerSubnetScan error', e);
    }
}

async function removeScanSubnet(cidr) {
    try {
        await networkAwareFetch('/api/config/scan-subnets', {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ cidr })
        });
        await loadScanSubnets();
    } catch (e) {
        console.error('removeScanSubnet error', e);
    }
}

// ── Subnet Scan Log ─────────────────────────────────────────
let _subnetLogTimer = null;

const _logStatusStyle = {
    ok:    'text-green-400',
    error: 'text-red-400',
    info:  'text-blue-400',
    skip:  'text-yellow-400',
};
const _logStatusIcon = {
    ok:    '✅',
    error: '❌',
    info:  '🔍',
    skip:  '⏭️',
};

async function loadSubnetScanLog() {
    const container = document.getElementById('subnet-scan-log');
    if (!container) return;
    try {
        const resp = await networkAwareFetch('/api/config/scan-subnets/log');
        const data = await resp.json();
        const log = data.log || [];
        if (log.length === 0) {
            container.innerHTML = '<p class="text-gray-600 italic">No scan data yet — waiting for next scan cycle.</p>';
            return;
        }
        // Render newest-first
        container.innerHTML = log.slice().reverse().map(e => {
            const cls = _logStatusStyle[e.status] || 'text-gray-400';
            const icon = _logStatusIcon[e.status] || '•';
            const dev = e.devices !== undefined ? ` (${e.devices} device${e.devices !== 1 ? 's' : ''})` : '';
            return `<div class="${cls}"><span class="text-gray-600">${escapeHtml(e.ts)}</span> ${icon} <span class="text-gray-300">${escapeHtml(e.cidr)}</span> — ${escapeHtml(e.msg)}${dev}</div>`;
        }).join('');
        // Auto-scroll to top (newest)
        container.scrollTop = 0;
    } catch (e) {
        console.error('loadSubnetScanLog error', e);
    }
}

function _startSubnetLogPolling() {
    _stopSubnetLogPolling();
    loadSubnetScanLog();                         // immediate
    _subnetLogTimer = setInterval(loadSubnetScanLog, 10000);  // every 10s while panel open
}

function _stopSubnetLogPolling() {
    if (_subnetLogTimer) { clearInterval(_subnetLogTimer); _subnetLogTimer = null; }
}

// Export new functions to window
window.checkServerCapabilities = checkServerCapabilities;
window.loadTrafficAnalysisData = loadTrafficAnalysisData;
window.toggleTrafficCapture = toggleTrafficCapture;
window.refreshTrafficData = refreshTrafficData;
window.showTrafficHostDetail = showTrafficHostDetail;
window.closeTrafficHostModal = closeTrafficHostModal;
window.showTrafficConnectionDetail = showTrafficConnectionDetail;
window.closeTrafficConnectionModal = closeTrafficConnectionModal;
window.showTrafficPortDetail = showTrafficPortDetail;
window.closeTrafficPortModal = closeTrafficPortModal;
window.loadAdvancedVulnData = loadAdvancedVulnData;
window.startAdvancedScan = startAdvancedScan;
window.toggleScanMode = toggleScanMode;
window.setScanStrength = setScanStrength;
window.toggleRequestBodyField = toggleRequestBodyField;
window.refreshAdvVulnData = refreshAdvVulnData;
window.toggleAdvVulnScansExpanded = toggleAdvVulnScansExpanded;
window.toggleAdvVulnScanFindings = toggleAdvVulnScanFindings;
window.toggleAdvVulnScanLogs = toggleAdvVulnScanLogs;
window.cancelAdvScan = cancelAdvScan;
window.startZapDaemon = startZapDaemon;
window.stopZapDaemon = stopZapDaemon;
window.zapClearSession = zapClearSession;
window.zapImportOpenAPI = zapImportOpenAPI;
window.zapSetAuthentication = zapSetAuthentication;
window.zapCheckAuthStatus = zapCheckAuthStatus;
window.zapClearAuthentication = zapClearAuthentication;
window.fetchZapStatus = fetchZapStatus;
window.checkTargetCredentials = checkTargetCredentials;
window.showCredentialsModal = showCredentialsModal;
window.closeCredentialsModal = closeCredentialsModal;
window.toggleCredentialFields = toggleCredentialFields;
window.toggleScanAuthFields = toggleScanAuthFields;
window.saveTargetCredentials = saveTargetCredentials;
window.clearCredentialForm = clearCredentialForm;
window.loadSavedCredentialsList = loadSavedCredentialsList;
window.editTargetCredential = editTargetCredential;
window.deleteTargetCredential = deleteTargetCredential;
window.loadNetworkMap = loadNetworkMap;
window.refreshNetworkMap = refreshNetworkMap;
window.onMapAiToggleClick = onMapAiToggleClick;
window.toggleSubnetPanel = toggleSubnetPanel;
window.addScanSubnet = addScanSubnet;
window.removeScanSubnet = removeScanSubnet;
