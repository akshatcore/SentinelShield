document.addEventListener('DOMContentLoaded', function() {
    const navItems = document.querySelectorAll('.nav-item');
    const sections = document.querySelectorAll('.view-section');
    const pageTitle = document.getElementById('page-title');

    // --- NEW: CUSTOM WALLPAPER LOADER ---
    const savedWallpaper = localStorage.getItem('sentinel_wallpaper');
    if(savedWallpaper) {
        document.body.style.backgroundImage = `url('${savedWallpaper}')`;
    }

    // --- SESSION TIMER LOGIC ---
    const timerElement = document.getElementById('session-timer');
    if (timerElement) {
        const expTime = parseInt(timerElement.getAttribute('data-exp')) * 1000;
        
        const countdown = setInterval(() => {
            const now = new Date().getTime();
            const distance = expTime - now;

            if (distance <= 0) {
                clearInterval(countdown);
                timerElement.innerText = "EXPIRED";
                fetch('/api/auth/logout', { method: 'POST' })
                    .then(() => window.location.href = '/admin-login');
            } else {
                const hours = Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
                const minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
                const seconds = Math.floor((distance % (1000 * 60)) / 1000);
                
                timerElement.innerText = 
                    (hours < 10 ? "0" + hours : hours) + "h " +
                    (minutes < 10 ? "0" + minutes : minutes) + "m " +
                    (seconds < 10 ? "0" + seconds : seconds) + "s";
            }
        }, 1000);
    }

    // --- NAVIGATION ---
    navItems.forEach(item => {
        if(item.getAttribute('href')) return;
        item.addEventListener('click', () => {
            navItems.forEach(n => n.classList.remove('active'));
            item.classList.add('active');
            
            const target = item.getAttribute('data-target');
            sections.forEach(s => s.classList.add('hidden'));
            
            const targetSection = document.getElementById(`view-${target}`);
            targetSection.classList.remove('hidden');
            targetSection.classList.add('fade-in');

            const titles = {
                'dashboard': 'Live Threat Monitor',
                'logs': 'Security Event Logs',
                'blacklist': 'Blocked IP Management',
                'settings': 'System Configuration'
            };
            pageTitle.innerText = titles[target];

            if(target === 'logs') loadFullLogs();
            if(target === 'blacklist') loadBlacklist();
            if(target === 'settings') {
                loadSettings();
                loadAISummary();
            }
        });
    });

    // --- CHARTS CONFIG ---
    Chart.defaults.color = '#94a3b8';
    Chart.defaults.borderColor = 'rgba(255, 255, 255, 0.05)';

   const ctxTraffic = document.getElementById('trafficChart').getContext('2d');
    const trafficChart = new Chart(ctxTraffic, {
        type: 'line',
        data: {
            labels: Array(20).fill(''),
            datasets: [{
                label: 'Requests/sec',
                data: Array(20).fill(0),
                borderColor: '#10b981', 
                backgroundColor: 'rgba(16, 185, 129, 0.1)',
                borderWidth: 2,
                fill: true,
                stepped: true, 
                pointRadius: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: { 
                y: { beginAtZero: true, suggestedMax: 5, grid: { color: 'rgba(255,255,255,0.05)' } },
                x: { grid: { display: false, drawBorder: false }, ticks: { display: true } }
            },
            animation: { duration: 0 } 
        }
    });
const ctxAttacks = document.getElementById('attackChart').getContext('2d');
    const attackChart = new Chart(ctxAttacks, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                label: 'Events',
                data: [],
                backgroundColor: [
                    '#ef4444', '#f59e0b', '#8b5cf6', '#3b82f6', '#10b981', '#ec4899', '#14b8a6'
                ],
                borderColor: '#0f172a',
                borderWidth: 2,
                hoverOffset: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true, 
            aspectRatio: 2.5, 
            layout: { padding: { top: 10, bottom: 35, left: 10, right: 10 } },
            plugins: { 
                legend: { display: true, position: 'right', labels: { color: '#cbd5e1', font: { size: 11 }, boxWidth: 12 } } 
            },
            scales: { x: { display: false }, y: { display: false } },
            cutout: '70%'
        }
    });

  const ctxCountry = document.getElementById('countryChart').getContext('2d');
    const countryChart = new Chart(ctxCountry, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Attacks',
                data: [],
                backgroundColor: 'rgba(16, 185, 129, 0.8)', 
                borderColor: '#10b981', 
                borderWidth: 1,
                borderRadius: 6, 
                barThickness: 12 
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: { 
                x: { grid: { color: 'rgba(255,255,255,0.05)' } }, 
                y: { grid: { display: false } } 
            }
        }
    });

    // --- REAL-TIME DATA ---
    let lastTotal = 0;

    function fetchStats() {
        // Run AI watcher in background regardless of what tab we are on
        checkBackgroundAI();

        // Also live reload the full logs page if it's currently visible
        if (!document.getElementById('view-logs').classList.contains('hidden')) {
            loadFullLogs();
        }

        if (document.getElementById('view-dashboard').classList.contains('hidden')) return;

        fetch('/api/stats')
            .then(res => {
                if (res.status === 401) { window.location.href = '/admin-login'; }
                return res.json();
            })
            .then(data => {
                if(!data || typeof data.blocked === 'undefined') return; 

                animateValue('blocked-count', parseInt(document.getElementById('blocked-count').innerText) || 0, data.blocked, 1000);
                document.getElementById('total-count').innerText = data.total;
                document.getElementById('ban-count').innerText = data.bans;

                const currentReqs = data.total - lastTotal;
                lastTotal = data.total;
                const timeStr = new Date().toLocaleTimeString();
                
                trafficChart.data.labels.push(timeStr);
                trafficChart.data.datasets[0].data.push(currentReqs > 0 ? currentReqs : 0);
                if(trafficChart.data.labels.length > 20) {
                    trafficChart.data.labels.shift();
                    trafficChart.data.datasets[0].data.shift();
                }
                trafficChart.update();

                attackChart.data.labels = Object.keys(data.attacks);
                attackChart.data.datasets[0].data = Object.values(data.attacks);
                attackChart.update();

                if(data.top_countries) {
                    countryChart.data.labels = Object.keys(data.top_countries).map(code => getFlag(code) + " " + code);
                    countryChart.data.datasets[0].data = Object.values(data.top_countries);
                    countryChart.update();
                }

                const heatmapContainer = document.getElementById('heatmap-body');
                if(data.top_endpoints && heatmapContainer) {
                    heatmapContainer.innerHTML = '';
                    const counts = Object.values(data.top_endpoints);
                    const maxCount = counts.length ? Math.max(...counts) : 1;
                    
                    for (const [url, count] of Object.entries(data.top_endpoints)) {
                        const percentage = Math.max(10, (count / maxCount) * 100);
                        const safeUrl = url.replace(/</g, "&lt;").replace(/>/g, "&gt;");
                        
                        heatmapContainer.innerHTML += `
                            <div style="margin-bottom: 12px;">
                                <div style="display: flex; justify-content: space-between; font-size: 0.85rem; margin-bottom: 4px;">
                                    <span style="font-family: monospace; color: #cbd5e1;">${safeUrl}</span>
                                    <span style="color: var(--danger); font-weight: bold;">${count} hits</span>
                                </div>
                                <div style="width: 100%; background: rgba(255,255,255,0.05); border-radius: 4px; overflow: hidden; height: 8px;">
                                    <div style="width: ${percentage}%; background: var(--danger); height: 100%; box-shadow: 0 0 8px var(--danger);"></div>
                                </div>
                            </div>
                        `;
                    }
                }

                const tbody = document.getElementById('logs-body-live');
                if (tbody && data.logs) {
                    tbody.innerHTML = '';
                    data.logs.slice(0, 5).forEach(log => {
                        const riskClass = log[8] >= 20 ? 'badge-crit' : (log[8] >= 10 ? 'badge-high' : 'badge-low');
                        const riskLabel = log[8] >= 20 ? 'CRITICAL' : (log[8] >= 10 ? 'HIGH' : 'LOW');
                        const flag = getFlag(log[10] || 'Unknown'); 
                        
                        tbody.innerHTML += `
                            <tr>
                                <td><span style="color:var(--primary)">${log[1].split(' ')[1]}</span></td>
                                <td>${log[2]}</td>
                                <td>${flag} ${log[10] || 'UNK'}</td>
                                <td>${log[7]}</td>
                                <td><span class="badge ${riskClass}">${riskLabel}</span></td>
                            </tr>
                        `;
                    });
                }
            })
            .catch(err => console.log("Waiting for server...", err));
    }

    function getFlag(code) {
        if (code === 'Local') return '🏠'; 
        if (!code || code === 'Unknown' || code === 'UNK') return '🏳️';
        return code.toUpperCase().replace(/./g, char => String.fromCodePoint(char.charCodeAt(0) + 127397));
    }

    function animateValue(id, start, end, duration) {
        if (start === end) return;
        const range = end - start;
        let current = start;
        const increment = end > start ? 1 : -1;
        const stepTime = Math.abs(Math.floor(duration / range));
        const obj = document.getElementById(id);
        if (!obj) return;
        const timer = setInterval(function() {
            current += increment;
            obj.innerHTML = current;
            if (current == end) clearInterval(timer);
        }, Math.min(stepTime, 50));
    }

    // --- PAGE LOADING FUNCTIONS ---
    window.loadFullLogs = function() {
        const query = document.getElementById('log-search-input').value.toLowerCase();
        
        fetch('/api/logs')
            .then(res => res.json())
            .then(data => {
                const tbody = document.getElementById('logs-body-full');
                if (!tbody) return;
                tbody.innerHTML = '';
                data.forEach(log => {
                    let badgeClass = 'badge-low';
                    if(log.score >= 20) badgeClass = 'badge-crit';
                    else if(log.score >= 10) badgeClass = 'badge-high';
                    
                    const safeUrl = log.url.replace(/</g, "&lt;").replace(/>/g, "&gt;");
                    const rowHtml = `
                        <tr>
                            <td>${log.time}</td>
                            <td style="font-family:monospace; color:var(--accent)">${log.ip}</td>
                            <td>${log.method}</td>
                            <td style="max-width:300px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; opacity:0.8">${safeUrl}</td>
                            <td>${log.attack}</td>
                            <td><span class="badge ${badgeClass}">Score: ${log.score}</span></td>
                            <td>${log.action}</td>
                            <td><button class="btn-primary" onclick="replayLog(${log.id})" style="font-size:0.7rem; padding: 4px 10px;">Analyze</button></td>
                        </tr>`;
                        
                    // If there is an active search, only render rows that match it to prevent flicker
                    if(query === '' || rowHtml.toLowerCase().includes(query)) {
                        tbody.innerHTML += rowHtml;
                    }
                });
            });
    }

    window.filterLogs = function() {
        // Triggering loadFullLogs will re-render with the search filter applied
        loadFullLogs();
    }

    window.loadBlacklist = function() {
        fetch('/api/bans')
            .then(res => res.json())
            .then(data => {
                const tbody = document.getElementById('blacklist-body');
                if (!tbody) return;
                tbody.innerHTML = '';
                if(data.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding:30px; color:var(--text-muted)">No active threats detained.</td></tr>';
                    return;
                }
                data.forEach(ban => {
                    tbody.innerHTML += `
                        <tr>
                            <td style="font-family:monospace; color:var(--danger)">${ban.ip}</td>
                            <td>${ban.banned_at}</td>
                            <td>${ban.expires}</td>
                            <td>${ban.reason}</td>
                            <td style="text-align:right">
                                <button class="btn-danger" onclick="unbanIP('${ban.ip}')">
                                    <i class="fas fa-unlock"></i> Lift Ban
                                </button>
                            </td>
                        </tr>`;
                });
            });
    }

    window.unbanIP = function(ip) {
        fetch(`/api/unban/${ip}`, { method: 'POST' }).then(() => loadBlacklist());
    }

    // --- CUSTOM WALLPAPER UPLOAD LOGIC ---
    window.uploadWallpaper = function() {
        const input = document.getElementById('wallpaper-upload');
        if (!input.files[0]) return;

        const formData = new FormData();
        formData.append('wallpaper', input.files[0]);

        showToast("Uploading wallpaper...");

        fetch('/api/settings/wallpaper', {
            method: 'POST',
            body: formData
        })
        .then(res => res.json())
        .then(data => {
            if (data.status === 'success') {
                showToast(data.message);
                document.body.style.backgroundImage = `url('${data.url}')`;
                localStorage.setItem('sentinel_wallpaper', data.url);
            } else {
                alert("Upload Failed: " + data.message);
            }
        })
        .catch(err => {
            alert("Error uploading file. The file might be larger than 5MB.");
        });
    }

    window.resetWallpaper = function() {
        document.body.style.backgroundImage = "url('/static/img/cyber-bg.jpg')";
        localStorage.removeItem('sentinel_wallpaper');
        showToast("Wallpaper reset to default.");
    }

    // --- TELEGRAM UI LOGIC ---
    window.checkTelegramStatus = function() {
        fetch('/api/telegram/status')
            .then(res => res.json())
            .then(data => {
                const badge = document.getElementById('telegram-status-badge');
                const btn = document.getElementById('btn-telegram-connect');
                const container = document.getElementById('telegram-pairing-container');
                if(!badge) return;

                if (data.status === 'linked') {
                    badge.innerHTML = '<span class="badge" style="background:var(--success); color:black; font-weight:bold;"><i class="fas fa-check-circle"></i> Connected</span>';
                    btn.style.display = 'none';
                    if(container) container.classList.add('hidden');
                } else if (data.status === 'pending') {
                    badge.innerHTML = '<span class="badge" style="background:var(--warning); color:black; font-weight:bold;"><i class="fas fa-clock"></i> Pending Verification...</span>';
                    btn.style.display = 'none';
                    if(container) container.classList.remove('hidden');
                    setTimeout(checkTelegramStatus, 3000);
                } else {
                    badge.innerHTML = '<span class="badge badge-low"><i class="fas fa-times-circle"></i> Not Connected</span>';
                    btn.style.display = 'block';
                    if(container) container.classList.add('hidden');
                }
            });
    };

    window.generateTelegramLink = function() {
        const btn = document.getElementById('btn-telegram-connect');
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Generating...';
        btn.disabled = true;

        fetch('/api/telegram/generate', { method: 'POST' })
            .then(res => res.json())
            .then(data => {
                if(data.status === 'success') {
                    document.getElementById('telegram-deep-link').href = data.link;
                    document.getElementById('telegram-deep-link').innerText = data.link;
                    checkTelegramStatus(); 
                }
            });
    };

    window.loadSettings = function() {
        fetch('/api/settings')
            .then(res => res.json())
            .then(data => {
                document.getElementById('setting-threshold').value = data.block_threshold;
                document.getElementById('setting-ratelimit').value = data.rate_limit;
                document.getElementById('setting-duration').value = data.ban_duration;
                document.getElementById('setting-proxy-url').value = data.reverse_proxy_url || ""; // NEW!
                
                document.getElementById('val-threshold').innerText = data.block_threshold;
                document.getElementById('val-ratelimit').innerText = data.rate_limit;
                document.getElementById('val-duration').innerText = data.ban_duration;
            });
        
        checkTelegramStatus();
    }

    const sliders = {
        'setting-threshold': 'val-threshold',
        'setting-ratelimit': 'val-ratelimit',
        'setting-duration': 'val-duration'
    };

    Object.keys(sliders).forEach(id => {
        const el = document.getElementById(id);
        if(el) {
            el.addEventListener('input', function() {
                document.getElementById(sliders[id]).innerText = this.value;
            });
        }
    });

    window.saveSettings = function() {
        const data = {
            block_threshold: parseInt(document.getElementById('setting-threshold').value),
            rate_limit: parseInt(document.getElementById('setting-ratelimit').value),
            ban_duration: parseInt(document.getElementById('setting-duration').value),
            reverse_proxy_url: document.getElementById('setting-proxy-url').value // NEW!
        };
        
        fetch('/api/settings', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data)
        })
        .then(res => res.json())
        .then(data => {
            showToast(data.message);
        });
    };

    window.clearDatabase = function() {
        if(!confirm("Are you sure? This will delete all Logs and Bans.")) return;
        fetch('/api/database/clear', { method: 'POST' })
            .then(res => res.json())
            .then(data => {
                showToast(data.message);
                lastTotal = 0; 
                document.getElementById('blocked-count').innerText = "0";
                document.getElementById('total-count').innerText = "0";
                document.getElementById('ban-count').innerText = "0";
                
                const liveLogs = document.getElementById('logs-body-live');
                if(liveLogs) liveLogs.innerHTML = "";
                const heatmap = document.getElementById('heatmap-body');
                if(heatmap) heatmap.innerHTML = "";
                
                trafficChart.data.labels = Array(20).fill('');
                trafficChart.data.datasets[0].data = Array(20).fill(0);
                trafficChart.update();
                
                attackChart.data.labels = [];
                attackChart.data.datasets[0].data = [];
                attackChart.update();
                
                countryChart.data.labels = [];
                countryChart.data.datasets[0].data = [];
                countryChart.update();
            });
    };

    window.replayLog = function(id) {
        fetch(`/api/logs/${id}`)
            .then(res => res.json())
            .then(log => {
                const modal = document.getElementById('replay-modal');
                const body = document.getElementById('modal-body');
                
                let headersHtml = '';
                try {
                    const cleanHeaders = log.headers.replace(/'/g, '"');
                    const headersObj = JSON.parse(cleanHeaders);
                    for (const [key, value] of Object.entries(headersObj)) {
                        headersHtml += `<div><span style="color:var(--primary)">${key}:</span> ${value}</div>`;
                    }
                } catch(e) { headersHtml = log.headers; }

                const curlCmd = generateCurl(log);
                const safePayload = log.payload ? log.payload.replace(/</g, "&lt;").replace(/>/g, "&gt;") : 'No Body Content';

                body.innerHTML = `
                    <div style="display:grid; grid-template-columns: 1fr 1fr; gap:20px; margin-bottom:20px;">
                        <div>
                            <div style="font-size:0.8rem; color:var(--text-muted)">SOURCE</div>
                            <div style="font-size:1.1rem; font-weight:bold">${log.ip_address} ${getFlag(log.country)}</div>
                        </div>
                        <div>
                            <div style="font-size:0.8rem; color:var(--text-muted)">THREAT VECTOR</div>
                            <div style="font-size:1.1rem; color:var(--danger)">${log.attack_type} (Score: ${log.risk_score})</div>
                        </div>
                    </div>

                    <div style="background:rgba(0,0,0,0.3); padding:15px; border-radius:8px; border:1px solid var(--border-subtle); margin-bottom:15px;">
                        <div style="font-weight:bold; color:#3b82f6; margin-bottom:10px;">HTTP REQUEST</div>
                        <div style="font-family:monospace; margin-bottom:10px;">${log.method} ${log.url.replace(/</g, "&lt;").replace(/>/g, "&gt;")}</div>
                        <div style="font-family:monospace; font-size:0.85rem; color:#cbd5e1; max-height:100px; overflow-y:auto;">${headersHtml}</div>
                    </div>

                    <div style="background:rgba(239,68,68,0.1); padding:15px; border-radius:8px; border:1px solid var(--danger); margin-bottom:20px;">
                        <div style="font-weight:bold; color:var(--danger); margin-bottom:10px;">DETECTED PAYLOAD</div>
                        <pre style="color:#fca5a5; white-space:pre-wrap; margin:0; font-size:0.9rem;">${safePayload}</pre>
                    </div>

                    <div style="display:flex; gap:10px; justify-content:flex-end;">
                        <button class="btn-primary" onclick="window.location.href='/api/report/pdf/${log.id}'" style="background: var(--warning); border-color: var(--warning);">
                            <i class="fas fa-file-pdf"></i> Download PDF
                        </button>
                        
                        <button class="btn-primary" onclick="copyToClipboard('${curlCmd.replace(/'/g, "\\'")}')">
                            <i class="fas fa-copy"></i> Copy cURL
                        </button>
                        <button class="btn-danger" onclick="replayAttack('${log.url}', '${log.method}', '${log.payload ? log.payload.replace(/'/g, "\\'") : ''}')">
                            <i class="fas fa-redo"></i> Replay Attack
                        </button>
                    </div>
                `;
                modal.classList.remove('hidden');
            });
    }

    window.generateCurl = function(log) {
        let cmd = `curl -X ${log.method} "${log.url}"`;
        cmd += ` -H "User-Agent: SentinelReplay"`;
        if(log.payload && log.payload !== 'None') cmd += ` -d '${log.payload}'`;
        return cmd;
    }

    window.copyToClipboard = function(text) {
        navigator.clipboard.writeText(text).then(() => showToast("cURL copied to clipboard!"));
    }

    window.replayAttack = function(url, method, payload) {
        if(!confirm("WARNING: Replaying this attack will target the server immediately. Your IP might get banned if the WAF catches it again. Proceed?")) return;
        
        const options = { method: method };
        if(method !== 'GET' && method !== 'HEAD' && payload && payload !== 'None') {
            options.body = payload;
        }

        fetch(url, options)
            .then(res => {
                showToast(`Replay Sent! Status: ${res.status}`);
            })
            .catch(err => {
                showToast("Replay blocked by WAF (Expected behavior)");
            });
    }

    window.closeModal = function() {
        document.getElementById('replay-modal').classList.add('hidden');
    }

    function showToast(msg) {
        const toast = document.getElementById('toast');
        if(!toast) return;
        toast.innerText = msg;
        toast.classList.remove('hidden');
        setTimeout(() => toast.classList.add('hidden'), 3000);
    }

    // --- AUTONOMOUS AI KNOWLEDGE BASE & NOTIFICATIONS ---
    let aiRuleCount = -1; // Stores the number of rules so we can detect new ones

    window.checkBackgroundAI = function() {
        fetch('/api/ai/summary')
            .then(res => res.json())
            .then(data => {
                // If this is the first load, just set the count and do nothing.
                if (aiRuleCount === -1) {
                    aiRuleCount = data.length;
                    return;
                }
                
                // If the count increased, a new rule was autonomously deployed!
                if (data.length > aiRuleCount) {
                    const newRule = data[0]; // Assuming API returns order DESC
                    showToast(`🧠 AI deployed new rule against: ${newRule.attack_type}`);
                    aiRuleCount = data.length;
                    
                    // If the user happens to be looking at the Settings page, refresh the table live
                    if (!document.getElementById('view-settings').classList.contains('hidden')) {
                        loadAISummary();
                    }
                } else if (data.length < aiRuleCount) {
                    // Handle case where user deleted a rule
                    aiRuleCount = data.length;
                }
            })
            .catch(err => {});
    }

    window.loadAISummary = function() {
        fetch('/api/ai/summary')
            .then(res => res.json())
            .then(data => {
                const tbody = document.getElementById('ai-summary-body');
                if (!tbody) return;
                
                tbody.innerHTML = '';
                if (data.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding:20px; color:var(--text-muted)">The AI has not detected any new patterns yet. Operating on baseline rules.</td></tr>';
                    return;
                }
                
                data.forEach(rule => {
                    const safePattern = rule.pattern.replace(/</g, "&lt;").replace(/>/g, "&gt;");
                    
                    tbody.innerHTML += `
                        <tr style="border-bottom: 1px solid var(--border-subtle); background: rgba(0,0,0,0.2);">
                            <td style="padding: 12px 20px; font-weight: bold; color: var(--warning);"><i class="fas fa-brain"></i> ${rule.attack_type}</td>
                            <td style="padding: 12px 20px; font-family: monospace; color: #f87171; word-break: break-all;">${safePattern}</td>
                            <td style="padding: 12px 20px; font-size: 0.85rem; color: var(--text-muted);">${rule.created_at}</td>
                            <td style="padding: 12px 20px; text-align: right;">
                                <button class="btn-danger" style="font-size: 0.75rem; padding: 4px 8px;" onclick="deleteAIRule(${rule.id})">
                                    <i class="fas fa-trash"></i> Remove
                                </button>
                            </td>
                        </tr>
                    `;
                });
            })
            .catch(err => console.error("Error loading AI Summary:", err));
    }

    window.deleteAIRule = function(id) {
        if(!confirm("Are you sure you want to remove this rule? If this was a valid attack, the AI will just re-learn it later.")) return;
        
        fetch(`/api/ai/delete/${id}`, { method: 'POST' })
            .then(res => res.json())
            .then(data => { 
                showToast(data.message); 
                loadAISummary(); 
            });
    }

    // --- AI KNOWLEDGE WIPE ---
    window.clearAIKnowledge = function() {
        if(confirm("⚠️ WARNING: This will permanently delete all dynamically learned Regex rules and wipe the AI's memory. The WAF will revert to its baseline configuration. Are you sure?")) {
            fetch('/api/ai/clear', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            })
            .then(response => response.json())
            .then(data => {
                if(data.status === 'success') {
                    showToast("🧠 AI Knowledge Wiped & Baseline Restored!");
                    setTimeout(() => window.location.reload(), 1500);
                } else {
                    alert("Error: " + data.message);
                }
            })
            .catch(err => console.error("Error clearing AI:", err));
        }
    };
    
    // START LIVE DATA LOOP
    setInterval(() => {
        fetchStats();
    }, 1000);

    // INITIAL LOAD
    fetchStats();
});