document.addEventListener('DOMContentLoaded', function() {
    const navItems = document.querySelectorAll('.nav-item');
    const sections = document.querySelectorAll('.view-section');
    const pageTitle = document.getElementById('page-title');

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

            if(target === 'dashboard') loadAdaptiveRules();
            if(target === 'logs') loadFullLogs();
            if(target === 'blacklist') loadBlacklist();
            if(target === 'settings') loadSettings();
        });
    });

Chart.defaults.color = '#94a3b8';
Chart.defaults.borderColor = 'rgba(255,255,255,0.05)';

const MAX_POINTS = 40;
let bufferIndex = 0;

const ctxTraffic = document.getElementById('trafficChart').getContext('2d');

const trafficChart = new Chart(ctxTraffic, {
    type: 'line',
    data: {
        labels: new Array(MAX_POINTS).fill(''),
        datasets: [{
            label: 'Requests/sec',
            data: new Array(MAX_POINTS).fill(0),
            borderColor: '#3b82f6',
            backgroundColor: 'rgba(59,130,246,0.1)',
            borderWidth: 2,
            fill: true,
            tension: 0.3,
            pointRadius: 0
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,

        plugins: {
            legend: { display: false }
        },

        scales: {
            y: {
                beginAtZero: true,
                suggestedMax: 5,
                grid: { color: 'rgba(255,255,255,0.05)' }
            },
            x: {
                grid: { display: false },
                ticks: { display: false }
            }
        },

        animation: {
            duration: 120,
            easing: 'linear'
        }
    }
});

    const ctxAttacks = document.getElementById('attackChart').getContext('2d');
    const attackChart = new Chart(ctxAttacks, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Events',
                data: [],
                backgroundColor: ['#ef4444', '#f59e0b', '#8b5cf6', '#3b82f6'],
                borderRadius: 6,
                barThickness: 20
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: { x: { grid: { display: false } } }
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
                backgroundColor: '#10b981',
                borderRadius: 4,
                barThickness: 15
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: { x: { grid: { color: 'rgba(255,255,255,0.05)' } }, y: { grid: { display: false } } }
        }
    });

    // --- REAL-TIME DATA ---
    let lastTotal = 0;

    function fetchStats() {
        if (document.getElementById('view-dashboard').classList.contains('hidden')) return;

        fetch('/api/stats')
            .then(res => {
                if (res.status === 401) { window.location.href = '/admin-login'; }
                return res.json();
            })
            .then(data => {
                if(!data || !data.blocked) return;

                animateValue('blocked-count', parseInt(document.getElementById('blocked-count').innerText), data.blocked, 1000);
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

                // --- THREAT HEATMAP RENDERER ---
                if(data.top_endpoints) {
                    const heatmapContainer = document.getElementById('heatmap-body');
                    if (heatmapContainer) {
                        heatmapContainer.innerHTML = '';
                        const counts = Object.values(data.top_endpoints);
                        const maxCount = counts.length ? Math.max(...counts) : 1;
                        
                        for (const [url, count] of Object.entries(data.top_endpoints)) {
                            const percentage = Math.max(10, (count / maxCount) * 100);
                            heatmapContainer.innerHTML += `
                                <div style="margin-bottom: 12px;">
                                    <div style="display: flex; justify-content: space-between; font-size: 0.85rem; margin-bottom: 4px;">
                                        <span style="font-family: monospace; color: #cbd5e1;">${url}</span>
                                        <span style="color: var(--danger); font-weight: bold;">${count} hits</span>
                                    </div>
                                    <div style="width: 100%; background: rgba(255,255,255,0.05); border-radius: 4px; overflow: hidden; height: 8px;">
                                        <div style="width: ${percentage}%; background: var(--danger); height: 100%; box-shadow: 0 0 8px var(--danger);"></div>
                                    </div>
                                </div>
                            `;
                        }
                    }
                }

                const tbody = document.getElementById('logs-body-live');
                tbody.innerHTML = '';
                data.logs.slice(0, 5).forEach(log => {
                    const riskClass = log[8] > 20 ? 'badge-crit' : (log[8] > 10 ? 'badge-high' : 'badge-low');
                    const riskLabel = log[8] > 20 ? 'CRITICAL' : (log[8] > 10 ? 'HIGH' : 'LOW');
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
        const timer = setInterval(function() {
            current += increment;
            obj.innerHTML = current;
            if (current == end) clearInterval(timer);
        }, Math.min(stepTime, 50));
    }

    // --- PAGE LOADING FUNCTIONS ---
    window.loadFullLogs = function() {
        fetch('/api/logs')
            .then(res => res.json())
            .then(data => {
                const tbody = document.getElementById('logs-body-full');
                tbody.innerHTML = '';
                data.forEach(log => {
                    let badgeClass = 'badge-low';
                    if(log.score > 20) badgeClass = 'badge-crit';
                    else if(log.score > 10) badgeClass = 'badge-high';
                    
                    tbody.innerHTML += `
                        <tr>
                            <td>${log.time}</td>
                            <td style="font-family:monospace; color:var(--accent)">${log.ip}</td>
                            <td>${log.method}</td>
                            <td style="max-width:300px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; opacity:0.8">${log.url}</td>
                            <td>${log.attack}</td>
                            <td><span class="badge ${badgeClass}">Score: ${log.score}</span></td>
                            <td>${log.action}</td>
                            <td><button class="btn-primary" onclick="replayLog(${log.id})" style="font-size:0.7rem; padding: 4px 10px;">Analyze</button></td>
                        </tr>`;
                });
            });
    }

    window.filterLogs = function() {
        const query = document.getElementById('log-search-input').value.toLowerCase();
        const rows = document.querySelectorAll('#logs-body-full tr');
        rows.forEach(row => {
            const text = row.innerText.toLowerCase();
            row.style.display = text.includes(query) ? '' : 'none';
        });
    }

    window.loadBlacklist = function() {
        fetch('/api/bans')
            .then(res => res.json())
            .then(data => {
                const tbody = document.getElementById('blacklist-body');
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

    // --- TELEGRAM UI LOGIC ---
    window.checkTelegramStatus = function() {
        fetch('/api/telegram/status')
            .then(res => res.json())
            .then(data => {
                const badge = document.getElementById('telegram-status-badge');
                const btn = document.getElementById('btn-telegram-connect');
                const container = document.getElementById('telegram-pairing-container');

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

    // --- ADAPTIVE DEFENSE LOGIC ---
    window.loadAdaptiveRules = function() {
        fetch('/api/rules/suggested')
            .then(res => res.json())
            .then(data => {
                const container = document.getElementById('adaptive-rules-body');
                if (!container) return; 
                
                container.innerHTML = '';
                if (data.length === 0) {
                    container.innerHTML = '<div style="padding:20px; text-align:center; color:var(--text-muted); font-size: 0.9rem;"><i class="fas fa-shield-alt"></i> No new patterns detected. WAF is operating normally.</div>';
                    return;
                }
                
                data.forEach(rule => {
                    container.innerHTML += `
                        <div class="glass-panel" style="padding: 15px; margin-bottom: 10px; border-left: 4px solid var(--warning); background: rgba(0,0,0,0.2);">
                            <div style="display:flex; justify-content: space-between; align-items: center;">
                                <div>
                                    <div style="font-size: 0.8rem; color: var(--warning); font-weight: bold; margin-bottom: 5px;">
                                        <i class="fas fa-brain"></i> AI SUGGESTED RULE: ${rule.attack_type}
                                    </div>
                                    <div style="font-family: monospace; color: #f87171; background: rgba(0,0,0,0.4); padding: 6px; border-radius: 4px; word-break: break-all;">
                                        ${rule.pattern}
                                    </div>
                                    <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 5px;">
                                        Confidence: ${rule.confidence}% | First Detected: ${rule.created_at}
                                    </div>
                                </div>
                                <div style="display: flex; gap: 8px; flex-direction: column;">
                                    <button class="btn-primary" style="background: var(--success); border-color: var(--success); font-size: 0.8rem; padding: 6px 12px;" onclick="approveRule(${rule.id})">
                                        <i class="fas fa-check"></i> Approve
                                    </button>
                                    <button class="btn-danger" style="font-size: 0.8rem; padding: 6px 12px;" onclick="rejectRule(${rule.id})">
                                        <i class="fas fa-times"></i> Dismiss
                                    </button>
                                </div>
                            </div>
                        </div>
                    `;
                });
            });
    }

    window.approveRule = function(id) {
        fetch(`/api/rules/approve/${id}`, { method: 'POST' })
            .then(res => res.json())
            .then(data => { 
                showToast(data.message); 
                loadAdaptiveRules(); 
            });
    }

    window.rejectRule = function(id) {
        fetch(`/api/rules/reject/${id}`, { method: 'POST' })
            .then(res => res.json())
            .then(data => { 
                showToast(data.message); 
                loadAdaptiveRules(); 
            });
    }

    window.loadSettings = function() {
        fetch('/api/settings')
            .then(res => res.json())
            .then(data => {
                document.getElementById('setting-threshold').value = data.block_threshold;
                document.getElementById('setting-ratelimit').value = data.rate_limit;
                document.getElementById('setting-duration').value = data.ban_duration;
                
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
            ban_duration: parseInt(document.getElementById('setting-duration').value)
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
                        <div style="font-family:monospace; margin-bottom:10px;">${log.method} ${log.url}</div>
                        <div style="font-family:monospace; font-size:0.85rem; color:#cbd5e1; max-height:100px; overflow-y:auto;">${headersHtml}</div>
                    </div>

                    <div style="background:rgba(239,68,68,0.1); padding:15px; border-radius:8px; border:1px solid var(--danger); margin-bottom:20px;">
                        <div style="font-weight:bold; color:var(--danger); margin-bottom:10px;">DETECTED PAYLOAD</div>
                        <pre style="color:#fca5a5; white-space:pre-wrap; margin:0; font-size:0.9rem;">${log.payload || 'No Body Content'}</pre>
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
        toast.innerText = msg;
        toast.classList.remove('hidden');
        setTimeout(() => toast.classList.add('hidden'), 3000);
    }

    setInterval(fetchStats, 2000);
    fetchStats();
    loadAdaptiveRules(); 
});