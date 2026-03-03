document.addEventListener('DOMContentLoaded', function() {
    
    // --- NAVIGATION ---
    const navItems = document.querySelectorAll('.nav-item');
    const sections = document.querySelectorAll('.view-section');
    const pageTitle = document.getElementById('page-title');

    navItems.forEach(item => {
        item.addEventListener('click', () => {
            navItems.forEach(nav => nav.classList.remove('active'));
            item.classList.add('active');
            
            const target = item.getAttribute('data-target');
            sections.forEach(sec => sec.classList.add('hidden'));
            
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
            if(target === 'settings') loadSettings();
        });
    });

    // --- CHARTS CONFIG ---
    Chart.defaults.color = '#94a3b8';
    Chart.defaults.borderColor = 'rgba(255, 255, 255, 0.05)';

    // Traffic Line Chart (Simulated History)
    const ctxTraffic = document.getElementById('trafficChart').getContext('2d');
    const trafficChart = new Chart(ctxTraffic, {
        type: 'line',
        data: {
            labels: Array(10).fill(''),
            datasets: [{
                label: 'Requests/sec',
                data: Array(10).fill(0),
                borderColor: '#3b82f6',
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.4,
                pointRadius: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: { y: { beginAtZero: true } },
            animation: { duration: 0 }
        }
    });

    // Attacks Bar Chart
    const ctxAttacks = document.getElementById('attackChart').getContext('2d');
    const attackChart = new Chart(ctxAttacks, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Events',
                data: [],
                backgroundColor: ['#ef4444', '#f59e0b', '#8b5cf6', '#3b82f6'],
                borderRadius: 4,
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

    // --- REAL-TIME DATA ---
    let lastTotal = 0;

    function fetchStats() {
        if (document.getElementById('view-dashboard').classList.contains('hidden')) return;

        fetch('/api/stats')
            .then(res => res.json())
            .then(data => {
                // Counters
                animateValue('blocked-count', parseInt(document.getElementById('blocked-count').innerText), data.blocked, 1000);
                document.getElementById('total-count').innerText = data.total;
                document.getElementById('ban-count').innerText = data.bans;

                // Update Line Chart (Traffic Pulse)
                const currentReqs = data.total - lastTotal;
                lastTotal = data.total;
                
                // Add new point, remove old
                const timeStr = new Date().toLocaleTimeString();
                trafficChart.data.labels.push(timeStr);
                trafficChart.data.datasets[0].data.push(currentReqs > 0 ? currentReqs : 0); // show diff as rate
                if(trafficChart.data.labels.length > 15) {
                    trafficChart.data.labels.shift();
                    trafficChart.data.datasets[0].data.shift();
                }
                trafficChart.update();

                // Update Bar Chart
                attackChart.data.labels = Object.keys(data.attacks);
                attackChart.data.datasets[0].data = Object.values(data.attacks);
                attackChart.update();

                // Update Live Feed Table
                const tbody = document.getElementById('logs-body-live');
                tbody.innerHTML = '';
                data.logs.slice(0, 5).forEach(log => {
                    const riskClass = log[8] > 20 ? 'badge-crit' : (log[8] > 10 ? 'badge-high' : 'badge-low');
                    const riskLabel = log[8] > 20 ? 'CRITICAL' : (log[8] > 10 ? 'HIGH' : 'LOW');
                    
                    tbody.innerHTML += `
                        <tr>
                            <td><span style="color:var(--primary)">${log[1].split(' ')[1]}</span></td>
                            <td>${log[2]}</td>
                            <td>${log[7]}</td>
                            <td><span class="badge ${riskClass}">${riskLabel}</span></td>
                        </tr>
                    `;
                });
            });
    }

    // Helper: Number Animation
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
                        </tr>`;
                });
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

    window.loadSettings = function() {
        fetch('/api/settings')
            .then(res => res.json())
            .then(data => {
                // Update slider values and text displays
                updateSlider('setting-threshold', data.block_threshold);
                updateSlider('setting-ratelimit', data.rate_limit);
                updateSlider('setting-duration', data.ban_duration);
            });
    }

    function updateSlider(id, val) {
        const el = document.getElementById(id);
        if(el) {
            el.value = val;
            el.nextElementSibling.innerText = val;
        }
    }

    // --- ACTIONS ---

    // Sliders Listener
    document.querySelectorAll('.range-slider').forEach(slider => {
        slider.addEventListener('input', (e) => {
            e.target.nextElementSibling.innerText = e.target.value;
        });
    });

    window.saveSettings = function() {
        const data = {
            block_threshold: document.getElementById('setting-threshold').value,
            rate_limit: document.getElementById('setting-ratelimit').value,
            ban_duration: document.getElementById('setting-duration').value
        };
        const btn = document.querySelector('.btn-primary');
        const originalText = btn.innerText;
        btn.innerText = "Saving...";
        
        fetch('/api/settings', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data)
        })
        .then(res => res.json())
        .then(() => {
            btn.innerText = "Configuration Synced";
            setTimeout(() => btn.innerText = originalText, 2000);
        });
    };

    window.unbanIP = function(ip) {
        fetch(`/api/unban/${ip}`, { method: 'POST' })
            .then(() => loadBlacklist());
    };

    // Init
    setInterval(fetchStats, 2000);
    fetchStats();
});