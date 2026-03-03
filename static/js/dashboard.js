document.addEventListener('DOMContentLoaded', function() {
    const navItems = document.querySelectorAll('.nav-item');
    const sections = document.querySelectorAll('.view-section');

    // --- NAVIGATION ---
    navItems.forEach(item => {
        if(item.getAttribute('href')) return;
        item.addEventListener('click', () => {
            navItems.forEach(n => n.classList.remove('active'));
            item.classList.add('active');
            sections.forEach(s => s.classList.add('hidden'));
            document.getElementById(`view-${item.dataset.target}`).classList.remove('hidden');
            
            if(item.dataset.target === 'logs') loadLogs();
            if(item.dataset.target === 'blacklist') loadBlacklist();
        });
    });

    // --- CHARTS ---
    const ctxAttack = document.getElementById('attackChart').getContext('2d');
    const attackChart = new Chart(ctxAttack, {
        type: 'doughnut',
        data: { labels: [], datasets: [{ data: [], backgroundColor: ['#ef4444', '#f59e0b', '#3b82f6', '#8b5cf6'], borderWidth: 0 }] },
        options: { responsive: true, plugins: { legend: { position: 'right', labels: { color: '#94a3b8' } } } }
    });

    const ctxIp = document.getElementById('ipChart').getContext('2d');
    const ipChart = new Chart(ctxIp, {
        type: 'bar',
        data: { labels: [], datasets: [{ label: 'Violations', data: [], backgroundColor: '#ef4444' }] },
        options: { responsive: true, scales: { x: { grid: { display:false } }, y: { grid: { color: 'rgba(255,255,255,0.05)' } } } }
    });

    // --- STATS LOOP ---
    function updateStats() {
        if(document.getElementById('view-dashboard').classList.contains('hidden')) return;
        
        fetch('/api/stats')
            .then(res => {
                if(res.status === 401) window.location.href = '/login';
                return res.json();
            })
            .then(data => {
                document.getElementById('blocked-count').innerText = data.blocked;
                document.getElementById('total-count').innerText = data.total;
                document.getElementById('ban-count').innerText = data.bans;

                attackChart.data.labels = Object.keys(data.attacks);
                attackChart.data.datasets[0].data = Object.values(data.attacks);
                attackChart.update();

                ipChart.data.labels = Object.keys(data.top_ips);
                ipChart.data.datasets[0].data = Object.values(data.top_ips);
                ipChart.update();

                const tbody = document.getElementById('logs-body-live');
                tbody.innerHTML = '';
                data.logs.slice(0, 6).forEach(log => {
                    const sevClass = log.severity === 'Critical' ? 'text-red' : (log.severity === 'High' ? 'text-orange' : 'text-blue');
                    tbody.innerHTML += `
                        <tr>
                            <td>${log.timestamp.split(' ')[1]}</td>
                            <td>${log.ip_address}</td>
                            <td>${log.attack_type}</td>
                            <td class="${sevClass}" style="font-weight:bold">${log.severity}</td>
                            <td>${log.risk_score}</td>
                        </tr>`;
                });
            })
            .catch(err => console.log("Waiting for server..."));
    }

    // --- FUNCTIONS ---
    window.loadLogs = function() {
        fetch('/api/stats').then(res=>res.json()).then(data => {
            const tbody = document.getElementById('logs-body-full');
            tbody.innerHTML = '';
            data.logs.forEach(log => {
                tbody.innerHTML += `
                    <tr>
                        <td>${log.timestamp}</td>
                        <td style="color:var(--primary)">${log.ip_address}</td>
                        <td>${log.method}</td>
                        <td>${log.attack_type}</td>
                        <td><span class="badge ${log.severity === 'Critical' ? 'badge-crit' : 'badge-low'}">${log.severity}</span></td>
                        <td>${log.action}</td>
                        <td><button class="btn-primary" onclick="replayLog(${log.id})" style="font-size:0.7rem">Analyze</button></td>
                    </tr>`;
            });
        });
    }

    window.replayLog = function(id) {
        fetch(`/api/logs/${id}`)
            .then(res => res.json())
            .then(log => {
                const modal = document.getElementById('replay-modal');
                const body = document.getElementById('modal-body');
                body.innerHTML = `
                    <p><strong style="color:var(--text-muted)">Time:</strong> ${log.timestamp}</p>
                    <p><strong style="color:var(--text-muted)">IP:</strong> ${log.ip_address} (Threat Index: ${log.threat_index})</p>
                    <hr style="border-color:var(--border-subtle); margin:10px 0">
                    <p><strong style="color:#3b82f6">${log.method} ${log.url}</strong></p>
                    <div style="background:rgba(0,0,0,0.3); padding:10px; border-radius:4px; margin:10px 0; color:#cbd5e1; word-break:break-all;">${log.headers}</div>
                    <p><strong style="color:var(--danger)">Payload:</strong></p>
                    <pre style="color:#ef4444; white-space:pre-wrap;">${log.payload || 'No Body'}</pre>
                `;
                modal.classList.remove('hidden');
            });
    }

    window.closeModal = function() {
        document.getElementById('replay-modal').classList.add('hidden');
    }

    window.loadBlacklist = function() {
        fetch('/api/bans').then(res=>res.json()).then(data => {
            const tbody = document.getElementById('blacklist-body');
            tbody.innerHTML = data.map(b => `
                <tr>
                    <td>${b.ip_address}</td>
                    <td>${b.reason}</td>
                    <td><button class="btn-unban" onclick="unbanIP('${b.ip_address}')">Lift Ban</button></td>
                </tr>`).join('');
        });
    }

    window.unbanIP = function(ip) {
        fetch(`/api/unban/${ip}`, { method: 'POST' }).then(() => loadBlacklist());
    }

    setInterval(updateStats, 2000);
    updateStats();
});