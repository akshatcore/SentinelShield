document.addEventListener('DOMContentLoaded', function() {
    // Initialize Charts
    const ctxAttack = document.getElementById('attackChart').getContext('2d');
    const attackChart = new Chart(ctxAttack, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: ['#ef4444', '#f59e0b', '#3b82f6', '#22c55e', '#a855f7'],
                borderColor: '#1e293b',
                borderWidth: 2
            }]
        },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'right', labels: { color: '#94a3b8' } } } }
    });

    const ctxIp = document.getElementById('ipChart').getContext('2d');
    const ipChart = new Chart(ctxIp, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Requests',
                data: [],
                backgroundColor: '#3b82f6',
                borderRadius: 4
            }]
        },
        options: { responsive: true, maintainAspectRatio: false, scales: { y: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.05)' } }, x: { ticks: { color: '#94a3b8' }, grid: { display: false } } }, plugins: { legend: { display: false } } }
    });

    // Fetch Data Function
    function fetchData() {
        fetch('/api/stats')
            .then(response => response.json())
            .then(data => {
                // Update Counters
                document.getElementById('blocked-count').innerText = data.blocked;
                document.getElementById('total-count').innerText = data.total;
                document.getElementById('ban-count').innerText = data.bans;

                // Update Attack Chart
                attackChart.data.labels = Object.keys(data.attacks);
                attackChart.data.datasets[0].data = Object.values(data.attacks);
                attackChart.update();

                // Update IP Chart
                ipChart.data.labels = Object.keys(data.top_ips);
                ipChart.data.datasets[0].data = Object.values(data.top_ips);
                ipChart.update();

                // Update Logs Table
                const tbody = document.getElementById('logs-body');
                tbody.innerHTML = '';
                data.logs.forEach(log => {
                    const row = `
                        <tr>
                            <td>${log[1]}</td>
                            <td>${log[2]}</td>
                            <td>${log[7]}</td>
                            <td><span class="badge">${log[8]}</span></td>
                            <td class="${log[9] === 'BLOCKED' ? 'action-blocked' : 'action-allowed'}">${log[9]}</td>
                        </tr>
                    `;
                    tbody.innerHTML += row;
                });
            });
    }

    // Auto Refresh every 2 seconds
    setInterval(fetchData, 2000);
    fetchData(); // Initial call
});