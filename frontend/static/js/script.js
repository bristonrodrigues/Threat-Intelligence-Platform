// THREAT TREND CHART

const threatTrendChart = new Chart(
    document.getElementById('threatTrendChart'),
    {
        type: 'line',

        data: {

            labels: [
                'Mon',
                'Tue',
                'Wed',
                'Thu',
                'Fri',
                'Sat',
                'Sun'
            ],

            datasets: [{
                label: 'Threat Trends',

                data: [25, 12, 18, 10, 35, 20, 28],
                borderWidth: 2
            }]
        }
    }
);


// ATTACK CATEGORY CHART

const attackCategoryChart = new Chart(
    document.getElementById('attackCategoryChart'),
    {
        type: 'pie',

        data: {

            labels: [
                'Malware',
                'Phishing',
                'Spam',
                'Botnet'
            ],

            datasets: [{
                data: [35, 25, 20, 20]
            }]
        }
    }
);


// SEVERITY CHART

const severityChart = new Chart(
    document.getElementById('severityChart'),
    {
        type: 'bar',

        data: {

            labels: [
                'High',
                'Medium',
                'Low'
            ],

            datasets: [{
                label: 'Severity Levels',

                data: [15, 25, 40],

                borderWidth: 1
            }]
        }
    }
);


// DAILY ATTACK CHART

const dailyAttackChart = new Chart(
    document.getElementById('dailyAttackChart'),
    {
        type: 'doughnut',

        data: {

            labels: [
                'Blocked',
                'Investigating',
                'Resolved'
            ],

            datasets: [{
                data: [40, 15, 45]
            }]
        }
    }
);
async function loadThreatFeed() {

    const response = await fetch('/get_threats')

    const data = await response.json()

    const tableBody = document.getElementById(
        'threatTableBody'
    )

    tableBody.innerHTML = ""

    data.forEach(threat => {

        const row = `
            <tr>

                <td>${threat.ip}</td>

                <td>${threat.threat_type}</td>

                <td>${threat.severity}</td>

                <td>
                    <span class="badge bg-danger">
                        Active
                    </span>
                </td>

            </tr>
        `

        tableBody.innerHTML += row
    })
}loadThreatFeed()

setInterval(
    loadThreatFeed,
    5000
)