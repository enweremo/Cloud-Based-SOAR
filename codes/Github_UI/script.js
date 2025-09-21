const apiUrl = "https://<API_GATEWAY_ID>.execute-api.<ACCOUNT_REGION>.amazonaws.com/prod/data";
let currentTab = "incident";
let chart1, chart2, refreshTimer;
let chartData = { threats: [], remediations: [], blocked_ips: [] };

// Dynamic font sizing for mobile
function getMobileChartFont(size) {
  return window.innerWidth <= 650 ? Math.max(10, size - 4) : size;
}

document.addEventListener("DOMContentLoaded", () => {
  fetchData();
  document.getElementById("dateRange").addEventListener("change", fetchData);
  document.getElementById("autoRefresh").addEventListener("change", toggleAutoRefresh);
  toggleAutoRefresh();
});

function switchTab(tab) {
  currentTab = tab;
  document.querySelectorAll(".tab-btn").forEach(btn => btn.classList.remove("active"));
  document.getElementById(`btn-${tab}`).classList.add("active");
  updateCharts();
}

function toggleAutoRefresh() {
  clearInterval(refreshTimer);
  if (document.getElementById("autoRefresh").checked) {
    refreshTimer = setInterval(fetchData, 60000);
  }
}

function fetchData() {
  const days = document.getElementById("dateRange").value;
  fetch(`${apiUrl}?days=${days}`)
    .then(res => res.json())
    .then(data => {
      chartData = data;
      updateCharts();
    })
    .catch(err => console.error("Fetch failed:", err));
}

function categorizeFindingType(type) {
  if (!type || type === "Unknown") return null;
  const t = type.toLowerCase();
  if (t.includes("sshbruteforce")) return "SSH_BF";
  if (t.includes("portprobeunprotectedport") || t.includes("portscan") || t.includes("portsweep")) return "Port_Scan";
  if (t.startsWith("credentialaccess:iamuser/anomalousbehavior") ||
      t.startsWith("persistence:iamuser/anomalousbehavior") ||
      t.startsWith("persistence:aws/iamuser/anomalousbehavior")) return "IAM_Anom";
  if (t.startsWith("exfiltration:iamuser/anomalousbehavior") ||
      t.startsWith("credentialaccess:aws/iamuser/accesskeyexfiltration")) return "Key_Exfil";
  if (t.includes("torclient")) return "Tor_Access";
  if (t.includes("consoleloginsuccess.b") || t.includes("webloginabuse") || t.includes("custom.web.logs")) return "Web_Abuse";
  if (t.includes("bucketanonymousaccessgranted") || t.includes("bucketpublicaccess") || t.includes("s3/anonymoususer")) return "S3_Unauth";
  if (t.includes("maliciousipcaller.custom") || t.includes("geolocation") || t.includes("highriskaccess")) return "GeoIPThreat";
  return null;
}

function updateCharts() {
  const canvas1 = document.getElementById("chart1");
  const canvas2 = document.getElementById("chart2");
  const ctx1 = canvas1.getContext("2d");
  const ctx2 = canvas2.getContext("2d");

  if (chart1) chart1.destroy();
  if (chart2) chart2.destroy();
  canvas1.className = "";
  canvas2.className = "";

  const remediations = chartData.remediations?.filter(r => r.finding_type !== "Unknown" && r.severity !== "Unknown") || [];

  if (currentTab === "incident") {
    const severities = ["Low", "Medium", "High", "Critical"];
    const autoCounts = [];
    const manualCounts = [];

    severities.forEach(sev => {
      const group = remediations.filter(r => (r.severity || "").toLowerCase() === sev.toLowerCase());
      autoCounts.push(group.filter(r => r.review_required === false).length);
      manualCounts.push(group.filter(r => r.review_required === true).length);
    });

    chart1 = new Chart(ctx1, {
      type: "bar",
      data: {
        labels: severities,
        datasets: [
          { label: "Automated", data: autoCounts, backgroundColor: "green" },
          { label: "Manual Review", data: manualCounts, backgroundColor: "orange" }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          title: { display: true, text: "Findings by Severity & Review Type", font: { weight: "bold", size: getMobileChartFont(16) } },
          legend: { position: "top", labels: { font: { size: getMobileChartFont(13) } } }
        },
        scales: {
          x: {
            title: { display: true, text: "Severity Category", font: { weight: "bold", size: getMobileChartFont(14) } },
            ticks: { font: { size: getMobileChartFont(12) } }
          },
          y: {
            beginAtZero: true,
            title: { display: true, text: "Number of Events", font: { weight: "bold", size: getMobileChartFont(14) } },
            ticks: { font: { size: getMobileChartFont(12) } }
          }
        }
      }
    });

    const total = remediations.length || 1;
    const completed = remediations.filter(r => r.action_status === "completed").length;
    const successRate = ((completed / total) * 100).toFixed(1);
    const remainingRate = (100 - successRate).toFixed(1);

    chart2 = new Chart(ctx2, {
      type: "doughnut",
      data: {
        labels: [`% Remediation Success Rate = ${successRate}%`, `% Remaining = ${remainingRate}%`],
        datasets: [{
          data: [completed, total - completed],
          backgroundColor: ["green", "#ccc"]
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          title: { display: true, text: "Remediation Success Rate", font: { weight: "bold", size: getMobileChartFont(16) } },
          legend: { position: "top", labels: { font: { size: getMobileChartFont(13) } } }
        },
        cutout: "60%"
      }
    });

  } else if (currentTab === "performance") {
    const categories = ["SSH_BF", "Port_Scan", "IAM_Anom", "Key_Exfil", "Tor_Access", "Web_Abuse", "S3_Unauth", "GeoIPThreat"];
    const countMap = {};
    const latencyMap = {};

    categories.forEach(cat => {
      countMap[cat] = 0;
      latencyMap[cat] = [];
    });

    remediations.forEach(r => {
      const mapped = categorizeFindingType(r.finding_type);
      if (!mapped) return;
      countMap[mapped]++;
      if (!isNaN(r.latency_seconds)) latencyMap[mapped].push(parseFloat(r.latency_seconds));
    });

    const values = categories.map(cat => countMap[cat]);
    const avgLatencies = categories.map(cat => {
      const data = latencyMap[cat];
      const total = data.reduce((a, b) => a + b, 0);
      const avgSec = data.length ? total / data.length : 0;
      return Number((avgSec * 1000).toFixed(2)); // Convert to ms
    });

    const fixedColors = {
      "SSH_BF": "#e74c3c",
      "Port_Scan": "#f39c12",
      "IAM_Anom": "#27ae60",
      "Key_Exfil": "#8e44ad",
      "Tor_Access": "#8B5A2B",
      "Web_Abuse": "#3498db",
      "S3_Unauth": "#00FFFF",
      "GeoIPThreat": "#34495e"
    };

    const topIndex = values.indexOf(Math.max(...values));
    const topCategory = categories[topIndex];
    const topColor = fixedColors[topCategory] || "#ccc";

    chart1 = new Chart(ctx1, {
      type: "bar",
      data: {
        labels: categories,
        datasets: [{
          label: "Top Finding Types",
          data: values,
          backgroundColor: categories.map(cat => fixedColors[cat] || "#ccc")
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          title: { display: true, text: "Top GuardDuty Finding Types", font: { weight: "bold", size: getMobileChartFont(16) } },
          legend: {
            labels: {
              font: { size: getMobileChartFont(13) },
              generateLabels: () => [{
                text: "Top Finding Types",
                fillStyle: topColor,
                strokeStyle: topColor,
                lineWidth: 1
              }]
            }
          }
        },
        scales: {
          x: {
            ticks: { maxRotation: 90, minRotation: 90, font: { size: getMobileChartFont(11) } },
            title: { display: true, text: "Threat Type", font: { weight: "bold", size: getMobileChartFont(14) } }
          },
          y: {
            beginAtZero: true,
            title: { display: true, text: "Count of Events", font: { weight: "bold", size: getMobileChartFont(14) } },
            ticks: { font: { size: getMobileChartFont(11) } }
          }
        }
      }
    });

    chart2 = new Chart(ctx2, {
      type: "line",
      data: {
        labels: categories,
        datasets: [{
          label: "Avg Response Time (ms)",
          data: avgLatencies,
          borderColor: "orange",
          backgroundColor: "transparent",
          tension: 0.3
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          title: { display: true, text: "Mean Time to Automated Response (MTTR)", font: { weight: "bold", size: getMobileChartFont(16) } },
          legend: { labels: { font: { size: getMobileChartFont(13) } } }
        },
        scales: {
          x: {
            ticks: { maxRotation: 90, minRotation: 90, font: { size: getMobileChartFont(11) } },
            title: { display: true, text: "Threat Type", font: { weight: "bold", size: getMobileChartFont(14) } }
          },
          y: {
            beginAtZero: true,
            title: { display: true, text: "Response Time (ms)", font: { weight: "bold", size: getMobileChartFont(14) } },
            ticks: { font: { size: getMobileChartFont(11) } }
          }
        }
      }
    });

  } else if (currentTab === "health") {
    const sevDist = {};
    remediations.forEach(r => {
      const sev = r.severity;
      if (!sev || sev === "Unknown") return;
      sevDist[sev] = (sevDist[sev] || 0) + 1;
    });

    const severityOrder = ["Low", "Medium", "High", "Critical"];
    const sevLabels = [];
    const sevValues = [];

    severityOrder.forEach(sev => {
      if (sevDist[sev]) {
        sevLabels.push(sev);
        sevValues.push(sevDist[sev]);
      }
    });

    const severityColorMap = {
      "Critical": "#A32424",
      "High": "#D6452A",
      "Medium": "#F4A300",
      "Low": "#90EE90"
    };

    const sevColors = sevLabels.map(label => severityColorMap[label] || "#ccc");
    const total = sevValues.reduce((a, b) => a + b, 0);

    const legendLabels = sevLabels.map((label, i) => {
      const count = sevValues[i];
      const percent = ((count / total) * 100).toFixed(1);
      return `${label} (${count}) ; (${percent}%)`;
    });

    chart1 = new Chart(ctx1, {
      type: "pie",
      data: {
        labels: legendLabels,
        datasets: [{
          data: sevValues,
          backgroundColor: sevColors
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          title: {
            display: true,
            text: "Severity Distribution (%)",
            font: { weight: "bold", size: getMobileChartFont(16) }
          },
          legend: { position: "right", labels: { font: { size: getMobileChartFont(12) } } },
          datalabels: {
            color: function(ctx) {
              const label = ctx.chart.data.labels[ctx.dataIndex];
              if (label.startsWith("Critical") || label.startsWith("High")) {
                return "#fff";
              }
              return "#000";
            },
            font: { weight: "bold", size: getMobileChartFont(11) },
            formatter: (value, ctx) => {
              const label = ctx.chart.data.labels[ctx.dataIndex].split(" (")[0];
              const total = ctx.chart.data.datasets[0].data.reduce((a, b) => a + b, 0)
              const percentage = ((value / total) * 100).toFixed(1);
              return `${label} (${percentage}%)`;
            },
            rotation: function(ctx) {
              try {
                const meta = ctx.chart.getDatasetMeta(ctx.datasetIndex);
                if (!meta || !meta.data[ctx.dataIndex]) return 0;
                const arc = meta.data[ctx.dataIndex];
                let startAngle = arc.startAngle !== undefined ? arc.startAngle : (arc._view ? arc._view.startAngle : 0);
                let endAngle = arc.endAngle !== undefined ? arc.endAngle : (arc._view ? arc._view.endAngle : 0);
                if (typeof startAngle !== "number" || typeof endAngle !== "number") return 0;
                const midAngle = (startAngle + endAngle) / 2;
                let deg = midAngle * 180 / Math.PI;
                // Keep text upright: if on left side, rotate by 180°
                if (deg > 90 && deg < 270) {
                  deg += 180;
                }
                return deg;
              } catch (e) {
                return 0;
              }
            }

          }
        }
      },
      plugins: [ChartDataLabels]
    });

    const reviewMap = {};
    remediations.forEach(r => {
      if (!r.review_required) return;
      const d = (r.time_occurred || '').split("T")[0];
      reviewMap[d] = (reviewMap[d] || 0) + 1;
    });

    const todayStr = new Date().toISOString().split("T")[0];
    if (!reviewMap[todayStr]) {
      reviewMap[todayStr] = 0;
    }

    // *** SORT DATES AND VALUES ***
    const sortedDates = Object.keys(reviewMap).sort();
    const sortedCounts = sortedDates.map(date => reviewMap[date]);

    chart2 = new Chart(ctx2, {
      type: "line",
      data: {
        labels: sortedDates,  // <-- use sortedDates
        datasets: [{
          label: "SNS Manual Reviews",
          data: sortedCounts, // <-- use sortedCounts
          borderColor: "red",
          backgroundColor: "transparent",
          tension: 0.3
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          title: {
            display: true,
            text: "Manual Reviews Over Time (SNS Sent)",
            font: { weight: "bold", size: getMobileChartFont(16) }
          },
          legend: { labels: { font: { size: getMobileChartFont(13) } } }
        },
        scales: {
          x: {
            title: { display: true, text: "Date", font: { weight: "bold", size: getMobileChartFont(14) } },
            ticks: { font: { size: getMobileChartFont(11) } }
          },
          y: {
            beginAtZero: true,
            title: { display: true, text: "Number of Events", font: { weight: "bold", size: getMobileChartFont(14) } },
            ticks: { font: { size: getMobileChartFont(11) } }
          }
        }
      }
    });
  }

  // Always call these at the END of updateCharts() for responsive resize!
  if (chart1 && typeof chart1.resize === "function") chart1.resize();
  if (chart2 && typeof chart2.resize === "function") chart2.resize();
  window.dispatchEvent(new Event('resize'));
}


function downloadCSV(type) {
  const data = chartData[type];
  if (!data || !data.length) return alert("No data to download.");
  const headers = Object.keys(data[0]);
  const csv = [
    headers.join(","),
    ...data.map(row => headers.map(h => `"${row[h] ?? ''}"`).join(","))
  ].join("\n");

  const blob = new Blob([csv], { type: "text/csv" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `${type}_${Date.now()}.csv`;
  a.click();
}
