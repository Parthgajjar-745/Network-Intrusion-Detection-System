const canvas = document.getElementById("networkCanvas");
const ctx = canvas.getContext("2d");

function resizeCanvas() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
}
resizeCanvas();
window.addEventListener("resize", resizeCanvas);

const fontSize = 14;
const columns = Math.floor(canvas.width / fontSize);
const drops = new Array(columns).fill(1);
const characters = "01";

function drawMatrix() {
    ctx.fillStyle = "rgba(10, 14, 10, 0.08)";
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    ctx.fillStyle = "#00ffaa";
    ctx.font = fontSize + "px monospace";

    for (let i = 0; i < drops.length; i++) {
        const text = characters.charAt(Math.floor(Math.random() * characters.length));
        const x = i * fontSize;
        const y = drops[i] * fontSize;

        ctx.fillText(text, x, y);

        if (y > canvas.height && Math.random() > 0.975) {
            drops[i] = 0;
        }

        drops[i]++;
    }

    requestAnimationFrame(drawMatrix);
}
drawMatrix();



const titleText = "Network Intrusion Detection System";
const typingElement = document.getElementById("typingTitle");
let charIndex = 0;

function typeTitle() {
    if (charIndex < titleText.length) {
        typingElement.textContent += titleText.charAt(charIndex);
        charIndex++;
        setTimeout(typeTitle, 40);
    }
}
typeTitle();



let totalChecks = 0;
let totalAlerts = 0;

function updateStats(isAlert) {
    totalChecks++;
    if (isAlert) totalAlerts++;
    document.getElementById("totalChecks").textContent = totalChecks;
    document.getElementById("totalAlerts").textContent = totalAlerts;
}



function getSeverity(count, limit) {
    const excess = count - limit;
    if (excess >= 6) return "HIGH";
    if (excess >= 3) return "MEDIUM";
    return "LOW";
}



function updateProgressBars(requestCount, portCount) {
    const reqFill = document.getElementById("reqProgressFill");
    const reqText = document.getElementById("reqProgressText");
    const portFill = document.getElementById("portProgressFill");
    const portText = document.getElementById("portProgressText");

    const reqPercent = Math.min((requestCount / REQUEST_LIMIT) * 100, 100);
    const portPercent = Math.min((portCount / PORT_SCAN_LIMIT) * 100, 100);

    reqFill.style.width = reqPercent + "%";
    reqText.textContent = requestCount + " / " + REQUEST_LIMIT;
    reqFill.className = "progress-bar-fill" + (requestCount > REQUEST_LIMIT ? " warning" : "");

    portFill.style.width = portPercent + "%";
    portText.textContent = portCount + " / " + PORT_SCAN_LIMIT;
    portFill.className = "progress-bar-fill" + (portCount > PORT_SCAN_LIMIT ? " warning" : "");
}



function playAlertSound() {
    try {
        const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = audioCtx.createOscillator();
        const gainNode = audioCtx.createGain();

        oscillator.connect(gainNode);
        gainNode.connect(audioCtx.destination);

        oscillator.frequency.value = 880;
        oscillator.type = "sine";
        gainNode.gain.setValueAtTime(0.15, audioCtx.currentTime);

        oscillator.start();
        oscillator.stop(audioCtx.currentTime + 0.15);
    } catch (error) {
        console.log("Sound could not be played:", error);
    }
}



const REQUEST_LIMIT = 5;
const TIME_WINDOW = 3000;
const PORT_SCAN_LIMIT = 4;

const ipRequestLog = {};
const ipPortLog = {};



const checkButton = document.getElementById("checkBtn");

checkButton.onclick = function() {

    const ip = document.getElementById("ipInput").value;
    const port = document.getElementById("portInput").value;
    const resultBox = document.getElementById("resultBox");

    if (ip === "" || port === "") {
        resultBox.className = "result-box";
        resultBox.textContent = "Please enter both IP address and port.";
        return;
    }

    // ---- Validate IP address format (e.g. 192.168.1.22) ----
    const ipPattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
    const ipMatch = ip.match(ipPattern);

    if (!ipMatch || ipMatch.slice(1).some(function(part) { return parseInt(part) > 255; })) {
        resultBox.className = "result-box";
        resultBox.textContent = "Please enter a valid IP address (e.g. 192.168.1.22).";
        return;
    }

    // ---- Validate port number (0 to 65535) ----
    const portNum = parseInt(port);
    if (isNaN(portNum) || portNum < 0 || portNum > 65535) {
        resultBox.className = "result-box";
        resultBox.textContent = "Please enter a valid port number (0-65535).";
        return;
    }

    const now = Date.now();

    if (!ipRequestLog[ip]) ipRequestLog[ip] = [];
    ipRequestLog[ip].push(now);
    ipRequestLog[ip] = ipRequestLog[ip].filter(function(t) { return now - t <= TIME_WINDOW; });
    const requestCount = ipRequestLog[ip].length;

    if (!ipPortLog[ip]) ipPortLog[ip] = new Set();
    ipPortLog[ip].add(port);
    const portCount = ipPortLog[ip].size;

    updateProgressBars(requestCount, portCount);

    if (requestCount > REQUEST_LIMIT) {
        const severity = getSeverity(requestCount, REQUEST_LIMIT);
        resultBox.className = "result-box danger";
        resultBox.textContent = "SUSPICIOUS! Possible DDoS Attack from " + ip +
            " (" + requestCount + " requests in " + (TIME_WINDOW / 1000) + " seconds)";
        addLogEntry(ip, "DDoS Attack", requestCount + " requests in " + (TIME_WINDOW / 1000) + "s", severity);
        updateStats(true);
        playAlertSound();

    } else if (portCount > PORT_SCAN_LIMIT) {
        const severity = getSeverity(portCount, PORT_SCAN_LIMIT);
        resultBox.className = "result-box danger";
        resultBox.textContent = "SUSPICIOUS! Possible Port Scanning from " + ip +
            " (" + portCount + " different ports accessed)";
        addLogEntry(ip, "Port Scanning", portCount + " different ports accessed", severity);
        updateStats(true);
        playAlertSound();

    } else {
        resultBox.className = "result-box safe";
        resultBox.textContent = "NORMAL - No suspicious activity for " + ip;
        updateStats(false);
    }
};


function addLogEntry(ip, type, details, severity) {
    const logBox = document.getElementById("logBox");
    const emptyMsg = logBox.querySelector(".log-empty");
    if (emptyMsg) emptyMsg.remove();

    const time = new Date().toLocaleTimeString();
    const card = document.createElement("div");
    card.className = "log-card";
    card.innerHTML =
        '<div class="log-card-top">' +
            '<span class="log-card-type">' + type + '</span>' +
            '<span class="badge ' + severity + '">' + severity + '</span>' +
        '</div>' +
        '<div class="log-card-details">IP ' + ip + ' &middot; ' + details + ' &middot; ' + time + '</div>';

    logBox.insertBefore(card, logBox.firstChild);
}



document.getElementById("resetBtn").onclick = function() {
    for (let key in ipRequestLog) delete ipRequestLog[key];
    for (let key in ipPortLog) delete ipPortLog[key];

    totalChecks = 0;
    totalAlerts = 0;
    document.getElementById("totalChecks").textContent = "0";
    document.getElementById("totalAlerts").textContent = "0";

    document.getElementById("logBox").innerHTML = '<p class="log-empty">No alerts yet...</p>';
    document.getElementById("resultBox").className = "result-box";
    document.getElementById("resultBox").textContent = "Enter details above and click \"Check IP\" to see the result.";

    updateProgressBars(0, 0);

    document.getElementById("ipInput").value = "";
    document.getElementById("portInput").value = "";
};



document.getElementById("exportBtn").onclick = function() {
    const logBox = document.getElementById("logBox");
    const entries = logBox.querySelectorAll(".log-card");

    if (entries.length === 0) {
        alert("No alerts to export yet.");
        return;
    }

    let textContent = "NIDS Alert Log Export\n";
    textContent += "Generated: " + new Date().toLocaleString() + "\n";
    textContent += "==================================================\n\n";

    entries.forEach(function(entry) {
        textContent += entry.textContent.trim() + "\n";
    });

    const blob = new Blob([textContent], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "nids_alert_log.txt";
    link.click();
    URL.revokeObjectURL(url);
};



document.getElementById("ipInput").addEventListener("keypress", function(e) {
    if (e.key === "Enter") {
        document.getElementById("portInput").focus();
    }
});

document.getElementById("portInput").addEventListener("keypress", function(e) {
    if (e.key === "Enter") {
        checkButton.click();
    }
});