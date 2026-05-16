const API_URL = "http://127.0.0.1:8002/analyze/url";
const BLOCKED_PROTOCOLS = ["chrome:", "edge:", "about:", "chrome-extension:"];

const elements = {
  currentUrl: document.getElementById("current-url"),
  favicon: document.getElementById("favicon"),
  scanButton: document.getElementById("scan-button"),
  scanLabel: document.getElementById("scan-label"),
  statusCard: document.getElementById("status-card"),
  resultCard: document.getElementById("result-card"),
  riskTitle: document.getElementById("risk-title"),
  riskBadge: document.getElementById("risk-badge"),
  scoreValue: document.getElementById("score-value"),
  scoreSummary: document.getElementById("score-summary"),
  reasonsList: document.getElementById("reasons-list"),
  recommendationText: document.getElementById("recommendation-text")
};

let activeUrl = "";
let activeTab = null;

document.addEventListener("DOMContentLoaded", initPopup);
elements.scanButton.addEventListener("click", scanCurrentPage);

async function initPopup() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    activeTab = tab;
    activeUrl = tab?.url || "";

    elements.currentUrl.textContent = activeUrl || "Nu s-a putut detecta URL-ul.";
    setFavicon(tab);

    if (!isScannableUrl(activeUrl)) {
      elements.scanButton.disabled = true;
      showStatus("Această pagină nu poate fi scanată.", "error");
    }
  } catch (error) {
    elements.scanButton.disabled = true;
    showStatus("Nu s-a putut citi pagina activă.", "error");
  }
}

async function scanCurrentPage() {
  if (!isScannableUrl(activeUrl)) {
    showStatus("Această pagină nu poate fi scanată.", "error");
    return;
  }

  setLoading(true);
  hideResult();
  showStatus("Se scanează...", "loading");

  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url: activeUrl })
    });

    if (!response.ok) {
      throw new Error(`Backend returned ${response.status}`);
    }

    const result = await response.json();
    renderResult(result);
    await saveLastScan(result);
  } catch (error) {
    const message = isBackendConnectionError(error)
      ? "Backend-ul nu este pornit pe portul 8002."
      : "Scanarea a eșuat. Încearcă din nou.";

    showStatus(message, "error");
  } finally {
    setLoading(false);
  }
}

function renderResult(result) {
  const risk = normalizeRisk(result.risk);
  const trustScore = clampScore(result.trust_score);
  const reasons = Array.isArray(result.reasons) ? result.reasons : [];

  elements.statusCard.hidden = true;
  elements.resultCard.hidden = false;
  elements.resultCard.classList.remove("risk-safe", "risk-suspicious", "risk-dangerous");
  elements.resultCard.classList.add(`risk-${risk}`);

  elements.riskTitle.textContent = riskLabel(risk);
  elements.riskBadge.textContent = risk.toUpperCase();
  elements.riskBadge.className = `risk-badge risk-${risk}`;
  elements.scoreValue.textContent = trustScore;
  elements.scoreSummary.textContent = scoreSummary(risk, trustScore);
  elements.resultCard.style.setProperty("--score", trustScore);

  elements.reasonsList.replaceChildren(
    ...reasons.map((reason) => {
      const item = document.createElement("li");
      item.textContent = reason;
      return item;
    })
  );

  if (!reasons.length) {
    const item = document.createElement("li");
    item.textContent = "Nu au fost returnate motive suplimentare.";
    elements.reasonsList.append(item);
  }

  elements.recommendationText.textContent =
    result.recommendation || "Nu există o recomandare disponibilă.";
}

function setLoading(isLoading) {
  elements.scanButton.disabled = isLoading;
  elements.scanButton.classList.toggle("is-loading", isLoading);
  elements.scanLabel.textContent = isLoading ? "Se scanează..." : "Scanează pagina";
}

function showStatus(message, type = "info") {
  elements.statusCard.textContent = message;
  elements.statusCard.className = `glass-card status-card ${type === "error" ? "error" : ""}`;
  elements.statusCard.hidden = false;
}

function hideResult() {
  elements.resultCard.hidden = true;
}

function setFavicon(tab) {
  if (!tab?.favIconUrl || tab.favIconUrl.startsWith("chrome://")) {
    elements.favicon.hidden = true;
    return;
  }

  elements.favicon.src = tab.favIconUrl;
  elements.favicon.hidden = false;
}

function isScannableUrl(url) {
  if (!url) {
    return false;
  }

  try {
    const parsedUrl = new URL(url);
    return !BLOCKED_PROTOCOLS.includes(parsedUrl.protocol) && ["http:", "https:"].includes(parsedUrl.protocol);
  } catch {
    return false;
  }
}

function normalizeRisk(risk) {
  return ["safe", "suspicious", "dangerous"].includes(risk) ? risk : "suspicious";
}

function riskLabel(risk) {
  const labels = {
    safe: "Sigur",
    suspicious: "Suspicios",
    dangerous: "Periculos"
  };

  return labels[risk];
}

function scoreSummary(risk, score) {
  if (risk === "safe") {
    return `Scor ${score}/100. Pagina pare de încredere.`;
  }

  if (risk === "dangerous") {
    return `Scor ${score}/100. Evită introducerea datelor personale.`;
  }

  return `Scor ${score}/100. Verifică atent pagina înainte de acțiuni sensibile.`;
}

function clampScore(score) {
  const numericScore = Number(score);

  if (!Number.isFinite(numericScore)) {
    return 0;
  }

  return Math.min(100, Math.max(0, Math.round(numericScore)));
}

function isBackendConnectionError(error) {
  return error instanceof TypeError || String(error?.message || "").includes("Failed to fetch");
}

async function saveLastScan(result) {
  try {
    await chrome.storage.local.set({
      lastScan: {
        url: activeUrl,
        tabId: activeTab?.id,
        scannedAt: new Date().toISOString(),
        result
      }
    });
  } catch {
    // Storage failures should not block the scan result from being shown.
  }
}
