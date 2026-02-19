import { appFlags } from "./app-flags.js";

export function formatFileSize(bytes) {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

export function showMessage(elementId, message, type) {
  const messageEl = document.getElementById(elementId);
  messageEl.style.display = "block";
  messageEl.className =
    "message-container " +
    (type === "error" ? "error-message" : "success-message");
  messageEl.innerHTML =
    '<i class="fas fa-' +
    (type === "error" ? "exclamation-triangle" : "check-circle") +
    '"></i> ' +
    message;
}

export function hideMessage(elementId) {
  document.getElementById(elementId).style.display = "none";
}

export function showError(message) {
  const uploadArea = document.getElementById("uploadArea");
  if (uploadArea) {
    const errorDiv = document.createElement("div");
    errorDiv.className = "error-message";
    errorDiv.innerHTML = `
            <strong>Error:</strong> ${message}
        `;
    uploadArea.parentNode.insertBefore(errorDiv, uploadArea.nextSibling);

    setTimeout(() => {
      if (errorDiv.parentNode) {
        errorDiv.parentNode.removeChild(errorDiv);
      }
    }, 5000);
  }

  appFlags.isProcessing = false;
}

export function showLoading() {
  const uploadSection = document.querySelector(".upload-section");
  if (uploadSection) {
    const existing = uploadSection.querySelector(".loading-overlay");
    if (existing) existing.remove();

    const loadingOverlay = document.createElement("div");
    loadingOverlay.className = "loading-overlay";
    loadingOverlay.innerHTML = `
            <div class="loading">
                <div class="loading-spinner"></div>
                <h3>Processing your file...</h3>
                <p>Parsing device data and running validation checks</p>
            </div>
        `;

    loadingOverlay.style.cssText = `
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(255, 255, 255, 0.95);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 1000;
            border-radius: 12px;
        `;

    uploadSection.style.position = "relative";
    uploadSection.appendChild(loadingOverlay);
  }
}

export function hideLoading() {
  const uploadSection = document.querySelector(".upload-section");
  if (uploadSection) {
    const loadingOverlay = uploadSection.querySelector(".loading-overlay");
    if (loadingOverlay) {
      loadingOverlay.remove();
    }
  }
}

export function copyToClipboard(text) {
  if (navigator.clipboard) {
    return navigator.clipboard
      .writeText(text)
      .then(() => true)
      .catch(() => fallbackCopyTextToClipboard(text));
  } else {
    return fallbackCopyTextToClipboard(text);
  }
}

function fallbackCopyTextToClipboard(text) {
  const textArea = document.createElement("textarea");
  textArea.value = text;
  textArea.style.top = "0";
  textArea.style.left = "0";
  textArea.style.position = "fixed";

  document.body.appendChild(textArea);
  textArea.focus();
  textArea.select();

  try {
    const successful = document.execCommand("copy");
    document.body.removeChild(textArea);
    return successful;
  } catch (err) {
    console.error("Fallback: Oops, unable to copy", err);
    document.body.removeChild(textArea);
    return false;
  }
}

export function showCopyFeedback() {
  const copyBtn = document.querySelector(".copy-btn");
  const originalHTML = copyBtn.innerHTML;

  copyBtn.innerHTML = '<i class="fas fa-check"></i>';
  copyBtn.style.background = "var(--success-color)";

  setTimeout(() => {
    copyBtn.innerHTML = originalHTML;
    copyBtn.style.background = "var(--accent-color)";
  }, 2000);
}

export function showCopySuccess(element) {
  const originalBg = element.style.backgroundColor;
  element.style.backgroundColor = "var(--success-color)";
  element.style.color = "white";

  setTimeout(() => {
    element.style.backgroundColor = originalBg;
    element.style.color = "";
  }, 1000);
}

export function updateProgress(percentage, message) {
  document.getElementById("progressFill").style.width = percentage + "%";
  document.getElementById("progressText").textContent = message;
}

export function showValidationLoader() {
  document.getElementById("validationLoader").style.display = "flex";
  document.body.style.overflow = "hidden";
}

export function hideValidationLoader() {
  document.getElementById("validationLoader").style.display = "none";
  document.body.style.overflow = "auto";
}

export function simulateProgress() {
  const steps = [
    { progress: 10, message: "Loading requirements...", delay: 200 },
    { progress: 25, message: "Parsing device data...", delay: 500 },
    { progress: 40, message: "Validating clusters...", delay: 800 },
    { progress: 60, message: "Checking attributes...", delay: 1200 },
    { progress: 80, message: "Verifying commands...", delay: 1500 },
    { progress: 95, message: "Finalizing results...", delay: 1800 },
  ];

  steps.forEach((step) => {
    setTimeout(() => {
      updateProgress(step.progress, step.message);
    }, step.delay);
  });
}

export function downloadFile(url, filename) {
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

export function downloadJSON(data, filename) {
  const jsonStr = JSON.stringify(data, null, 2);
  const blob = new Blob([jsonStr], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  downloadFile(url, filename);
  URL.revokeObjectURL(url);
}

export function toggleDetailedResults() {
  const detailedResults = document.getElementById("detailedResults");
  const toggleIcon = document.querySelector(".toggle-icon");

  if (detailedResults.style.display === "none") {
    detailedResults.style.display = "grid";
    toggleIcon.innerHTML =
      '<i class="fas fa-chevron-up"></i> Click to collapse';
  } else {
    detailedResults.style.display = "none";
    toggleIcon.innerHTML =
      '<i class="fas fa-chevron-down"></i> Click to expand';
  }
}
