import {
  initializeDragAndDrop,
  initializeFileUpload,
  initializeUploadNewButton,
  resetUploadArea,
} from "./file-upload.js";
import { closeClusterModal, initializeModal } from "./modal.js";
import {
  copyToClipboard,
  downloadJSON,
  showCopyFeedback,
  toggleDetailedResults,
} from "./utils.js";
import { initializeValidationFunctionality } from "./validation.js";

document.addEventListener("DOMContentLoaded", function () {
  window.addEventListener("pyodide-ready", function () {
    initializeFileUpload();
    initializeDragAndDrop();
    initializeValidationFunctionality();
    initializeUploadNewButton();
    initializeModal();
    loadExistingData();
    bindGlobalUiActions();
  });
});

function bindGlobalUiActions() {
  const copyCommandBtn = document.getElementById("copyCommandBtn");
  if (copyCommandBtn) {
    copyCommandBtn.addEventListener("click", async () => {
      const command =
        "./chip-tool any read-by-id 0xFFFFFFFF 0xFFFFFFFF <node-id> 0xFFFF > wildcard_logs.txt";
      const success = await copyToClipboard(command);
      if (success) {
        showCopyFeedback();
      }
    });
  }

  const downloadValidationReportBtn = document.getElementById(
    "downloadValidationReportBtn",
  );
  if (downloadValidationReportBtn) {
    downloadValidationReportBtn.addEventListener("click", () => {
      const validationData = localStorage.getItem("currentValidationData");
      if (validationData) {
        downloadJSON(JSON.parse(validationData), "validation_report.json");
      } else {
        alert("No validation data available to download");
      }
    });
  }

  const downloadParsedDataBtn = document.getElementById("downloadParsedDataBtn");
  if (downloadParsedDataBtn) {
    downloadParsedDataBtn.addEventListener("click", () => {
      const parsedData = localStorage.getItem("currentParsedData");
      if (parsedData) {
        downloadJSON(JSON.parse(parsedData), "parsed_data.json");
      } else {
        alert("No parsed data available to download");
      }
    });
  }

  const detailedResultsHeader = document.getElementById("detailedResultsHeader");
  if (detailedResultsHeader) {
    detailedResultsHeader.addEventListener("click", toggleDetailedResults);
  }

  document.addEventListener("click", (e) => {
    const target = e.target;
    if (!(target instanceof Element)) return;
    const anchor = target.closest('a[href^="#"]');
    if (!anchor) return;
    const href = anchor.getAttribute("href");
    if (!href || href === "#") return;
    const el = document.querySelector(href);
    if (!el) return;
    e.preventDefault();
    el.scrollIntoView({ behavior: "smooth", block: "start" });
  });
}

function loadExistingData() {
  const parsedData = localStorage.getItem("currentParsedData");
  const validationData = localStorage.getItem("currentValidationData");
  const uploadedFilename = localStorage.getItem("currentUploadedFilename");
  const detectedVersion = localStorage.getItem("detectedVersion");

  if (parsedData && uploadedFilename) {
    const uploadSection = document.getElementById("uploadSection");
    const uploadSuccessSection = document.getElementById("uploadSuccessSection");

    if (uploadSection) uploadSection.style.display = "none";
    if (uploadSuccessSection) uploadSuccessSection.style.display = "block";

    const filenameEl = document.getElementById("uploadedFilename");
    if (filenameEl) filenameEl.textContent = uploadedFilename;

    import("./pyodide-bridge.js").then(module => {
      module.getSupportedVersions().then(versions => {
        populateVersionDropdown(versions, detectedVersion);
      });
    });

    if (validationData) {
      import("./results-renderer.js").then(module => {
        module.renderValidationResults(
          JSON.parse(validationData),
          JSON.parse(parsedData)
        );
      });
    }
  }
}

function populateVersionDropdown(versions, detectedVersion) {
  const versionSelect = document.getElementById("complianceVersion");
  if (!versionSelect) return;

  while (versionSelect.options.length > 1) {
    versionSelect.remove(1);
  }

  if (detectedVersion && versions.includes(detectedVersion)) {
    const option = document.createElement("option");
    option.value = detectedVersion;
    option.textContent = `${detectedVersion} (Auto-detected - Recommended)`;
    option.selected = true;
    versionSelect.appendChild(option);
  }

  versions.forEach(version => {
    if (version !== detectedVersion) {
      const option = document.createElement("option");
      option.value = version;
      option.textContent = version;
      versionSelect.appendChild(option);
    }
  });
}

document.addEventListener("keydown", function (e) {
  if ((e.ctrlKey || e.metaKey) && e.key === "u") {
    e.preventDefault();
    const fileInput = document.getElementById("fileInput");
    if (fileInput) {
      fileInput.click();
    }
  }

  if (e.key === "Escape") {
    const modal = document.getElementById("clusterModal");
    if (modal && modal.style.display === "flex") {
      closeClusterModal();
    } else {
      resetUploadArea();
    }
  }
});
