import {
  hideMessage,
  hideValidationLoader,
  showMessage,
  showValidationLoader,
  simulateProgress,
  updateProgress,
} from "./utils.js";
import { validateDeviceConformance } from "./pyodide-bridge.js";
import { renderValidationResults } from "./results-renderer.js";
import { appFlags } from "./app-flags.js";

export function initializeValidationFunctionality() {
  initializeValidateButton();
  restoreSelectedVersion();
}

function initializeValidateButton() {
  const validateBtn = document.getElementById("validateBtn");
  const versionSelect = document.getElementById("complianceVersion");

  if (validateBtn && versionSelect) {
    validateBtn.addEventListener("click", async function () {
      const selectedVersion = versionSelect.value;

      if (!selectedVersion) {
        showMessage(
          "validateMessage",
          "Please select a data model version to validate against",
          "error",
        );
        return;
      }

      const parsedDataStr = localStorage.getItem("currentParsedData");
      if (!parsedDataStr) {
        showMessage(
          "validateMessage",
          "No parsed data found. Please upload a file first.",
          "error",
        );
        return;
      }

      sessionStorage.setItem("selectedVersion", selectedVersion);
      const parseId = localStorage.getItem("currentParseId");
      if (parseId) {
        localStorage.setItem(`selectedComplianceVersion:${parseId}`, selectedVersion);
      }

      appFlags.isValidationInProgress = true;
      appFlags.isIntentionalNavigation = true;

      showValidationLoader();
      hideMessage("validateMessage");
      simulateProgress();

      try {
        const parsedData = JSON.parse(parsedDataStr);

        updateProgress(50, "Validating device conformance...");
        const validationResults = await validateDeviceConformance(parsedData, selectedVersion);

        localStorage.setItem("currentValidationData", JSON.stringify(validationResults));

        updateProgress(100, "Validation complete!");

        setTimeout(() => {
          hideValidationLoader();
          appFlags.isValidationInProgress = false;
          appFlags.isIntentionalNavigation = false;
          renderValidationResults(validationResults, parsedData);
        }, 1000);
      } catch (error) {
        appFlags.isValidationInProgress = false;
        appFlags.isIntentionalNavigation = false;
        hideValidationLoader();
        showMessage("validateMessage", `Validation failed: ${error.message}`, "error");
      }
    });
  }
}

function restoreSelectedVersion() {
  try {
    const versionSelect = document.getElementById("complianceVersion");
    const validateBtn = document.getElementById("validateBtn");

    if (!versionSelect) {
      console.debug("Version select element not found");
      return;
    }

    const parseId = versionSelect.dataset
      ? versionSelect.dataset.parseId
      : null;
    const detectedVersion = versionSelect.dataset
      ? versionSelect.dataset.detectedVersion
      : null;

    if (parseId) {
      const storageKey = `selectedComplianceVersion:${parseId}`;

      try {
        const saved = localStorage.getItem(storageKey);
        if (
          saved &&
          versionSelect.querySelector(`option[value="${CSS.escape(saved)}"]`)
        ) {
          versionSelect.value = saved;
        } else if (
          detectedVersion &&
          versionSelect.querySelector(
            `option[value="${CSS.escape(detectedVersion)}"]`,
          )
        ) {
          versionSelect.value = detectedVersion;
        }
      } catch (e) {
        console.warn("Failed to access localStorage:", e);
      }

      versionSelect.addEventListener("change", function () {
        try {
          localStorage.setItem(storageKey, versionSelect.value || "");
        } catch (e) {
          console.warn("Failed to save selection:", e);
        }
      });

      if (validateBtn) {
        validateBtn.addEventListener("click", function () {
          try {
            localStorage.setItem(storageKey, versionSelect.value || "");
          } catch (e) {
            console.warn("Failed to save selection on validate:", e);
          }
        });
      }

      return;
    }

    let storedVersion;
    try {
      storedVersion = sessionStorage.getItem("selectedVersion");
    } catch (e) {
      console.warn("Failed to access sessionStorage:", e);
      return;
    }

    if (storedVersion) {
      try {
        const autoDetectedOption =
          versionSelect.querySelector("option[selected]");

        if (autoDetectedOption && !appFlags.isValidationInProgress) {
          try {
            sessionStorage.removeItem("selectedVersion");
          } catch (e) {
            console.warn("Failed to remove stored version:", e);
          }
          return;
        }

        versionSelect.value = storedVersion;

        const selectedOption = versionSelect.querySelector(
          `option[value="${CSS.escape(storedVersion)}"]`,
        );
        if (selectedOption) {
          const optionIndex = Array.from(versionSelect.options).indexOf(
            selectedOption,
          );
          if (optionIndex >= 0) {
            versionSelect.selectedIndex = optionIndex;
          }
        }
      } catch (e) {
        console.warn("Error processing stored version:", e);
      }
    }
  } catch (e) {
    console.error("Error in restoreSelectedVersion:", e);
  }
}
