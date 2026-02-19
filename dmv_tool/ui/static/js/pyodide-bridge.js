let pyodide = null;

export async function initializePyodide() {
  if (pyodide) {
    return pyodide;
  }

  pyodide = await loadPyodide({
    indexURL: "https://cdn.jsdelivr.net/pyodide/v0.24.1/full/",
  });

  await pyodide.loadPackage("micropip");

  try {
    await pyodide.runPythonAsync(`
      import micropip
      await micropip.install(["esp-matter-dm-validator"])
      import dmv_tool  # sanity check
    `);
  } catch (error) {
    const msg = error?.message || String(error);
    throw new Error(`Python package not available: esp-matter-dm-validator (${msg})`);
  }

  try {
    await pyodide.runPythonAsync(`
      import micropip
      await micropip.install(['pyodide-http'])
      import pyodide_http
      pyodide_http.patch_all()
    `);
  } catch (error) {
    console.warn("Could not install pyodide-http, continuing without it:", error);
  }
  return pyodide;
}

export async function parseDatamodelLogs(logData) {
  await ensurePyodideReady();

  try {
    const escapedLogData = logData
      .replace(/\\/g, '\\\\')
      .replace(/`/g, '\\`')
      .replace(/\${/g, '\\${');

    const pythonCode1 = `import json
log_data_str = """${escapedLogData}"""`;

    pyodide.runPython(pythonCode1);

    const pythonCode2 = `from dmv_tool.parsers.wildcard_logs import parse_datamodel_logs
import json

parsed = parse_datamodel_logs(log_data_str)
json.dumps(parsed)`;

    const result = await pyodide.runPythonAsync(pythonCode2);
    return JSON.parse(result);
  } catch (error) {
    console.error("Error parsing logs:", error);
    throw new Error(`Failed to parse logs: ${error.message}`);
  }
}

export async function detectSpecVersion(parsedData) {
  await ensurePyodideReady();

  try {
    pyodide.globals.set('parsed_data_json', JSON.stringify(parsedData));

    const pythonCode = `from dmv_tool.validators.conformance_checker import detect_spec_version_from_parsed_data
import json

parsed_data = json.loads(parsed_data_json)
version = detect_spec_version_from_parsed_data(parsed_data)
version if version else "master"`;

    const result = await pyodide.runPythonAsync(pythonCode);

    return result;
  } catch (error) {
    console.error("Error detecting version:", error);
    return null;
  }
}

export async function validateDeviceConformance(parsedData, specVersion) {
  await ensurePyodideReady();

  try {
    pyodide.globals.set('parsed_data_json', JSON.stringify(parsedData));
    pyodide.globals.set('spec_version_str', specVersion);

    const pythonCode = `from dmv_tool.validators.conformance_checker import validate_device_conformance
import json

parsed_data = json.loads(parsed_data_json)
spec_version = spec_version_str

validation_results = validate_device_conformance(parsed_data, spec_version)
json.dumps(validation_results)`;

    const result = await pyodide.runPythonAsync(pythonCode);

    return JSON.parse(result);
  } catch (error) {
    console.error("Error validating conformance:", error);
    throw new Error(`Validation failed: ${error.message}`);
  }
}

export async function getSupportedVersions() {
  await ensurePyodideReady();

  try {
    const pythonCode = `from dmv_tool.configs.constants import SUPPORTED_SPEC_VERSIONS
import json

json.dumps(list(SUPPORTED_SPEC_VERSIONS))`;

    const result = await pyodide.runPythonAsync(pythonCode);

    return JSON.parse(result);
  } catch (error) {
    console.error("Error getting supported versions:", error);
    throw new Error("Error getting supported versions: " + error.message);
  }
}

async function ensurePyodideReady() {
  if (!pyodide) {
    await initializePyodide();
  }
}

let initializationPromise = null;

export function getPyodide() {
  if (!initializationPromise) {
    initializationPromise = initializePyodide();
  }
  return initializationPromise;
}

getPyodide().then(() => {
  const loadingEl = document.getElementById('pyodide-loading');
  const mainContent = document.getElementById('mainContent');
  if (loadingEl) loadingEl.style.display = 'none';
  if (mainContent) mainContent.style.display = 'block';

  window.dispatchEvent(new CustomEvent('pyodide-ready'));
}).catch(error => {
  console.error("Failed to initialize Pyodide:", error);
  const loadingEl = document.getElementById('pyodide-loading');
  if (loadingEl) {
    let errorMessage = error.message || 'Unknown error occurred';
    let troubleshootingTips = '';

    if (errorMessage.includes('Python package not available')) {
      troubleshootingTips = `
        <div style="margin-top: 20px; padding: 15px; background: #fff3cd; border-radius: 6px; text-align: left; max-width: 600px; margin-left: auto; margin-right: auto;">
          <h4 style="margin-top: 0; color: #856404;"><i class="fas fa-lightbulb"></i> Troubleshooting Tips:</h4>
          <ul style="margin: 10px 0; padding-left: 20px; color: #856404;">
            <li>Check your internet connection</li>
            <li>Try refreshing the page</li>
            <li>Check browser console for detailed error messages</li>
            <li>Ensure esp-matter-dm-validator package is available Install it via pip: <code>pip install esp-matter-dm-validator</code></li>
            <li>For local development, serve the UI with: <code>python3 -m http.server 8000 --directory dmv_tool/ui</code></li>
          </ul>
        </div>
      `;
    }

    loadingEl.innerHTML = `
      <div style="text-align: center; color: #d32f2f;">
        <i class="fas fa-exclamation-triangle fa-3x" style="margin-bottom: 20px;"></i>
        <h3>Failed to Load Python Runtime</h3>
        <p style="font-weight: 500;">${errorMessage}</p>
        ${troubleshootingTips}
        <p style="margin-top: 20px;">
          <button onclick="window.location.reload()" class="btn btn-primary" style="padding: 10px 20px; cursor: pointer;">
            <i class="fas fa-redo"></i> Refresh Page
          </button>
        </p>
      </div>
    `;
  }
});

