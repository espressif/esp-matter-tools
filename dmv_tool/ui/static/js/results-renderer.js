import { openClusterModal } from "./modal.js";
import { copyToClipboard, showCopySuccess } from "./utils.js";
import { setClusterCache } from "./cluster-cache.js";

let detailedResultsInteractionsBound = false;

export function renderValidationResults(validationData, parsedData) {
  const resultsSection = document.getElementById("resultsSection");
  if (resultsSection) {
    resultsSection.style.display = "block";
  }

  const summary = validationData.summary || {};
  const totalEndpoints = summary.total_endpoints || 0;
  const compliantEndpoints = summary.compliant_endpoints || 0;
  const nonCompliantEndpoints = summary.non_compliant_endpoints || 0;
  const complianceRate = totalEndpoints > 0
    ? Math.round((compliantEndpoints / totalEndpoints) * 100)
    : 0;

  document.getElementById("totalEndpoints").textContent = totalEndpoints;
  document.getElementById("compliantEndpoints").textContent = compliantEndpoints;
  document.getElementById("nonCompliantEndpoints").textContent = nonCompliantEndpoints;
  document.getElementById("complianceRate").textContent = `${complianceRate}%`;

  renderDetailedResults(validationData.endpoints || [], parsedData);
  resultsSection?.scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderDetailedResults(endpoints, parsedData) {
  const detailedResults = document.getElementById("detailedResults");
  if (!detailedResults) return;

  let html = "";

  endpoints.forEach(endpoint => {
    const endpointId = endpoint.endpoint || 0;
    const isCompliant = endpoint.is_compliant !== false;

    html += `
      <div class="endpoint-card">
        <div class="endpoint-header">
          <div class="endpoint-title">
            <i class="fas fa-plug"></i>
            Endpoint ${endpointId}
          </div>
          <span class="compliance-badge ${isCompliant ? 'badge-compliant' : 'badge-non-compliant'}">
            ${isCompliant ? '✓ Compliant' : '✗ Non-Compliant'}
          </span>
        </div>

        <div class="endpoint-content">
          <div class="device-types">
    `;

    (endpoint.device_types || []).forEach(deviceType => {
      const deviceTypeName = deviceType.device_type_name || "Unknown";
      const deviceTypeId = deviceType.device_type_id || "Unknown";
      const deviceCompliant = deviceType.is_compliant !== false;

      html += `
        <div class="device-type-card ${deviceCompliant ? '' : 'non-compliant'}">
          <div class="device-type-header">
            <div class="device-type-name">
              <i class="fas fa-microchip"></i>
              ${deviceTypeName.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
            </div>
            <div class="device-type-id">${deviceTypeId}</div>
          </div>
      `;

      const revisionIssues = (deviceType.revision_issues || []).filter(
        issue => issue.item_type === 'device_type'
      );
      if (revisionIssues.length > 0) {
        html += `
          <div class="revision-issues">
            <h4><i class="fas fa-exclamation-circle"></i> Device Type Revision Issues (${revisionIssues.length})</h4>
            <ul class="revision-list">
        `;
        revisionIssues.forEach(issue => {
          html += `
            <li class="revision-error">
              <i class="fas fa-times-circle"></i>
              <span class="issue-message">${issue.message || 'Revision issue'}</span>
            </li>
          `;
        });
        html += `</ul></div>`;
      }

      if (deviceType.cluster_validations && deviceType.cluster_validations.length > 0) {
        html += `<div class="clusters-grid">`;

        deviceType.cluster_validations.forEach(cluster => {
          const clusterId = cluster.cluster_id || "Unknown";
          const clusterName = cluster.cluster_name || "Unknown";
          const clusterCompliant = cluster.is_compliant !== false;
          const hasEventWarnings = (cluster.event_warnings || []).length > 0;
          const isClusterMissing = (cluster.missing_elements || []).some(
            el => el.type === 'cluster'
          );

          const endpointData = (parsedData?.endpoints || []).find(
            ep => ep.id === endpointId || ep.endpoint === endpointId
          );
          const actualClusterData = endpointData?.clusters?.[clusterId] || {};

          html += `
            <div class="cluster-card ${!isClusterMissing ? 'clickable-cluster' : ''} ${clusterCompliant ? (hasEventWarnings ? 'warning' : '') : 'non-compliant'}"
                 data-cluster-id="${clusterId}"
                 data-endpoint-id="${endpointId}"
                 ${!isClusterMissing ? 'role="button" tabindex="0" style="cursor: pointer;"' : ''}>
              <div class="cluster-header">
                <div class="cluster-info">
                  <div class="cluster-name">
                    <i class="fas fa-${isClusterMissing ? 'exclamation-triangle' : 'network-wired'}"></i>
                    ${clusterName.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                  </div>
                  <div class="cluster-description">${isClusterMissing ? 'Cluster not found in device' : 'Click to view details'}</div>
                </div>
                <div class="cluster-actions">
                  <div class="cluster-id">${clusterId}</div>
                  ${!isClusterMissing ? `
                    <div class="view-button">
                      <i class="fas fa-eye"></i>
                    </div>
                  ` : ''}
                </div>
              </div>

              <div class="cluster-stats">
                <div class="compliance-status">
                  <span><i class="fas fa-list"></i> ${(cluster.cluster_type || 'server').charAt(0).toUpperCase() + (cluster.cluster_type || 'server').slice(1)}</span>
                  ${!clusterCompliant ? `
                    <span style="color: var(--error-color);">
                      <i class="fas fa-times"></i> Non-Compliant
                      ${cluster.missing_elements ? `(${cluster.missing_elements.length} missing)` : ''}
                      ${cluster.duplicate_elements?.length > 0 ? `
                        <span style="margin-left: 5px;">
                          <i class="fas fa-clone"></i> ${cluster.duplicate_elements.length} duplicates
                        </span>
                      ` : ''}
                    </span>
                  ` : `
                    <span style="color: var(--success-color);">
                      <i class="fas fa-check"></i> Compliant
                      ${hasEventWarnings ? `
                        <span style="color: var(--warning-color); margin-left: 5px;">
                          <i class="fas fa-exclamation-triangle"></i> Warnings
                        </span>
                      ` : ''}
                    </span>
                  `}
                </div>
          `;

          if (actualClusterData.attributes) {
            const attrCount = Object.keys(actualClusterData.attributes).length;
            const cmdCount = (
              (actualClusterData.commands?.GeneratedCommandList?.GeneratedCommandList || []).length +
              (actualClusterData.commands?.AcceptedCommandList?.AcceptedCommandList || []).length
            );

            html += `
              <div class="data-stats">
                <div class="stat-item">
                  <i class="fas fa-list"></i>
                  <span class="stat-count">${attrCount}</span>
                  <span class="stat-label">Attributes</span>
                </div>
                <div class="stat-item">
                  <i class="fas fa-list"></i>
                  <span class="stat-count">${cmdCount}</span>
                  <span class="stat-label">Commands</span>
                </div>
              </div>
            `;
          }

          html += `</div>`;

          if (!isClusterMissing) {
            setClusterCache(endpointId, clusterId, {
              clusterData: actualClusterData,
              validationData: cluster,
            });
          }

          html += `</div>`;
        });

        html += `</div>`;
      }

      html += `</div>`;
    });

    html += `
          </div>
        </div>
      </div>
    `;
  });

  detailedResults.innerHTML = html;

  bindDetailedResultsInteractions();
}

function bindDetailedResultsInteractions() {
  if (detailedResultsInteractionsBound) return;
  const detailedResults = document.getElementById("detailedResults");
  if (!detailedResults) return;

  detailedResultsInteractionsBound = true;

  detailedResults.addEventListener("click", async (e) => {
    const target = e.target;
    if (!(target instanceof Element)) return;

    const clusterCard = target.closest(".cluster-card.clickable-cluster");
    if (clusterCard) {
      const clusterId = clusterCard.getAttribute("data-cluster-id");
      const endpointId = clusterCard.getAttribute("data-endpoint-id");
      if (clusterId && endpointId) {
        openClusterModal(clusterId, endpointId);
      }
      return;
    }

    const copyEl = target.closest(".device-type-id, .cluster-id");
    if (copyEl) {
      const text = copyEl.textContent || "";
      const success = await copyToClipboard(text);
      if (success) {
        showCopySuccess(copyEl);
      }
      return;
    }

    const header = target.closest(".device-type-header");
    if (header) {
      const card = header.closest(".device-type-card");
      if (!card) return;
      const content = card.querySelector(".clusters-grid");
      if (!content) return;
      const isVisible = content.style.display !== "none";
      content.style.display = isVisible ? "none" : "grid";

      let icon = header.querySelector(".expand-icon");
      if (!icon) {
        icon = document.createElement("span");
        icon.className = "expand-icon";
        header.appendChild(icon);
      }
      icon.textContent = isVisible ? "▶" : "▼";
    }
  });

  detailedResults.addEventListener("keydown", (e) => {
    if (e.key !== "Enter" && e.key !== " ") return;
    const target = e.target;
    if (!(target instanceof Element)) return;
    const clusterCard = target.closest(".cluster-card.clickable-cluster");
    if (!clusterCard) return;
    e.preventDefault();
    const clusterId = clusterCard.getAttribute("data-cluster-id");
    const endpointId = clusterCard.getAttribute("data-endpoint-id");
    if (clusterId && endpointId) {
      openClusterModal(clusterId, endpointId);
    }
  });
}

