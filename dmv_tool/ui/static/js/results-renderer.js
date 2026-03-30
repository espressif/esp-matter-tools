import { openClusterModal } from "./modal.js";
import { copyToClipboard, showCopySuccess } from "./utils.js";
import { setClusterCache } from "./cluster-cache.js";

let detailedResultsInteractionsBound = false;

/** Parsed JSON key lookup for modal / stats — not conformance logic. */
function clusterIdToInt(clusterId) {
  if (clusterId == null || clusterId === "") return NaN;
  const s = String(clusterId).trim();
  if (/^0x/i.test(s)) return parseInt(s, 16);
  if (/^\d+$/.test(s)) return parseInt(s, 10);
  return parseInt(s, 0);
}

function clusterIdToCanonicalHex(clusterId) {
  const n = clusterIdToInt(clusterId);
  if (Number.isNaN(n)) return String(clusterId);
  return `0x${n.toString(16).toUpperCase().padStart(4, "0")}`;
}

function getClusterDataCaseInsensitive(clusters, clusterId) {
  if (!clusters || clusterId == null) return {};
  const canon = clusterIdToCanonicalHex(clusterId);
  if (clusters[canon]) return clusters[canon];
  if (clusters[clusterId]) return clusters[clusterId];
  const want = clusterIdToInt(clusterId);
  for (const k of Object.keys(clusters)) {
    if (clusterIdToInt(k) === want) return clusters[k];
  }
  return {};
}

function findParsedEndpoint(parsedData, endpointId) {
  return (parsedData?.endpoints || []).find(
    (e) => e.id === endpointId || e.endpoint === endpointId,
  );
}

/** Extra cluster count from validator JSON only (summary, or sum of endpoint.extra_clusters). */
function totalExtraClustersFromValidation(validationData) {
  const summary = validationData.summary || {};
  if (typeof summary.total_extra_clusters === "number") {
    return summary.total_extra_clusters;
  }
  return (validationData.endpoints || []).reduce(
    (n, ep) => n + (Array.isArray(ep.extra_clusters) ? ep.extra_clusters.length : 0),
    0,
  );
}

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
  const totalExtraClusters = totalExtraClustersFromValidation(validationData);

  document.getElementById("totalEndpoints").textContent = totalEndpoints;
  document.getElementById("compliantEndpoints").textContent = compliantEndpoints;
  document.getElementById("nonCompliantEndpoints").textContent = nonCompliantEndpoints;
  document.getElementById("complianceRate").textContent = `${complianceRate}%`;
  const extraEl = document.getElementById("totalExtraClusters");
  if (extraEl) extraEl.textContent = totalExtraClusters;

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
    const endpointData = findParsedEndpoint(parsedData, endpointId);
    const extraClusters = endpoint.extra_clusters || [];
    const extraCount = extraClusters.length;
    const endpointCardClass =
      extraCount > 0 ? "endpoint-card endpoint-card--has-extra-clusters" : "endpoint-card";

    html += `
      <div class="${endpointCardClass}" data-endpoint-id="${endpointId}">
        <div class="endpoint-header">
          <div class="endpoint-title endpoint-title-row">
            <span class="endpoint-title-main">
              <i class="fas fa-plug"></i>
              Endpoint ${endpointId}
            </span>
            ${
              extraCount > 0
                ? `<span class="endpoint-extra-count-badge" title="Extra clusters on this endpoint (not required by any device type here)">
              <i class="fas fa-puzzle-piece" aria-hidden="true"></i>
              <span>${extraCount} extra cluster${extraCount === 1 ? "" : "s"}</span>
            </span>`
                : ""
            }
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

      const cv = deviceType.cluster_validations || [];
      const hasClusterGrids = cv.length > 0;

      if (hasClusterGrids) {
        html += `<div class="device-type-cluster-grids">`;
      }

      if (cv.length > 0) {
        html += `<div class="clusters-grid">`;

        cv.forEach(cluster => {
          const clusterId = cluster.cluster_id || "Unknown";
          const clusterName = cluster.cluster_name || "Unknown";
          const clusterCompliant = cluster.is_compliant !== false;
          const hasEventWarnings = (cluster.event_warnings || []).length > 0;
          const isClusterMissing = (cluster.missing_elements || []).some(
            el => el.type === 'cluster'
          );

          const actualClusterData = getClusterDataCaseInsensitive(
            endpointData?.clusters,
            clusterId,
          );

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

      if (hasClusterGrids) {
        html += `</div>`;
      }

      html += `</div>`;
    });

    html += `</div>`;

    if (extraClusters.length > 0) {
      html += `
        <div class="endpoint-extra-clusters-section extra-clusters-section extra-clusters-panel" id="endpoint-${endpointId}-extra-clusters">
          <h4 class="extra-clusters-section-title">
            <span class="extra-clusters-badge" aria-hidden="true">Extra Clusters</span>
          </h4>
          <p class="extra-clusters-section-hint">Extra clusters are skipped from conformance check.</p>
          <div class="clusters-grid clusters-grid--extra">
      `;
      extraClusters.forEach(cluster => {
        const clusterId = cluster.cluster_id || "Unknown";
        const clusterName = cluster.cluster_name || "Unknown";
        const actualClusterData = getClusterDataCaseInsensitive(
          endpointData?.clusters,
          clusterId,
        );

        html += `
          <div class="cluster-card clickable-cluster extra-cluster"
               data-cluster-id="${clusterId}"
               data-endpoint-id="${endpointId}"
               data-cluster-kind="extra"
               role="button" tabindex="0" style="cursor: pointer;">
            <div class="cluster-header">
              <div class="cluster-info">
                <div class="cluster-name">
                  <i class="fas fa-network-wired"></i>
                  ${clusterName.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                </div>
                <div class="cluster-description">${cluster.message || 'Not required by any device type on this endpoint'}</div>
              </div>
              <div class="cluster-actions">
                <div class="cluster-id">${clusterId}</div>
                <div class="view-button">
                  <i class="fas fa-eye"></i>
                </div>
              </div>
            </div>
            <div class="cluster-stats">
              <div class="compliance-status">
                <span><i class="fas fa-list"></i> ${(cluster.cluster_type || 'server').charAt(0).toUpperCase() + (cluster.cluster_type || 'server').slice(1)}</span>
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
        html += `</div></div>`;
        setClusterCache(endpointId, clusterId, {
          clusterData: actualClusterData,
          validationData: cluster,
        });
      });
      html += `</div></div>`;
    }

    html += `
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
      const content = card.querySelector(".device-type-cluster-grids");
      if (!content) return;
      const isVisible = content.style.display !== "none";
      content.style.display = isVisible ? "none" : "block";

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
