const cache = new Map();

function key(endpointId, clusterId) {
  return `${endpointId}_${clusterId}`;
}

export function setClusterCache(endpointId, clusterId, payload) {
  cache.set(key(endpointId, clusterId), payload);
}

export function getClusterCache(endpointId, clusterId) {
  return cache.get(key(endpointId, clusterId)) || null;
}

export function clearClusterCache() {
  cache.clear();
}

