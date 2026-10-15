// Device search box on the dashboard: free text over serial, short id, model, depot and bay.
const MAX_TERMS = 8;

export function tokenize(query) {
  return String(query ?? '')
    .toLowerCase()
    .split(/[\s,;]+/)
    .filter(Boolean)
    .slice(0, MAX_TERMS);
}

export function searchDevices(devices, query) {
  const tokens = tokenize(query);
  if (tokens.length === 0) return devices;
  return devices.filter((d) => {
    const text = [d.serial, d.shortId, d.model, d.depot, d.bay].filter(Boolean).join(' ').toLowerCase();
    return tokens.every((t) => text.includes(t));
  });
}
