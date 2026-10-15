// Fuel surcharges on cross-border consignments are quoted in EUR. The conversion uses the ECB's daily
// reference rates, fetched at most once an hour.
import { get } from 'node:https';

const ECB_DAILY_RATES = 'https://www.ecb.europa.eu/stats/eurofxref/eurofxref-daily.xml';
const REFRESH_MS = 60 * 60 * 1000;
const SURCHARGE_PERCENT = 6.5;
let cached = null;

function fetchText(url) {
  return new Promise((resolve, reject) => {
    get(url, { timeout: 10_000 }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        reject(new Error(`rates request failed with HTTP ${res.statusCode}`));
        return;
      }
      let text = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { text += chunk; });
      res.on('end', () => resolve(text));
    }).on('error', reject);
  });
}

export async function eurRate(currency = 'GBP', now = Date.now()) {
  if (!cached || now - cached.at > REFRESH_MS) {
    const xml = await fetchText(ECB_DAILY_RATES);
    const rates = {};
    for (const m of xml.matchAll(/currency='([A-Z]{3})' rate='([\d.]+)'/g)) rates[m[1]] = Number(m[2]);
    cached = { at: now, rates };
  }
  return cached.rates[currency] ?? null;
}

export function surchargeEur(fuelCostGbp, gbpPerEur) {
  if (!gbpPerEur) return null;
  const eur = fuelCostGbp / gbpPerEur;
  return Math.round(eur * SURCHARGE_PERCENT) / 100;
}
