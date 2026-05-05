import logger from '../utils/logger.js';
import dotenv from 'dotenv';

dotenv.config();

const VT_API_KEY = process.env.VT_API_KEY || '';
const OTX_API_KEY = process.env.OTX_API_KEY || '';

export const detectIndicatorType = (value) => {
  const q = String(value || '').trim();
  if (/^[a-fA-F0-9]{32}$/.test(q) || /^[a-fA-F0-9]{40}$/.test(q) || /^[a-fA-F0-9]{64}$/.test(q)) return 'hash';
  if (/^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(q)) return 'ip';
  if (/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/.test(q)) return 'domain';
  if (/^https?:\/\/[^\s/$.?#].[^\s]*$/i.test(q)) return 'url';
  return 'unknown';
};

export const queryVirusTotal = async (indicator, explicitType) => {
  const type = explicitType || detectIndicatorType(indicator);
  const q = String(indicator || '').trim();
  if (!VT_API_KEY) throw new Error('VT_API_KEY not configured');

  let endpoint;
  if (type === 'hash') endpoint = `files/${q}`;
  else if (type === 'ip') endpoint = `ip_addresses/${q}`;
  else if (type === 'domain') endpoint = `domains/${encodeURIComponent(q)}`;
  else if (type === 'url') {
    const submit = await fetch('https://www.virustotal.com/api/v3/urls', {
      method: 'POST',
      headers: {
        'x-apikey': VT_API_KEY,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ url: q }),
    });
    return await submit.json();
  } else {
    throw new Error('Invalid indicator type');
  }

  const r = await fetch(`https://www.virustotal.com/api/v3/${endpoint}`, { 
    headers: { 'x-apikey': VT_API_KEY } 
  });
  return await r.json();
};

export const queryOTX = async (ip) => {
  if (!OTX_API_KEY) throw new Error('OTX_API_KEY not configured');
  const r = await fetch(`https://otx.alienvault.com/api/v1/indicators/IPv4/${ip}/general`, { 
    headers: { 'X-OTX-API-KEY': OTX_API_KEY } 
  });
  return await r.json();
};
