'use strict';
// Server-side version of NetVault sync for the API endpoint
// Same logic as collector/netvaultSync.js but required by api/server.js

const { Pool } = require('pg');

const nvPool = new Pool({
  host:     process.env.NETVAULT_DB_HOST || 'localhost',
  port:     parseInt(process.env.NETVAULT_DB_PORT || '5432'),
  database: process.env.NETVAULT_DB_NAME || 'netvault',
  user:     process.env.NETVAULT_DB_USER || 'netvault',
  password: process.env.NETVAULT_DB_PASS,
  ssl:      false,
  max:      3,
  idleTimeoutMillis: 30000,
});

const BRAND_TO_VENDOR = {
  'cisco': 'cisco', 'fortinet': 'fortinet',
  'palo alto': 'paloalto', 'palo alto networks': 'paloalto',
  'aruba': 'aruba', 'aruba networks': 'aruba',
  'sangfor': 'sangfor', 'forcepoint': 'generic',
  'juniper': 'generic', 'hp': 'generic',
};

function brandToVendor(brandName) {
  if (!brandName) return 'generic';
  const lower = brandName.toLowerCase();
  for (const [key, vendor] of Object.entries(BRAND_TO_VENDOR)) {
    if (lower.includes(key)) return vendor;
  }
  return 'generic';
}

async function syncFromNetVault(lvPool) {
  const { rows: devices } = await nvPool.query(`
    SELECT d.id::TEXT AS netvault_id, d.name AS device_name, d.ip_address,
      d.model, d.device_status, d.lifecycle_status,
      b.name AS brand_name, s.name AS site_name, s.city AS site_city
    FROM devices d
    LEFT JOIN brands b ON b.id = d.brand_id
    LEFT JOIN sites  s ON s.id = d.site_id
    WHERE d.ip_address IS NOT NULL AND d.ip_address != ''
      AND d.device_status != 'Decommed'
  `);

  let synced = 0;
  for (const device of devices) {
    try {
      const ipAddr = device.ip_address.trim();
      if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ipAddr)) continue;
      const vendor   = brandToVendor(device.brand_name);
      const siteName = [device.site_name, device.site_city].filter(Boolean).join(' · ');
      await lvPool.query(`
        INSERT INTO known_hosts (
          ip_address, hostname, vendor, description,
          site_name, brand, model, device_status, lifecycle_status,
          netvault_id, synced_from_nv, last_synced, last_seen
        ) VALUES ($1::inet,$2,$3,$4,$5,$6,$7,$8,$9,$10,TRUE,NOW(),NOW())
        ON CONFLICT (ip_address) DO UPDATE SET
          hostname=EXCLUDED.hostname, vendor=EXCLUDED.vendor,
          description=EXCLUDED.description, site_name=EXCLUDED.site_name,
          brand=EXCLUDED.brand, model=EXCLUDED.model,
          device_status=EXCLUDED.device_status,
          lifecycle_status=EXCLUDED.lifecycle_status,
          netvault_id=EXCLUDED.netvault_id,
          synced_from_nv=TRUE, last_synced=NOW()
      `, [ipAddr, device.device_name, vendor,
          `${device.brand_name || ''} ${device.model || ''}`.trim() || null,
          siteName || null, device.brand_name || null, device.model || null,
          device.device_status || null, device.lifecycle_status || null,
          device.netvault_id]);
      synced++;
    } catch (_) {}
  }
  console.log(`[NetVaultSync] API sync: ${synced} devices`);
  return { synced };
}

module.exports = { syncFromNetVault };
