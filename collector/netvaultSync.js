'use strict';

/**
 * NetVault Asset Sync
 * Pulls device data from NetVault DB and enriches LogVault's known_hosts table
 * Runs every 15 minutes from collector.js
 */

const { Pool } = require('pg');

// NetVault DB connection
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

// Brand name → syslog vendor mapping
const BRAND_TO_VENDOR = {
  'cisco':              'cisco',
  'fortinet':           'fortinet',
  'palo alto':          'paloalto',
  'palo alto networks': 'paloalto',
  'aruba':              'aruba',
  'aruba networks':     'aruba',
  'sangfor':            'sangfor',
  'forcepoint':         'forcepoint',
  'websense':           'forcepoint',
  'check point':        'checkpoint',
  'checkpoint':         'checkpoint',
  'juniper':            'juniper',
  'juniper networks':   'juniper',
  'microsoft':          'windows',
  'windows':            'windows',
  'sonicwall':          'sonicwall',
  'sonic wall':         'sonicwall',
  'hp':                 'generic',
  'hewlett packard':    'generic',
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
  const startTime = Date.now();
  console.log('[NetVaultSync] Starting asset sync...');

  try {
    // Pull all devices with brand and site info from NetVault
    const { rows: devices } = await nvPool.query(`
      SELECT
        d.id::TEXT          AS netvault_id,
        d.name              AS device_name,
        d.ip_address,
        d.model,
        d.device_status,
        d.lifecycle_status,
        b.name              AS brand_name,
        s.name              AS site_name,
        s.city              AS site_city,
        s.code              AS site_code
      FROM devices d
      LEFT JOIN brands b ON b.id = d.brand_id
      LEFT JOIN sites  s ON s.id = d.site_id
      WHERE d.ip_address IS NOT NULL
        AND d.ip_address != ''
        AND d.device_status != 'Decommed'
      ORDER BY d.name
    `);

    if (devices.length === 0) {
      console.log('[NetVaultSync] No devices found in NetVault');
      return;
    }

    console.log(`[NetVaultSync] Found ${devices.length} devices in NetVault`);

    let synced = 0;
    let skipped = 0;

    for (const device of devices) {
      try {
        const vendor   = brandToVendor(device.brand_name);
        const siteName = [device.site_name, device.site_city].filter(Boolean).join(' · ');
        const ipAddr   = device.ip_address.trim();

        // Validate IP address format
        if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ipAddr)) {
          skipped++;
          continue;
        }

        await lvPool.query(`
          INSERT INTO known_hosts (
            ip_address, hostname, vendor, description,
            site_name, brand, model, device_status, lifecycle_status,
            netvault_id, synced_from_nv, last_synced, last_seen
          ) VALUES (
            $1::inet, $2, $3, $4,
            $5, $6, $7, $8, $9,
            $10, TRUE, NOW(), NOW()
          )
          ON CONFLICT (ip_address) DO UPDATE SET
            hostname         = EXCLUDED.hostname,
            vendor           = EXCLUDED.vendor,
            description      = EXCLUDED.description,
            site_name        = EXCLUDED.site_name,
            brand            = EXCLUDED.brand,
            model            = EXCLUDED.model,
            device_status    = EXCLUDED.device_status,
            lifecycle_status = EXCLUDED.lifecycle_status,
            netvault_id      = EXCLUDED.netvault_id,
            synced_from_nv   = TRUE,
            last_synced      = NOW()
        `, [
          ipAddr,
          device.device_name,
          vendor,
          `${device.brand_name || ''} ${device.model || ''}`.trim() || null,
          siteName || null,
          device.brand_name || null,
          device.model || null,
          device.device_status || null,
          device.lifecycle_status || null,
          device.netvault_id,
        ]);
        synced++;
      } catch (err) {
        console.error(`[NetVaultSync] Failed to sync device ${device.device_name} (${device.ip_address}):`, err.message);
        skipped++;
      }
    }

    const elapsed = Date.now() - startTime;
    console.log(`[NetVaultSync] Done — ${synced} synced, ${skipped} skipped in ${elapsed}ms`);

  } catch (err) {
    // NetVault DB unreachable — log but don't crash collector
    console.error('[NetVaultSync] Failed to connect to NetVault DB:', err.message);
  }
}

module.exports = { syncFromNetVault };
