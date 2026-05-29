/**
 * LogVault Correlation Engine
 * Real-time multi-event pattern detection
 * Runs inside the collector process as logs arrive
 *
 * Each rule watches a sliding time window of recent events
 * and fires a correlated alert when a pattern is matched
 */

'use strict';

// ── In-memory event buffers per correlation rule ──────────────
// Structure: Map<ruleId, Map<groupKey, [{timestamp, entry}]>>
const eventBuffers = new Map();

// ── Correlation Rules ─────────────────────────────────────────
const CORRELATION_RULES = [

  // ── 1. Brute Force Success ──────────────────────────────────
  // 3+ failed logins from same source IP followed by a success within 10 min
  {
    id:          'BRUTE_FORCE_SUCCESS',
    name:        'Brute Force Login Success',
    description: 'Multiple failed logins from the same IP followed by a successful login',
    severity:    'critical',
    windowMs:    10 * 60 * 1000, // 10 minutes
    phases: [
      {
        name:      'failures',
        minCount:  3,
        match:     (e) => (
          (e.vendor === 'cisco' && ['login_failed','auth_failed'].includes(e.structured_data?.subcategory)) ||
          (e.message && /login failed|authentication fail/i.test(e.message))
        ),
        groupBy:   (e) => e.source_ip,
      },
      {
        name:      'success',
        minCount:  1,
        mustFollow: 'failures',
        match:     (e) => (
          (e.vendor === 'cisco' && e.structured_data?.subcategory === 'login_success') ||
          (e.message && /login success|authenticated successfully/i.test(e.message))
        ),
        groupBy:   (e) => e.source_ip,
      },
    ],
    buildAlert: (groups, entry) => ({
      source_ip:      entry.source_ip,
      source_host:    entry.source_host,
      match_count:    groups.failures?.length || 0,
      sample_message: `Brute force success: ${groups.failures?.length || 0} failures then login succeeded from ${entry.source_ip}`,
    }),
  },

  // ── 2. Port Scan Detection ──────────────────────────────────
  // Same source IP hitting 8+ unique destinations denied within 3 min
  {
    id:          'PORT_SCAN',
    name:        'Port Scan Detected',
    description: 'Single source IP hitting many destinations in a short window',
    severity:    'warning',
    windowMs:    3 * 60 * 1000, // 3 minutes
    phases: [
      {
        name:     'denies',
        minCount: 8,
        uniqueKey: (e) => e.structured_data?.dstip, // count unique destinations
        match:    (e) => (
          e.vendor === 'fortinet' &&
          e.structured_data?.action === 'deny' &&
          e.structured_data?.srcip
        ),
        groupBy:  (e) => e.structured_data?.srcip || e.source_ip,
      },
    ],
    buildAlert: (groups, entry) => {
      const dsts = [...new Set(groups.denies?.map(e => e.entry.structured_data?.dstip).filter(Boolean))];
      return {
        source_ip:      entry.structured_data?.srcip || entry.source_ip,
        source_host:    entry.source_host,
        match_count:    dsts.length,
        sample_message: `Port scan: ${entry.structured_data?.srcip || entry.source_ip} hit ${dsts.length} unique destinations. Sample: ${dsts.slice(0,3).join(', ')}`,
      };
    },
  },

  // ── 3. Interface Flapping ───────────────────────────────────
  // Same interface up/down 4+ times within 10 min
  {
    id:          'INTERFACE_FLAPPING',
    name:        'Interface Flapping Detected',
    description: 'Same interface changed state multiple times — possible physical layer issue',
    severity:    'warning',
    windowMs:    10 * 60 * 1000,
    phases: [
      {
        name:     'flaps',
        minCount: 4,
        match:    (e) => (
          e.vendor === 'cisco' &&
          e.structured_data?.category === 'interface' &&
          e.structured_data?.interface
        ),
        groupBy:  (e) => `${e.source_ip}__${e.structured_data?.interface}`,
      },
    ],
    buildAlert: (groups, entry) => ({
      source_ip:      entry.source_ip,
      source_host:    entry.source_host,
      match_count:    groups.flaps?.length || 0,
      sample_message: `Interface flapping: ${entry.structured_data?.interface} on ${entry.source_host || entry.source_ip} changed state ${groups.flaps?.length || 0} times in 10 min`,
    }),
  },

  // ── 4. MAC Flapping (Loop) ──────────────────────────────────
  // MAC flap events from same switch within 2 min = active loop
  {
    id:          'NETWORK_LOOP',
    name:        'Network Loop Detected',
    description: 'MAC address flapping indicates an active network loop',
    severity:    'critical',
    windowMs:    2 * 60 * 1000,
    phases: [
      {
        name:     'macflaps',
        minCount: 2,
        match:    (e) => (
          e.vendor === 'cisco' &&
          e.structured_data?.subcategory === 'mac_flap'
        ),
        groupBy:  (e) => e.source_ip,
      },
    ],
    buildAlert: (groups, entry) => ({
      source_ip:      entry.source_ip,
      source_host:    entry.source_host,
      match_count:    groups.macflaps?.length || 0,
      sample_message: `Network loop: MAC flapping detected on ${entry.source_host || entry.source_ip}. Disable suspect port immediately.`,
    }),
  },

  // ── 5. After-Hours Config Change ───────────────────────────
  // Any config change between 10PM and 6AM
  {
    id:          'AFTER_HOURS_CONFIG',
    name:        'After-Hours Configuration Change',
    description: 'Network device configuration changed outside business hours',
    severity:    'warning',
    windowMs:    60 * 1000,
    phases: [
      {
        name:     'config',
        minCount: 1,
        match:    (e) => {
          const hour = new Date().getHours();
          return (hour >= 22 || hour < 6) && (
            (e.vendor === 'cisco' && e.structured_data?.subcategory === 'config_change') ||
            (e.message && /configured from|configuration changed/i.test(e.message))
          );
        },
        groupBy:  (e) => e.source_ip,
      },
    ],
    buildAlert: (groups, entry) => ({
      source_ip:      entry.source_ip,
      source_host:    entry.source_host,
      match_count:    1,
      sample_message: `After-hours config change on ${entry.source_host || entry.source_ip} at ${new Date().toLocaleTimeString()}: ${entry.message?.substring(0, 100)}`,
    }),
  },

  // ── 6. STP Topology Change Surge ───────────────────────────
  // 3+ STP topology changes within 5 min = unstable STP
  {
    id:          'STP_INSTABILITY',
    name:        'STP Instability Detected',
    description: 'Multiple spanning tree topology changes in a short window',
    severity:    'warning',
    windowMs:    5 * 60 * 1000,
    phases: [
      {
        name:     'stpchanges',
        minCount: 3,
        match:    (e) => (
          e.vendor === 'cisco' &&
          ['topology_change','root_change','loop_detected'].includes(e.structured_data?.subcategory)
        ),
        groupBy:  (e) => e.source_ip,
      },
    ],
    buildAlert: (groups, entry) => ({
      source_ip:      entry.source_ip,
      source_host:    entry.source_host,
      match_count:    groups.stpchanges?.length || 0,
      sample_message: `STP instability: ${groups.stpchanges?.length || 0} topology changes on ${entry.source_host || entry.source_ip} in 5 min`,
    }),
  },

  // ── 7. Repeated IPS Hits from Same Source ──────────────────
  // Same source IP triggering IPS 5+ times in 5 min
  {
    id:          'IPS_REPEATED_ATTACK',
    name:        'Repeated IPS Triggers',
    description: 'Same source IP repeatedly triggering IPS signatures',
    severity:    'critical',
    windowMs:    5 * 60 * 1000,
    phases: [
      {
        name:     'ipshits',
        minCount: 5,
        match:    (e) => (
          e.vendor === 'fortinet' &&
          e.structured_data?.type === 'utm' &&
          e.structured_data?.srcip
        ),
        groupBy:  (e) => e.structured_data?.srcip || e.source_ip,
      },
    ],
    buildAlert: (groups, entry) => ({
      source_ip:      entry.structured_data?.srcip || entry.source_ip,
      source_host:    entry.source_host,
      match_count:    groups.ipshits?.length || 0,
      sample_message: `Repeated IPS: ${entry.structured_data?.srcip || entry.source_ip} triggered ${groups.ipshits?.length || 0} IPS events in 5 min`,
    }),
  },

  // ── 8. VPN Credential Stuffing ─────────────────────────────
  // 5+ VPN login failures in 5 min
  {
    id:          'VPN_BRUTE_FORCE',
    name:        'VPN Brute Force Attempt',
    description: 'Multiple VPN login failures from the same source',
    severity:    'error',
    windowMs:    5 * 60 * 1000,
    phases: [
      {
        name:     'vpnfails',
        minCount: 5,
        match:    (e) => (
          e.vendor === 'fortinet' &&
          (e.structured_data?.subtype === 'vpn' || /vpn/i.test(e.message || '')) &&
          /fail|error/i.test(e.message || '')
        ),
        groupBy:  (e) => e.structured_data?.srcip || e.source_ip,
      },
    ],
    buildAlert: (groups, entry) => ({
      source_ip:      entry.structured_data?.srcip || entry.source_ip,
      source_host:    entry.source_host,
      match_count:    groups.vpnfails?.length || 0,
      sample_message: `VPN brute force: ${groups.vpnfails?.length || 0} failed VPN logins from ${entry.structured_data?.srcip || entry.source_ip}`,
    }),
  },

];

// ── Cooldown tracker to prevent duplicate alerts ──────────────
// Map<ruleId_groupKey, lastFiredTimestamp>
const cooldowns = new Map();
const COOLDOWN_MS = 30 * 60 * 1000; // 30 minutes between same-rule same-group alerts

// ── Main evaluation function ─────────────────────────────────
async function evaluateCorrelation(entry, pool) {
  const now = Date.now();

  for (const rule of CORRELATION_RULES) {
    // Initialize buffer for this rule
    if (!eventBuffers.has(rule.id)) eventBuffers.set(rule.id, new Map());
    const ruleBuffer = eventBuffers.get(rule.id);

    // For each phase, check if this entry matches
    for (const phase of rule.phases) {
      if (!phase.match(entry)) continue;

      const groupKey = phase.groupBy(entry);
      if (!groupKey) continue;

      // Initialize group buffer
      if (!ruleBuffer.has(groupKey)) ruleBuffer.set(groupKey, {});
      const groupData = ruleBuffer.get(groupKey);
      if (!groupData[phase.name]) groupData[phase.name] = [];

      // Add this event
      groupData[phase.name].push({ timestamp: now, entry });

      // Purge events outside the window
      groupData[phase.name] = groupData[phase.name].filter(
        e => now - e.timestamp <= rule.windowMs
      );
    }

    // Now check if all phases are satisfied for any group key
    const ruleGroups = eventBuffers.get(rule.id);
    for (const [groupKey, groupData] of ruleGroups.entries()) {
      // Purge stale group data
      let allPhasesHaveData = true;
      const phaseCounts = {};

      for (const phase of rule.phases) {
        const events = groupData[phase.name] || [];
        // Purge old events
        const fresh = events.filter(e => now - e.timestamp <= rule.windowMs);
        groupData[phase.name] = fresh;
        phaseCounts[phase.name] = fresh;

        // Check unique key count if specified
        let countToCheck = fresh.length;
        if (phase.uniqueKey) {
          const uniqueVals = new Set(fresh.map(e => phase.uniqueKey(e.entry)).filter(Boolean));
          countToCheck = uniqueVals.size;
        }

        if (countToCheck < phase.minCount) { allPhasesHaveData = false; break; }

        // Check mustFollow constraint
        if (phase.mustFollow) {
          const precedingPhase = phaseCounts[phase.mustFollow];
          if (!precedingPhase || precedingPhase.length === 0) { allPhasesHaveData = false; break; }
          const lastPreceding = Math.max(...precedingPhase.map(e => e.timestamp));
          const hasFollowup   = fresh.some(e => e.timestamp > lastPreceding);
          if (!hasFollowup) { allPhasesHaveData = false; break; }
        }
      }

      if (!allPhasesHaveData) continue;

      // Check cooldown
      const cooldownKey = `${rule.id}__${groupKey}`;
      const lastFired   = cooldowns.get(cooldownKey) || 0;
      if (now - lastFired < COOLDOWN_MS) continue;

      // FIRE the correlation alert
      cooldowns.set(cooldownKey, now);

      // Get the most recent entry that triggered this
      const lastEntry = rule.phases
        .flatMap(p => groupData[p.name] || [])
        .sort((a, b) => b.timestamp - a.timestamp)[0]?.entry || entry;

      const alertData = rule.buildAlert(phaseCounts, lastEntry);

      try {
        // Find or create a correlation rule in alert_rules table
        let ruleRow = await pool.query(
          `SELECT id FROM alert_rules WHERE name = $1 LIMIT 1`, [rule.name]
        );

        let ruleId;
        if (ruleRow.rows.length === 0) {
          const inserted = await pool.query(`
            INSERT INTO alert_rules (name, description, is_enabled, threshold_count, threshold_window)
            VALUES ($1, $2, TRUE, $3, '10 minutes') RETURNING id
          `, [rule.name, rule.description, rule.phases[0].minCount]);
          ruleId = inserted.rows[0].id;
        } else {
          ruleId = ruleRow.rows[0].id;
        }

        // Check for existing open alert — update instead of inserting duplicate
        const existing = await pool.query(`
          SELECT id, match_count FROM alert_events
          WHERE rule_id = $1
            AND acknowledged = FALSE
            AND source_ip = $2
            AND fired_at > NOW() - INTERVAL '2 hours'
          ORDER BY fired_at DESC LIMIT 1
        `, [ruleId, alertData.source_ip]);

        if (existing.rows.length > 0) {
          await pool.query(`
            UPDATE alert_events
            SET match_count    = match_count + $1,
                sample_message = $2,
                fired_at       = NOW()
            WHERE id = $3
          `, [alertData.match_count, alertData.sample_message, existing.rows[0].id]);
          console.log(`[Correlation] Rule "${rule.name}" updated existing alert — ${alertData.sample_message}`);
        } else {
          await pool.query(`
            INSERT INTO alert_events (rule_id, source_host, source_ip, match_count, sample_message)
            VALUES ($1, $2, $3, $4, $5)
          `, [ruleId, alertData.source_host, alertData.source_ip, alertData.match_count, alertData.sample_message]);
          console.log(`[Correlation] Rule "${rule.name}" fired — ${alertData.sample_message}`);
        }

        // Clear the buffer for this group after firing to avoid re-firing immediately
        for (const phase of rule.phases) {
          if (groupData[phase.name]) groupData[phase.name] = [];
        }
      } catch (err) {
        console.error(`[Correlation] Failed to insert alert for rule ${rule.id}:`, err.message);
      }
    }
  }
}

// ── Periodic cleanup of stale buffers ────────────────────────
setInterval(() => {
  const now = Date.now();
  for (const [ruleId, ruleBuffer] of eventBuffers.entries()) {
    const rule = CORRELATION_RULES.find(r => r.id === ruleId);
    if (!rule) continue;
    for (const [groupKey, groupData] of ruleBuffer.entries()) {
      let hasData = false;
      for (const phase of rule.phases) {
        if (groupData[phase.name]) {
          groupData[phase.name] = groupData[phase.name].filter(e => now - e.timestamp <= rule.windowMs);
          if (groupData[phase.name].length > 0) hasData = true;
        }
      }
      if (!hasData) ruleBuffer.delete(groupKey);
    }
  }
}, 60000); // cleanup every minute

module.exports = { evaluateCorrelation };
