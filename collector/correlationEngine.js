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

// ── MITRE ATT&CK technique mapping per correlation rule (technique-level) ─────
// Keyed by rule.id. Operational rules (interface flap / loop / STP) are NOT
// adversary behaviour, so they map to [] (no technique). Keep in sync with the
// catalog in frontend/src/components/mitre.tsx and collector/mitreMapper.js.
const MITRE_BY_RULE = {
  BRUTE_FORCE_SUCCESS: ['T1110'],
  PORT_SCAN:           ['T1046'],
  INTERFACE_FLAPPING:  [],
  NETWORK_LOOP:        [],
  AFTER_HOURS_CONFIG:  ['T1562'],
  STP_INSTABILITY:     [],
  IPS_REPEATED_ATTACK: ['T1190'],
  VPN_BRUTE_FORCE:     ['T1110', 'T1133'],
};

// ── Correlation Rules ─────────────────────────────────────────
const CORRELATION_RULES = [

  // ── 1. Brute Force Success ──────────────────────────────────
  // 3+ failed logins from same source IP followed by a success within 10 min.
  // VENDOR-AGNOSTIC: matches the normalized contract (structured_data.subcategory)
  // OR a strong failed/success message regex for any vendor (cisco still works,
  // but vendor==='cisco' is no longer required). Both phases group by the REAL
  // attacker IP (structured_data.srcip || source_ip), not the relaying device.
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
          ['login_failed','auth_failed'].includes(e.structured_data?.subcategory) ||
          (e.message && /login failed|authentication fail|failed (?:login|logon|password|auth)/i.test(e.message))
        ),
        groupBy:   (e) => e.structured_data?.srcip || e.source_ip,
      },
      {
        name:      'success',
        minCount:  1,
        mustFollow: 'failures',
        match:     (e) => (
          e.structured_data?.subcategory === 'login_success' ||
          (e.message && /login success|authenticated successfully|accepted password/i.test(e.message))
        ),
        groupBy:   (e) => e.structured_data?.srcip || e.source_ip,
      },
    ],
    buildAlert: (groups, entry) => ({
      source_ip:      entry.structured_data?.srcip || entry.source_ip,
      source_host:    entry.source_host,
      match_count:    groups.failures?.length || 0,
      sample_message: `Brute force success: ${groups.failures?.length || 0} failures then login succeeded from ${entry.structured_data?.srcip || entry.source_ip}`,
    }),
  },

  // ── 2. Port Scan Detection ──────────────────────────────────
  // Same source IP hitting 8+ unique destinations denied within 3 min.
  // VENDOR-AGNOSTIC: no longer gated on vendor==='fortinet'. Matches any vendor
  // emitting a denied/blocked action (tolerant of vendor action spellings) with a
  // destination present. Groups by the REAL attacker IP (structured_data.srcip ||
  // source_ip). Vendors that don't emit a denied action simply won't match.
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
          /deny|drop|block|reject/i.test(e.structured_data?.action || '') &&
          (e.structured_data?.dstip || e.structured_data?.dst)
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
  // Same source IP triggering IPS 5+ times in 5 min.
  // VENDOR-AGNOSTIC: no longer gated on vendor==='fortinet' + type==='utm'.
  // Matches ONLY true IPS signal (structured_data.type === 'ips' OR subtype === 'ips'
  // — FortiOS UTM IPS logs arrive as type=utm/subtype=ips). The old
  // category==='security' fallback was removed — it fired on benign blocked
  // web/SSL traffic and mislabeled it as an IPS exploit (T1190). Groups by the
  // REAL attacker IP (structured_data.srcip || source_ip).
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
        match:    (e) => e.structured_data?.type === 'ips' || e.structured_data?.subtype === 'ips',
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
  // 5+ VPN login failures in 5 min.
  // VENDOR-AGNOSTIC: no longer gated on vendor==='fortinet'. Matches any vendor
  // whose event is a VPN auth event (top-level category === 'vpn' OR
  // structured_data.subtype === 'vpn') AND is a failed auth (normalized
  // subcategory login_failed/auth_failed OR strong failed-auth message regex).
  // Groups by the REAL attacker IP (structured_data.srcip || source_ip).
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
          (e.category === 'vpn' || e.structured_data?.subtype === 'vpn') &&
          (
            ['login_failed','auth_failed'].includes(e.structured_data?.subcategory) ||
            (e.message && /login failed|authentication fail|failed (?:login|logon|password|auth)/i.test(e.message))
          )
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

// ── Adaptive thresholds (Phase 2) — SAFE DIRECTION ONLY ───────
// A per-entity learned-volume cache, loaded from entity_baselines (written by
// the Phase 2 baselineBuilder). It is refreshed on the same TTL the rest of the
// codebase uses for cached settings (5 min), and is used ONLY to RAISE a noisy
// entity's effective minCount — never to lower it. So:
//   - When a baseline exists for an entity, the effective minCount for a group
//     becomes max(staticMinCount, ceil(learnedAvg + 3*learnedStddev)). This can
//     only make a rule HARDER to trip for a chronically-noisy entity (no new
//     false negatives beyond what the operator already tolerates as "normal").
//   - When NO baseline exists, the static threshold is used UNCHANGED. Until
//     baselines accumulate this is a complete NO-OP — zero behavior change, zero
//     regression risk. The whole feature degrades gracefully: any load error
//     leaves the cache empty, which is exactly the no-op path.
//
// Cache shape: Map<entityValue, { avg, stddev }> using the MAX learned
// (avg + 3*stddev) across all dow/hour slots for that entity, so the raised
// floor reflects the entity's busiest normal hour (conservative — least likely
// to suppress a genuine burst). Keyed by entity_value only (device host/ip or
// user) so it matches correlation group keys, which are srcip/source_ip/host.
let baselineCache = new Map();
let baselineCacheLoadedAt = 0;
const BASELINE_CACHE_TTL = 5 * 60 * 1000; // 5 minutes (matches settings cache)

async function refreshBaselineCache(pool) {
  const now = Date.now();
  if (now - baselineCacheLoadedAt < BASELINE_CACHE_TTL) return;
  // Mark attempted up-front so a failing/empty DB doesn't hammer every event.
  baselineCacheLoadedAt = now;
  try {
    // Pull the per-entity worst-case learned ceiling. We key on entity_value
    // only (collapsing device+user) because correlation group keys are plain
    // ip/host/user strings; collisions only ever RAISE the floor, still safe.
    const { rows } = await pool.query(`
      SELECT entity_value,
             MAX(avg_count + 3 * COALESCE(stddev_count, 0)) AS learned_ceiling
      FROM entity_baselines
      WHERE avg_count IS NOT NULL
      GROUP BY entity_value
    `);
    const next = new Map();
    for (const r of rows) {
      const ceiling = Number(r.learned_ceiling);
      if (Number.isFinite(ceiling) && ceiling > 0) {
        next.set(String(r.entity_value), Math.ceil(ceiling));
      }
    }
    baselineCache = next;
  } catch (_) {
    // entity_baselines may not exist yet (pre-deploy) or DB blip — leave the
    // cache as-is (empty = no-op). Never throw on the correlation hot path.
  }
}

// Effective minCount for a phase given a group key. Returns the static minCount
// unchanged unless a learned ceiling exists for this entity, in which case it
// can only be RAISED (never lowered). Pure + synchronous (reads the cache only).
function effectiveMinCount(staticMinCount, groupKey) {
  if (groupKey == null) return staticMinCount;
  const learnedCeiling = baselineCache.get(String(groupKey));
  if (!learnedCeiling) return staticMinCount; // no baseline → unchanged (no-op)
  return Math.max(staticMinCount, learnedCeiling);
}

// ── Main evaluation function ─────────────────────────────────
async function evaluateCorrelation(entry, pool) {
  const now = Date.now();

  // Best-effort, non-blocking refresh of the adaptive-threshold cache (5-min
  // TTL). Fire-and-forget so it never adds latency to the ingest hot path; the
  // CURRENT event still evaluates against whatever the cache already holds
  // (empty = static thresholds, the safe no-op default).
  refreshBaselineCache(pool).catch(() => {});

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

        // Adaptive threshold (SAFE direction only): for a chronically-noisy
        // entity with a learned baseline, RAISE the required count to
        // max(static, ceil(avg + 3*stddev)). With no baseline this returns the
        // static minCount unchanged — a complete no-op (no regression risk).
        const requiredCount = effectiveMinCount(phase.minCount, groupKey);

        if (countToCheck < requiredCount) { allPhasesHaveData = false; break; }

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

        const mitre = MITRE_BY_RULE[rule.id] || [];

        let ruleId;
        if (ruleRow.rows.length === 0) {
          const inserted = await pool.query(`
            INSERT INTO alert_rules (name, description, is_enabled, threshold_count, threshold_window, mitre_techniques)
            VALUES ($1, $2, TRUE, $3, '10 minutes', $4) RETURNING id
          `, [rule.name, rule.description, rule.phases[0].minCount, mitre]);
          ruleId = inserted.rows[0].id;
        } else {
          ruleId = ruleRow.rows[0].id;
          // Keep the technique mapping fresh on already-seeded rule rows (idempotent;
          // backfills rows created before this feature shipped).
          await pool.query(
            `UPDATE alert_rules SET mitre_techniques = $1
             WHERE id = $2 AND mitre_techniques IS DISTINCT FROM $1`,
            [mitre, ruleId]
          );
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
