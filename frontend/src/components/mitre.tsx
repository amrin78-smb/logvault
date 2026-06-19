'use client';

// ── MITRE ATT&CK technique catalog (technique-level) ──────────────────────────
// Shared by the alert badges (AlertEvents.tsx), the per-event badges
// (LogDetailPanel.tsx) and the ATT&CK coverage view (SecurityAnalysis.tsx).
// Keep the ID set in sync with collector/mitreMapper.js and the MITRE_BY_RULE
// map in collector/correlationEngine.js.

export interface MitreTechnique { id: string; name: string; tactic: string; }

export const MITRE_TECHNIQUES: Record<string, { name: string; tactic: string }> = {
  T1110: { name: 'Brute Force',                           tactic: 'Credential Access' },
  T1133: { name: 'External Remote Services',              tactic: 'Initial Access' },
  T1046: { name: 'Network Service Discovery',             tactic: 'Discovery' },
  T1595: { name: 'Active Scanning',                       tactic: 'Reconnaissance' },
  T1190: { name: 'Exploit Public-Facing Application',     tactic: 'Initial Access' },
  T1562: { name: 'Impair Defenses',                       tactic: 'Defense Evasion' },
  T1098: { name: 'Account Manipulation',                  tactic: 'Persistence' },
  T1078: { name: 'Valid Accounts',                        tactic: 'Initial Access' },
  T1068: { name: 'Exploitation for Privilege Escalation', tactic: 'Privilege Escalation' },
  T1567: { name: 'Exfiltration Over Web Service',         tactic: 'Exfiltration' },
  T1041: { name: 'Exfiltration Over C2 Channel',          tactic: 'Exfiltration' },
  T1486: { name: 'Data Encrypted for Impact',             tactic: 'Impact' },
  T1498: { name: 'Network Denial of Service',             tactic: 'Impact' },
};

// ATT&CK kill-chain tactic order for laying out the coverage matrix.
export const MITRE_TACTIC_ORDER: string[] = [
  'Reconnaissance', 'Initial Access', 'Execution', 'Persistence',
  'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
  'Exfiltration', 'Impact',
];

export function mitreInfo(id: string): MitreTechnique {
  const m = MITRE_TECHNIQUES[id];
  return { id, name: m?.name || id, tactic: m?.tactic || 'Other' };
}

// Deep-link to the technique page on attack.mitre.org (sub-techniques use /Txxxx/yyy/).
export function mitreUrl(id: string): string {
  return `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`;
}

// Reusable purple ATT&CK technique pills. Returns null when there is nothing to
// show, so callers can drop it inline without a guard. Each pill links out to
// the technique definition and stops click propagation (safe inside clickable rows).
export function MitreBadges({ ids, compact }: { ids?: string[] | null; compact?: boolean }) {
  if (!Array.isArray(ids) || ids.length === 0) return null;
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, flexWrap: 'wrap', minWidth: 0 }}>
      {ids.map(id => {
        const info = mitreInfo(id);
        return (
          <a key={id} href={mitreUrl(id)} target="_blank" rel="noreferrer"
            title={`${info.id} · ${info.name} (${info.tactic})`}
            onClick={(e) => e.stopPropagation()}
            style={{ display: 'inline-flex', alignItems: 'center', textDecoration: 'none',
              background: 'var(--tint-purple)', color: 'var(--tint-purple-fg)',
              border: '1px solid var(--tint-purple)', borderRadius: 4,
              padding: compact ? '0 5px' : '1px 6px', fontSize: 'var(--text-xs)', fontWeight: 700,
              fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap', flexShrink: 0 }}>
            {info.id}
          </a>
        );
      })}
    </span>
  );
}
