'use client';

import { useState } from 'react';

// ── MITRE ATT&CK technique catalog (technique-level) ──────────────────────────
// Shared by the alert badges (AlertEvents.tsx), the per-event badges
// (LogDetailPanel.tsx) and the ATT&CK coverage view (SecurityAnalysis.tsx).
// Keep the ID set in sync with collector/mitreMapper.js and the MITRE_BY_RULE
// map in collector/correlationEngine.js.
//
// `description` / `whyItMatters` are short, curated plain-language fields so the
// badges teach (not just label). Both are optional on the type so any future ID
// added to the catalog still type-checks before its copy is written.

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  description?: string;
  whyItMatters?: string;
}

export const MITRE_TECHNIQUES: Record<
  string,
  { name: string; tactic: string; description?: string; whyItMatters?: string }
> = {
  T1110: {
    name: 'Brute Force', tactic: 'Credential Access',
    description: 'Attackers guess passwords by trying many combinations, often automated, until one works.',
    whyItMatters: 'A successful guess hands over a real account, giving the attacker legitimate access with no malware needed.',
  },
  T1133: {
    name: 'External Remote Services', tactic: 'Initial Access',
    description: 'Attackers log in through internet-facing remote access such as VPN, RDP or SSH.',
    whyItMatters: 'Remote services are a direct front door into the network, so any abuse here can mean a full foothold from outside.',
  },
  T1046: {
    name: 'Network Service Discovery', tactic: 'Discovery',
    description: 'Attackers scan hosts and ports to find running services and map what is reachable.',
    whyItMatters: 'Scanning is usually the prelude to an attack — it tells the adversary exactly where to strike next.',
  },
  T1595: {
    name: 'Active Scanning', tactic: 'Reconnaissance',
    description: 'Attackers actively probe your perimeter from the outside to enumerate hosts, ports and software versions.',
    whyItMatters: 'Early external probing reveals exposed, exploitable services before an attack and is an early-warning signal.',
  },
  T1190: {
    name: 'Exploit Public-Facing Application', tactic: 'Initial Access',
    description: 'Attackers abuse a vulnerability in an internet-exposed app or device to break in.',
    whyItMatters: 'A single unpatched public service can give an attacker code execution and an initial foothold.',
  },
  T1562: {
    name: 'Impair Defenses', tactic: 'Defense Evasion',
    description: 'Attackers disable or tamper with security controls such as logging, firewalls or antivirus.',
    whyItMatters: 'Blinding the defenses lets the rest of the attack proceed unseen, so this is a strong sign of a hands-on intruder.',
  },
  T1098: {
    name: 'Account Manipulation', tactic: 'Persistence',
    description: 'Attackers modify accounts — adding privileges, keys or group membership — to keep their access.',
    whyItMatters: 'Tampered accounts let an attacker stay in even after the original intrusion is cleaned up.',
  },
  T1078: {
    name: 'Valid Accounts', tactic: 'Initial Access',
    description: 'Attackers use legitimate stolen or default credentials to log in as a real user.',
    whyItMatters: 'Activity looks normal and authorized, making this one of the hardest intrusions to spot.',
  },
  T1068: {
    name: 'Exploitation for Privilege Escalation', tactic: 'Privilege Escalation',
    description: 'Attackers exploit a software or system flaw to gain higher-level (e.g. admin/root) permissions.',
    whyItMatters: 'Elevated privileges let an attacker control the host and reach data and systems they should not.',
  },
  T1567: {
    name: 'Exfiltration Over Web Service', tactic: 'Exfiltration',
    description: 'Attackers steal data by sending it out through trusted web services like cloud storage or paste sites.',
    whyItMatters: 'Riding legitimate web traffic helps stolen data slip past filters, so this can mean an active breach.',
  },
  T1041: {
    name: 'Exfiltration Over C2 Channel', tactic: 'Exfiltration',
    description: 'Attackers send stolen data back out over the same channel their malware uses for command-and-control.',
    whyItMatters: 'Data leaving over an existing C2 link confirms both a live compromise and active theft.',
  },
  T1486: {
    name: 'Data Encrypted for Impact', tactic: 'Impact',
    description: 'Attackers encrypt files or systems to make them unusable — the core action of ransomware.',
    whyItMatters: 'This is the damaging payoff stage; it causes outages, data loss and extortion demands.',
  },
  T1498: {
    name: 'Network Denial of Service', tactic: 'Impact',
    description: 'Attackers flood the network or a service with traffic to exhaust it and make it unavailable.',
    whyItMatters: 'Outages disrupt the business directly and can also be a smokescreen for other malicious activity.',
  },
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
  return {
    id,
    name: m?.name || id,
    tactic: m?.tactic || 'Other',
    description: m?.description,
    whyItMatters: m?.whyItMatters,
  };
}

// Deep-link to the technique page on attack.mitre.org (sub-techniques use /Txxxx/yyy/).
export function mitreUrl(id: string): string {
  return `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`;
}

// Plain-text summary (used for the native `title` fallback so the curated copy is
// still available without JS / on touch / for assistive tech).
export function mitreTitle(id: string): string {
  const info = mitreInfo(id);
  let t = `${info.id} · ${info.name} (${info.tactic})`;
  if (info.description) t += `\n\n${info.description}`;
  if (info.whyItMatters) t += `\nWhy it matters: ${info.whyItMatters}`;
  return t;
}

// Rich hover/focus popover content for a single technique. Inline-styled, no deps,
// matches the suite purple tints. Shown on hover or keyboard focus; a native
// `title` fallback on the anchor keeps the info available without JS.
export function MitrePopover({ id }: { id: string }) {
  const info = mitreInfo(id);
  return (
    <span role="tooltip"
      style={{
        position: 'absolute', zIndex: 1000, top: 'calc(100% + 6px)', left: 0,
        width: 'max-content', maxWidth: 280, textAlign: 'left',
        background: 'var(--bg-card)', color: 'var(--text-primary)',
        border: '1px solid var(--border)', borderRadius: 8,
        boxShadow: 'var(--shadow-sm)', padding: '10px 12px',
        fontFamily: 'system-ui, -apple-system, sans-serif', whiteSpace: 'normal',
        cursor: 'default',
      }}
      onClick={(e) => e.stopPropagation()}>
      <span style={{ display: 'block', fontWeight: 700, fontSize: 'var(--text-base)' }}>
        <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--tint-purple-fg)' }}>{info.id}</span>
        {' '}— {info.name}
      </span>
      <span style={{ display: 'block', marginTop: 2, fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
        {info.tactic}
      </span>
      {info.description && (
        <span style={{ display: 'block', marginTop: 8, fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
          {info.description}
        </span>
      )}
      {info.whyItMatters && (
        <span style={{ display: 'block', marginTop: 6, fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
          <span style={{ fontWeight: 700, color: 'var(--tint-purple-fg)' }}>Why it matters: </span>
          {info.whyItMatters}
        </span>
      )}
      <a href={mitreUrl(id)} target="_blank" rel="noreferrer"
        onClick={(e) => e.stopPropagation()}
        style={{ display: 'inline-block', marginTop: 8, fontSize: 'var(--text-xs)', fontWeight: 700,
          color: 'var(--tint-purple-fg)', textDecoration: 'none' }}>
        View on attack.mitre.org →
      </a>
    </span>
  );
}

// A single ATT&CK technique pill with a rich hover/focus popover. Lives at module
// level (never nested in a component). Keeps the native `title` fallback and stops
// click propagation so it is safe inside clickable rows.
function MitrePill({ id, compact }: { id: string; compact?: boolean }) {
  const [open, setOpen] = useState(false);
  const info = mitreInfo(id);
  const hasDetail = !!(info.description || info.whyItMatters);
  return (
    <span style={{ position: 'relative', display: 'inline-flex', flexShrink: 0 }}
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}>
      <a href={mitreUrl(id)} target="_blank" rel="noreferrer"
        title={mitreTitle(id)}
        onFocus={() => setOpen(true)}
        onBlur={() => setOpen(false)}
        onClick={(e) => e.stopPropagation()}
        style={{ display: 'inline-flex', alignItems: 'center', textDecoration: 'none',
          background: 'var(--tint-purple)', color: 'var(--tint-purple-fg)',
          border: '1px solid var(--tint-purple)', borderRadius: 4,
          padding: compact ? '0 5px' : '1px 6px', fontSize: 'var(--text-xs)', fontWeight: 700,
          fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap' }}>
        {info.id}
      </a>
      {open && hasDetail && <MitrePopover id={id} />}
    </span>
  );
}

// Reusable purple ATT&CK technique pills. Returns null when there is nothing to
// show, so callers can drop it inline without a guard. Each pill links out to
// the technique definition and stops click propagation (safe inside clickable rows).
export function MitreBadges({ ids, compact }: { ids?: string[] | null; compact?: boolean }) {
  if (!Array.isArray(ids) || ids.length === 0) return null;
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, flexWrap: 'wrap', minWidth: 0 }}>
      {ids.map(id => <MitrePill key={id} id={id} compact={compact} />)}
    </span>
  );
}
