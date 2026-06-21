'use strict';

/**
 * LogVault Email Alerting
 * Sends alert emails via SMTP using nodemailer.
 * SMTP config is read from the app_settings table and reloaded
 * every 5 minutes — no collector restart needed.
 *
 * Silently does nothing when SMTP is not configured or disabled.
 * The SMTP password is never logged or included in error messages.
 */

const nodemailer = require('nodemailer');

// SMTP settings cache — reloaded every 5 minutes
let smtpSettings      = null;
let smtpSettingsAt    = 0;
const SMTP_SETTINGS_TTL = 5 * 60 * 1000; // 5 minutes

// Load SMTP settings from app_settings, cached for 5 minutes.
async function getSmtpSettings(pool) {
  const now = Date.now();
  if (smtpSettings && now - smtpSettingsAt < SMTP_SETTINGS_TTL) return smtpSettings;
  try {
    const { rows } = await pool.query(
      `SELECT key, value FROM app_settings
       WHERE key IN ('smtp_host','smtp_port','smtp_user','smtp_pass','smtp_from','smtp_enabled')`
    );
    const s = Object.fromEntries(rows.map(r => [r.key, r.value]));
    smtpSettings = {
      host:    s.smtp_host || '',
      port:    parseInt(s.smtp_port || '587') || 587,
      user:    s.smtp_user || '',
      pass:    s.smtp_pass || '',
      from:    s.smtp_from || '',
      enabled: s.smtp_enabled === 'true',
    };
    smtpSettingsAt = now;
  } catch (err) {
    console.error('[Email] Failed to load SMTP settings:', err.message);
  }
  return smtpSettings;
}

// Notification-preference settings cache — reloaded every 5 minutes.
// Separate from the SMTP cache above.
let notifySettings    = null;
let notifySettingsAt   = 0;
const NOTIFY_SETTINGS_TTL = 5 * 60 * 1000; // 5 minutes

// Per-rule in-memory cooldown: rule.id -> last send timestamp (ms).
// Intentionally NOT persisted to the DB — resets on collector restart.
const lastEmailAt = new Map();

// Parse a JSON-array string from app_settings, defaulting to [] on any error.
function parseJsonArray(raw) {
  try {
    const v = JSON.parse(raw);
    return Array.isArray(v) ? v : [];
  } catch (_e) {
    return [];
  }
}

// Load notification-preference settings from app_settings, cached 5 minutes.
// app_settings values are always strings.
async function getNotifySettings(pool) {
  const now = Date.now();
  if (notifySettings && now - notifySettingsAt < NOTIFY_SETTINGS_TTL) return notifySettings;
  try {
    const { rows } = await pool.query(
      `SELECT key, value FROM app_settings
       WHERE key IN ('email_notify_enabled','email_notify_severities','email_notify_categories',
                     'email_notify_vendors','email_notify_min_risk','email_notify_digest_mode',
                     'email_notify_digest_hour','email_notify_recipients','email_notify_cooldown_mins')`
    );
    const s = Object.fromEntries(rows.map(r => [r.key, r.value]));
    notifySettings = {
      enabled:      s.email_notify_enabled === 'true',
      severities:   parseJsonArray(s.email_notify_severities),
      categories:   parseJsonArray(s.email_notify_categories),
      vendors:      parseJsonArray(s.email_notify_vendors),
      minRisk:      parseInt(s.email_notify_min_risk || '0', 10) || 0,
      digestMode:   s.email_notify_digest_mode || 'instant',
      digestHour:   parseInt(s.email_notify_digest_hour || '8', 10) || 8,
      recipients:   s.email_notify_recipients || '',
      cooldownMins: parseInt(s.email_notify_cooldown_mins || '30', 10) || 30,
    };
    notifySettingsAt = now;
  } catch (err) {
    console.error('[Email] Failed to load notification settings:', err.message);
    // Fail open — if we have never loaded prefs, default to enabled/no-filters.
    if (!notifySettings) {
      notifySettings = {
        enabled: true, severities: [], categories: [], vendors: [],
        minRisk: 0, digestMode: 'instant', digestHour: 8,
        recipients: '', cooldownMins: 30,
      };
    }
  }
  return notifySettings;
}

// Build a nodemailer transport from a config object.
// Returns null if host is missing.
function buildTransport(cfg) {
  if (!cfg || !cfg.host) return null;
  const options = {
    host:   cfg.host,
    port:   cfg.port,
    secure: cfg.port === 465, // implicit TLS on 465, STARTTLS otherwise
  };
  // Only attach auth when a username is configured
  if (cfg.user) {
    options.auth = { user: cfg.user, pass: cfg.pass };
  }
  return nodemailer.createTransport(options);
}

function appUrl() {
  return process.env.NEXTAUTH_URL || 'http://localhost:3004';
}

function escapeHtml(str) {
  return String(str == null ? '' : str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Decide whether an email should be sent for this rule/entry, applying the
 * global notification filters and the per-rule cooldown.
 * MUST NEVER THROW — fails open (returns true) on any error.
 */
async function shouldSendEmail(rule, entry, pool) {
  try {
    // 1. Master notify toggle
    const prefs = await getNotifySettings(pool);
    if (!prefs.enabled) return false;

    // 2. SMTP must be configured + enabled
    const cfg = await getSmtpSettings(pool);
    if (!cfg || !cfg.host || cfg.enabled !== true) return false;

    // 3. Severity filter (empty = allow all)
    if (prefs.severities.length > 0) {
      if (!prefs.severities.includes(String(entry.severity))) return false;
    }

    // 4. Category filter (empty = allow all)
    const category = entry.category || (entry.structured_data && entry.structured_data.category);
    if (prefs.categories.length > 0) {
      if (!prefs.categories.includes(category)) return false;
    }

    // 5. Vendor filter (empty = allow all)
    if (prefs.vendors.length > 0) {
      if (!prefs.vendors.includes(entry.vendor)) return false;
    }

    // 6. Minimum risk score (0 = no minimum)
    if (prefs.minRisk > 0) {
      if (Number(entry.risk_score || 0) < prefs.minRisk) return false;
    }

    // 7. Per-rule cooldown (read only — timestamp is set on successful send)
    const cooldownMs = prefs.cooldownMins * 60000;
    const last = lastEmailAt.get(rule.id);
    if (last && Date.now() - last < cooldownMs) return false;

    return true;
  } catch (err) {
    console.error('[Email] shouldSendEmail error (failing open):', err.message);
    return true;
  }
}

// Color for the risk-score badge based on the 0-100 score.
function riskColor(score) {
  if (score <= 30) return '#16a34a'; // green
  if (score <= 60) return '#d97706'; // amber
  if (score <= 80) return '#ea580c'; // orange
  return '#dc2626';                  // red
}

// Build the HTML body for an alert email.
function buildAlertHtml(rule, entry, matchCount) {
  const url        = appUrl();
  const ruleName   = escapeHtml(rule.name);
  const severity   = escapeHtml(entry.severity_label || String(entry.severity));
  // The real actor (attacker) is structured_data.srcip; source_ip is the syslog
  // sender (the relay/firewall). Show + link the actor, with the sender as fallback.
  const actorIp    = (entry.structured_data && entry.structured_data.srcip) || entry.source_ip;
  const sourceIp   = escapeHtml(actorIp || 'unknown');
  const hostname   = escapeHtml(entry.source_host || actorIp || 'unknown');
  const sampleMsg  = escapeHtml((entry.message || '').substring(0, 500));
  const timestamp  = escapeHtml((entry.received_at instanceof Date ? entry.received_at : new Date()).toISOString());
  const count      = escapeHtml(String(matchCount != null ? matchCount : ''));

  const riskScore  = Number(entry.risk_score || 0);
  const category   = entry.category || (entry.structured_data && entry.structured_data.category);
  const vendor     = entry.vendor;

  const explorerUrl = `${url}/?host=${encodeURIComponent(actorIp || '')}#logs`;

  const pill = (text, bg, color) =>
    `<span style="display:inline-block;background:${bg};color:${color};font-size:11px;font-weight:600;padding:3px 10px;border-radius:999px;margin:0 6px 6px 0;">${text}</span>`;

  const badges = [
    pill(`Risk ${escapeHtml(String(riskScore))}`, riskColor(riskScore), '#ffffff'),
    category ? pill(escapeHtml(category), '#e2e8f0', '#334155') : '',
    vendor ? pill(escapeHtml(vendor), '#dbeafe', '#1e3a8a') : '',
  ].join('');

  const matchLine = (typeof matchCount === 'number' && matchCount > 0)
    ? `<div style="font-size:12px;color:#64748b;margin-bottom:14px;">This alert fired ${escapeHtml(String(matchCount))} times in the threshold window</div>`
    : '';

  const row = (label, value) => `
        <tr>
          <td style="padding:8px 14px;font-size:12px;color:#64748b;font-weight:600;white-space:nowrap;vertical-align:top;">${label}</td>
          <td style="padding:8px 14px;font-size:13px;color:#0f172a;">${value}</td>
        </tr>`;

  return `
<div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#f1f5f9;padding:24px;">
  <div style="max-width:560px;margin:0 auto;background:#ffffff;border:1px solid #e2e8f0;border-radius:10px;overflow:hidden;">
    <div style="background:#1a2744;padding:16px 22px;">
      <div style="font-size:16px;font-weight:700;color:#ffffff;">LogVault Alert</div>
      <div style="font-size:11px;color:#94a3b8;margin-top:2px;">NocVault Network Intelligence Suite</div>
    </div>
    <div style="padding:20px 22px;">
      <div style="font-size:15px;font-weight:700;color:#0f172a;margin-bottom:12px;">${ruleName}</div>
      <div style="margin-bottom:10px;">${badges}</div>
      ${matchLine}
      <table style="width:100%;border-collapse:collapse;border:1px solid #e2e8f0;border-radius:8px;">
${row('Severity', severity)}
${row('Source IP', sourceIp)}
${row('Hostname', hostname)}
${count ? row('Match Count', count) : ''}
${row('Timestamp', timestamp)}
${row('Sample Message', `<span style="font-family:JetBrains Mono,Consolas,monospace;word-break:break-word;">${sampleMsg}</span>`)}
      </table>
      <div style="margin-top:20px;">
        <a href="${url}" style="display:inline-block;background:#C8102E;color:#ffffff;text-decoration:none;font-size:13px;font-weight:600;padding:10px 20px;border-radius:7px;margin:0 8px 8px 0;">Open LogVault</a>
        <a href="${explorerUrl}" style="display:inline-block;background:#1a2744;color:#ffffff;text-decoration:none;font-size:13px;font-weight:600;padding:10px 20px;border-radius:7px;">View in Log Explorer</a>
      </div>
    </div>
    <div style="padding:12px 22px;border-top:1px solid #e2e8f0;font-size:11px;color:#94a3b8;">
      This is an automated alert from LogVault. <a href="${url}" style="color:#64748b;">${escapeHtml(url)}</a>
    </div>
  </div>
</div>`;
}

/**
 * Send an alert email for a fired rule.
 * Silently returns if SMTP is not configured/enabled — never throws.
 */
async function sendAlertEmail(rule, entry, matchCount, pool) {
  try {
    // Apply global filters + cooldown — emailer decides whether to send.
    if (!(await shouldSendEmail(rule, entry, pool))) return;

    const cfg = await getSmtpSettings(pool);

    // Resolve recipients: per-rule notify_email + global recipients, both
    // comma-separated. Trim, drop empties, deduplicate (case-insensitive).
    const prefs = await getNotifySettings(pool);
    const rawRecipients = []
      .concat(String(rule.notify_email || '').split(','))
      .concat(String(prefs.recipients || '').split(','));

    const seen = new Set();
    const recipients = [];
    for (const r of rawRecipients) {
      const addr = r.trim();
      if (!addr) continue;
      const key = addr.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      recipients.push(addr);
    }
    if (recipients.length === 0) return; // nobody to notify — skip

    const transport = buildTransport(cfg);
    if (!transport) return;

    const subject = `[LogVault Alert] ${(entry.severity_label || String(entry.severity)).toUpperCase()} — ${rule.name}`;
    await transport.sendMail({
      from:    cfg.from || cfg.user,
      to:      recipients.join(', '),
      subject,
      html:    buildAlertHtml(rule, entry, matchCount),
    });
    lastEmailAt.set(rule.id, Date.now());
    console.log(`[Email] Alert sent for rule "${rule.name}" to ${recipients.length} recipient(s)`);
  } catch (err) {
    // Never throw to the caller — alerting must not break the collector
    console.error('[Email] Failed to send alert email:', err.message);
  }
}

/**
 * Send a test email using either explicit overrides or the saved settings.
 * Used by the Settings "Test Email" button.
 *
 * @param {string} toAddress  recipient
 * @param {object} pool       pg pool (used when no overrides given)
 * @param {object} [override] { host, port, user, pass, from } to test unsaved settings
 * @returns {{ok:boolean, error?:string}}
 */
async function testEmail(toAddress, pool, override) {
  if (!toAddress || typeof toAddress !== 'string') {
    return { ok: false, error: 'Recipient address required' };
  }

  let cfg;
  if (override && override.host) {
    cfg = {
      host: override.host,
      port: parseInt(override.port || '587') || 587,
      user: override.user || '',
      pass: override.pass || '',
      from: override.from || '',
    };
  } else {
    const saved = await getSmtpSettings(pool);
    if (!saved || !saved.host) return { ok: false, error: 'SMTP is not configured' };
    cfg = saved;
  }

  const transport = buildTransport(cfg);
  if (!transport) return { ok: false, error: 'SMTP host is required' };

  try {
    const url = appUrl();
    await transport.sendMail({
      from:    cfg.from || cfg.user,
      to:      toAddress,
      subject: '[LogVault Alert] Test Email',
      html: `
<div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#f1f5f9;padding:24px;">
  <div style="max-width:520px;margin:0 auto;background:#ffffff;border:1px solid #e2e8f0;border-radius:10px;overflow:hidden;">
    <div style="background:#1a2744;padding:16px 22px;">
      <div style="font-size:16px;font-weight:700;color:#ffffff;">LogVault</div>
      <div style="font-size:11px;color:#94a3b8;margin-top:2px;">NocVault Network Intelligence Suite</div>
    </div>
    <div style="padding:20px 22px;font-size:13px;color:#0f172a;line-height:1.6;">
      <p style="margin:0 0 10px;">This is a test email from LogVault.</p>
      <p style="margin:0;">If you received this, your SMTP settings are working correctly and alert emails will be delivered.</p>
      <div style="margin-top:20px;">
        <a href="${url}" style="display:inline-block;background:#C8102E;color:#ffffff;text-decoration:none;font-size:13px;font-weight:600;padding:10px 20px;border-radius:7px;">Open LogVault</a>
      </div>
    </div>
  </div>
</div>`,
    });
    return { ok: true };
  } catch (err) {
    // Surface a sanitized message — never echo the password
    return { ok: false, error: err.message };
  }
}

module.exports = { sendAlertEmail, testEmail, shouldSendEmail };
