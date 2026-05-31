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

// Build the HTML body for an alert email.
function buildAlertHtml(rule, entry, matchCount) {
  const url        = appUrl();
  const ruleName   = escapeHtml(rule.name);
  const severity   = escapeHtml(entry.severity_label || String(entry.severity));
  const sourceIp   = escapeHtml(entry.source_ip || 'unknown');
  const hostname   = escapeHtml(entry.source_host || entry.source_ip || 'unknown');
  const sampleMsg  = escapeHtml((entry.message || '').substring(0, 500));
  const timestamp  = escapeHtml((entry.received_at instanceof Date ? entry.received_at : new Date()).toISOString());
  const count      = escapeHtml(String(matchCount != null ? matchCount : ''));

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
      <div style="font-size:15px;font-weight:700;color:#0f172a;margin-bottom:14px;">${ruleName}</div>
      <table style="width:100%;border-collapse:collapse;border:1px solid #e2e8f0;border-radius:8px;">
${row('Severity', severity)}
${row('Source IP', sourceIp)}
${row('Hostname', hostname)}
${count ? row('Match Count', count) : ''}
${row('Timestamp', timestamp)}
${row('Sample Message', `<span style="font-family:JetBrains Mono,Consolas,monospace;word-break:break-word;">${sampleMsg}</span>`)}
      </table>
      <div style="margin-top:20px;">
        <a href="${url}" style="display:inline-block;background:#C8102E;color:#ffffff;text-decoration:none;font-size:13px;font-weight:600;padding:10px 20px;border-radius:7px;">Open LogVault</a>
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
    const cfg = await getSmtpSettings(pool);
    if (!cfg || !cfg.enabled || !cfg.host) return; // not configured/disabled — skip silently

    const to = rule.notify_email;
    if (!to) return;

    const transport = buildTransport(cfg);
    if (!transport) return;

    const subject = `[LogVault Alert] ${rule.name} - ${entry.severity_label || entry.severity}`;
    await transport.sendMail({
      from:    cfg.from || cfg.user,
      to,
      subject,
      html:    buildAlertHtml(rule, entry, matchCount),
    });
    console.log(`[Email] Alert sent for rule "${rule.name}" to ${to}`);
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

module.exports = { sendAlertEmail, testEmail };
