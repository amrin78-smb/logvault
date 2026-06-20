'use strict';

/**
 * Forcepoint Parser for LogVault
 * Covers: Web Security, NGFW, Email Security, DLP
 * Log format: CEF (Common Event Format) — ArcSight standard
 *
 * CEF format:
 * CEF:0|Forcepoint|Security|version|signatureId|name|severity|extensions
 *
 * Sample logs:
 * Web Security:
 *   CEF:0|Forcepoint|Security|8.5|block|Transaction Blocked|7|act=blocked app=https dst=185.220.101.1 dhost=malware.example.com src=10.1.1.5 suser=john.doe request=https://malware.example.com/payload.exe reason=Malware
 *
 * NGFW:
 *   CEF:0|Forcepoint|NGFW|6.8|100001|Traffic Denied|5|act=Deny src=10.1.1.5 dst=8.8.8.8 dpt=53 proto=UDP app=DNS
 *
 * Email Security:
 *   CEF:0|Forcepoint|Email Security|8.5|Policy|Policy Violation|6|act=quarantine suser=user@domain.com duser=recipient@domain.com msg=Sensitive Data Detected
 *
 * DLP:
 *   CEF:0|Forcepoint|DLP|8.9|Incident|DLP Incident|8|act=block suser=john.doe fileType=docx reason=PII Detected cs1Label=Policy cs1=PII-Policy
 */

// Validate an IPv4 address (4 octets, 0-255). Returns the IP or null.
function validIp(ip) {
  if (!ip || typeof ip !== 'string') return null;
  const m = ip.trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  for (let i = 1; i <= 4; i++) { if (parseInt(m[i], 10) > 255) return null; }
  return ip.trim();
}

// Detect login/auth events and their result from signature/name/act text.
// Returns 'login_failed', 'login_success', or null (non-auth).
function authSubcategory(signatureId, name, act) {
  const t = `${signatureId || ''} ${name || ''} ${act || ''}`.toLowerCase();
  if (!/auth|login|logon|logoff|logout|sign.?in|credential|password|account/.test(t)) return null;
  if (/fail|failed|denied|deny|reject|invalid|incorrect|wrong|bad|lockout|locked|unauthor/.test(t)) return 'login_failed';
  if (/success|succeed|succeeded|granted|accept|established|logged in|logon success/.test(t)) return 'login_success';
  return null;
}

// CEF severity 0-10 → syslog severity
function cefSeverityToSyslog(cefSev) {
  const n = parseInt(cefSev) || 5;
  if (n >= 9) return { severity: 2, label: 'critical' };
  if (n >= 7) return { severity: 3, label: 'error' };
  if (n >= 5) return { severity: 4, label: 'warning' };
  if (n >= 3) return { severity: 5, label: 'notice' };
  return { severity: 6, label: 'info' };
}

// Parse CEF extension key=value pairs
// Handles: key=value key2=value with spaces key3=value\=escaped
function parseCEFExtension(ext) {
  if (!ext) return {};
  const result = {};
  // Match key=value pairs — value ends at next key= or end of string
  const regex = /(\w+)=((?:[^=\\]|\\.)*)(?=\s+\w+=|$)/g;
  let match;
  while ((match = regex.exec(ext)) !== null) {
    result[match[1]] = match[2].trim().replace(/\\=/g, '=').replace(/\\n/g, '\n');
  }
  return result;
}

// Map CEF action to normalized action
function normalizeAction(act) {
  if (!act) return null;
  const lower = act.toLowerCase();
  if (['block', 'blocked', 'deny', 'denied', 'drop'].includes(lower)) return 'blocked';
  if (['allow', 'allowed', 'permit', 'permitted', 'pass'].includes(lower)) return 'allowed';
  if (['quarantine', 'quarantined'].includes(lower)) return 'quarantine';
  if (['alert', 'alertonly'].includes(lower)) return 'alert';
  if (['encrypt', 'encrypted'].includes(lower)) return 'encrypt';
  return act.toLowerCase();
}

// Determine event category from CEF product and fields
function getCategory(product, signatureId, fields) {
  const prod = (product || '').toLowerCase();
  const sig  = (signatureId || '').toLowerCase();
  const act  = (fields.act || '').toLowerCase();

  if (prod.includes('email')) return 'email';
  if (prod.includes('dlp'))   return 'dlp';
  if (prod.includes('ngfw') || prod.includes('firewall')) {
    if (act.includes('deny') || act.includes('drop') || act.includes('block')) return 'firewall';
    return 'network';
  }
  if (prod.includes('web') || prod.includes('proxy')) {
    if (fields.request || fields.dhost) return 'web';
    return 'proxy';
  }
  if (fields.suser && fields.duser) return 'email';
  if (fields.request) return 'web';
  return 'security';
}

// Build human-readable summary
function buildSummary(product, name, fields, action) {
  const user    = fields.suser || fields.loginID || null;
  const src     = fields.src   || null;
  const dst     = fields.dst   || fields.dhost || null;
  const url     = fields.request || null;
  const reason  = fields.reason || fields.cs1 || null;
  const policy  = fields.cs1Label === 'Policy' ? fields.cs1 : null;

  let parts = [];

  if (product) parts.push(`[${product}]`);
  parts.push(name || 'Event');
  if (action)  parts.push(`— ${action}`);
  if (user)    parts.push(`| User: ${user}`);
  if (src)     parts.push(`| Src: ${src}`);
  if (dst && dst !== src) parts.push(`→ ${dst}`);
  if (url)     parts.push(`| URL: ${url.substring(0, 80)}`);
  if (reason)  parts.push(`| Reason: ${reason}`);
  if (policy)  parts.push(`| Policy: ${policy}`);

  return parts.join(' ');
}

function parseForcepoint(raw, sourceIP) {
  if (!raw) return null;

  // Detect CEF format — must start with CEF:
  const cefMatch = raw.match(/CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)/s);

  // Also handle key-value format (Splunk/syslog style)
  // vendor=Forcepoint product=Security action=block user=john ...
  const isKV = !cefMatch && /vendor=Forcepoint/i.test(raw);

  if (!cefMatch && !isKV) return null;

  let structured = {};
  let severity, severityLabel, program, message;

  if (cefMatch) {
    // CEF format
    const [, , vendor, product, version, signatureId, name, cefSeverity, extension] = cefMatch;

    const sev    = cefSeverityToSyslog(cefSeverity);
    severity      = sev.severity;
    severityLabel = sev.label;
    program       = `Forcepoint/${product}`;

    const fields = parseCEFExtension(extension);
    const action = normalizeAction(fields.act);
    let category = getCategory(product, signatureId, fields);

    // Auth events: classify subcategory + force category 'authentication'.
    const subcategory = authSubcategory(signatureId, name, fields.act);
    if (subcategory) category = 'authentication';

    structured = {
      // CEF header fields
      cef_version:   '0',
      vendor:        vendor || 'Forcepoint',
      product:       product,
      version:       version,
      signature_id:  signatureId,
      name:          name,
      cef_severity:  cefSeverity,

      // Normalized fields
      action,
      category,
      subcategory:   subcategory || null,

      // Network fields
      // srcip = REAL client/source IP only — never the syslog sender (avoids
      // the sender-as-attacker conflation that src_ip's sourceIP fallback has).
      srcip:         validIp(fields.src),
      dstip:         validIp(fields.dst),
      src_ip:        fields.src    || sourceIP || null,
      dst_ip:        fields.dst    || null,
      dst_host:      fields.dhost  || null,
      dst_port:      fields.dpt    ? parseInt(fields.dpt) : null,
      src_port:      fields.spt    ? parseInt(fields.spt) : null,
      protocol:      fields.proto  || fields.app || null,

      // User fields
      user:          fields.suser  || fields.loginID || null,
      dst_user:      fields.duser  || null,

      // Web fields
      url:           fields.request || null,
      method:        fields.requestMethod || null,
      user_agent:    fields.requestClientApplication || null,
      content_type:  fields.cs3Label === 'ContentType' ? fields.cs3 : null,

      // Traffic fields
      bytes_in:      fields.in  ? parseInt(fields.in)  : null,
      bytes_out:     fields.out ? parseInt(fields.out) : null,

      // Policy fields
      policy:        fields.cs1Label === 'Policy'  ? fields.cs1 : null,
      reason:        fields.reason || null,
      disposition:   fields.cn1Label === 'DispositionCode' ? fields.cn1 : null,

      // DLP fields
      file_type:     fields.fileType || null,
      dlp_incident:  category === 'dlp' ? true : null,

      // Email fields
      msg_subject:   fields.msg || null,

      // Device
      device:        fields.dvc || null,

      // Raw extension for reference
      _raw_ext: extension ? extension.substring(0, 500) : null,
    };

    // Remove null values
    Object.keys(structured).forEach(k => structured[k] === null && delete structured[k]);

    message = buildSummary(product, name, fields, action);

  } else {
    // Key-value format: vendor=Forcepoint product=Security action=block ...
    const kvRegex = /(\w+)=([^\s]+)/g;
    const fields  = {};
    let m;
    while ((m = kvRegex.exec(raw)) !== null) {
      fields[m[1]] = m[2];
    }

    const sev    = cefSeverityToSyslog(fields.severity || '5');
    severity      = sev.severity;
    severityLabel = sev.label;
    program       = `Forcepoint/${fields.product || 'Security'}`;

    const action   = normalizeAction(fields.action || fields.act);
    let category   = getCategory(fields.product || '', '', fields);

    // Auth events: classify subcategory + force category 'authentication'.
    const subcategory = authSubcategory(fields.signature || fields.signatureId, fields.name, fields.action || fields.act);
    if (subcategory) category = 'authentication';

    structured = {
      vendor:    'Forcepoint',
      product:   fields.product || null,
      action,
      category,
      subcategory: subcategory || null,
      // srcip = REAL client/source IP only — never the syslog sender.
      srcip:     validIp(fields.src || fields.source),
      dstip:     validIp(fields.dst || fields.destination),
      src_ip:    fields.src || fields.source || sourceIP || null,
      dst_ip:    fields.dst || fields.destination || null,
      user:      fields.user || fields.suser || null,
      reason:    fields.reason || null,
      policy:    fields.policy || null,
      url:       fields.url || null,
    };

    Object.keys(structured).forEach(k => structured[k] === null && delete structured[k]);

    const parts = ['Forcepoint'];
    if (fields.product) parts.push(fields.product);
    if (action)         parts.push(`| ${action}`);
    if (fields.user)    parts.push(`| User: ${fields.user}`);
    if (fields.reason)  parts.push(`| ${fields.reason}`);
    message = parts.join(' ');
  }

  return {
    vendor:         'forcepoint',
    program,
    severity,
    severity_label: severityLabel,
    message,
    structured_data: structured,
    is_parsed:      true,
    parser_version: 'forcepoint-v1.0',
  };
}

// Detection function — called by collector to check if this parser applies
function detectForcepoint(raw) {
  if (!raw) return false;
  // CEF format from Forcepoint
  if (/CEF:\d+\|Forcepoint\|/i.test(raw)) return true;
  // Key-value format
  if (/vendor=Forcepoint/i.test(raw)) return true;
  // Websense (legacy Forcepoint brand)
  if (/CEF:\d+\|Websense\|/i.test(raw)) return true;
  return false;
}

module.exports = { parseForcepoint, detectForcepoint };
