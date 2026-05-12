/**
 * Aruba / HP ProCurve Syslog Parser
 *
 * Aruba APs and controllers send RFC 3164 with Aruba-specific program tags.
 * Controller example: <30>May 12 10:23:01 aruba-ctrl authmgr[1234]: <522007> <WARN> ...
 * AP example:         <30>May 12 10:23:01 AP-LobbyFloor sapd[678]: <305074> <INFO> ...
 *
 * Aruba Mobility Controller logs often contain <MSGID> and <LEVEL> inline.
 */

'use strict';

const ARUBA_PROGRAMS  = /^(authmgr|sapd|stm|mdns|fpapps|nanny|aruba-airwave|localdb|nbapi|profmgr|certmgr|datapath|wms)/i;
const ARUBA_DETECT_RE = /<\d+>\s*\w{3}\s+\d+\s+[\d:]+\s+\S+\s+(authmgr|sapd|stm|fpapps|nanny|aruba|localdb|profmgr|certmgr|wms)/i;
const ARUBA_LEVEL_RE  = /<(EMERG|ALERT|CRIT|ERR|WARN|NOTICE|INFO|DBG)>/i;

const ARUBA_SEV_MAP = {
  'EMERG': 0, 'ALERT': 1, 'CRIT': 2, 'ERR': 3,
  'WARN': 4, 'NOTICE': 5, 'INFO': 6, 'DBG': 7,
};
const ARUBA_SEV_LABELS = {
  'EMERG': 'emergency', 'ALERT': 'alert', 'CRIT': 'critical', 'ERR': 'error',
  'WARN': 'warning', 'NOTICE': 'notice', 'INFO': 'info', 'DBG': 'debug',
};

const RFC3164_ARUBA = /^<(\d{1,3})>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)/s;

function parseAruba(raw, sourceIp) {
  if (!ARUBA_DETECT_RE.test(raw)) return null;

  const m = RFC3164_ARUBA.exec(raw);
  if (!m) return null;

  const pri     = parseInt(m[1], 10);
  const facility = Math.floor(pri / 8);
  let severity   = pri % 8;
  let sevLabel   = ['emergency','alert','critical','error','warning','notice','info','debug'][severity] || 'info';

  const msgBody = m[6] || '';

  // Aruba may embed <WARN>, <INFO> etc. in the message body - use that if present
  const levelMatch = ARUBA_LEVEL_RE.exec(msgBody);
  if (levelMatch) {
    const lvl = levelMatch[1].toUpperCase();
    severity  = ARUBA_SEV_MAP[lvl] ?? severity;
    sevLabel  = ARUBA_SEV_LABELS[lvl] ?? sevLabel;
  }

  // Extract Aruba message ID if present: <522007>
  const msgIdMatch = /<(\d{6})>/.exec(msgBody);
  const msgId      = msgIdMatch ? msgIdMatch[1] : null;
  const cleanMsg   = msgBody.replace(/<[^>]+>/g, '').trim();

  const year = new Date().getFullYear();

  return {
    source_ip:       sourceIp,
    source_host:     m[3] || null,
    facility,
    facility_label:  ['kern','user','mail','daemon','auth','syslog','lpr','news','uucp','cron','authpriv','ftp','ntp','audit','alert2','clock','local0','local1','local2','local3','local4','local5','local6','local7'][facility] || 'local7',
    severity,
    severity_label:  sevLabel,
    vendor:          'aruba',
    program:         m[4] || null,
    message:         cleanMsg || msgBody,
    raw_message:     raw,
    structured_data: { msg_id: msgId, program: m[4], pid: m[5] },
    is_parsed:       true,
    log_timestamp:   new Date(`${m[2]} ${year}`),
  };
}

module.exports = { parseAruba };
