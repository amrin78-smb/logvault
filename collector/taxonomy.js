'use strict';

/**
 * Universal Event Taxonomy
 *
 * Assigns a standard `category` to every parsed log entry so the UI and
 * alerting can reason about events consistently across all vendors.
 *
 * Standard categories:
 *   authentication, vpn, firewall, interface, routing, configuration,
 *   security, wireless, system, dns, web, email, dlp, network (fallback)
 */

function getCategory(vendor, structured, message) {
  const msg  = (message || '').toLowerCase();
  const cat  = (structured.category || '').toLowerCase();

  // Already categorized by the parser — trust it unless it's the generic fallback
  if (cat && cat !== 'network') return cat;

  // Authentication
  if (/login|logon|auth|password|credential|account|ldap|radius|saml/i.test(msg)) return 'authentication';

  // VPN
  if (/vpn|tunnel|ipsec|ssl-vpn|ikev|phase.?[12]|dialup/i.test(msg)) return 'vpn';

  // Security/IPS
  if (/ips|ids|intrusion|threat|malware|exploit|attack|signature|anomaly/i.test(msg)) return 'security';

  // Interface
  if (/link.?(up|down)|interface|port.?(up|down)|flap|stp|spanning.?tree|lag|lacp/i.test(msg)) return 'interface';

  // Routing
  if (/bgp|ospf|rip|eigrp|neighbor|adjacency|route|prefix/i.test(msg)) return 'routing';

  // Configuration
  if (/config|configured|admin|policy.?change|firmware|upgrade|backup/i.test(msg)) return 'configuration';

  // DNS
  if (/dns|domain.?name|nxdomain|ptr|resolve/i.test(msg)) return 'dns';

  // Web
  if (/http|https|url|web|proxy|browse|request|response/i.test(msg)) return 'web';

  // Wireless
  if (/wifi|wireless|ssid|802\.1[x1]|wpa|eap|ap.?client|associate/i.test(msg)) return 'wireless';

  // System
  if (/reboot|restart|shutdown|cpu|memory|disk|temperature|power|service/i.test(msg)) return 'system';

  // Firewall (action-based)
  if (structured.action === 'blocked' || structured.action === 'allowed') return 'firewall';

  return 'network';
}

module.exports = { getCategory };
