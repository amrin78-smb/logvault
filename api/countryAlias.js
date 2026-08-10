'use strict';
/**
 * countryAlias.js — reconciles the two country-name spellings in this database.
 *
 * FortiGate writes ISO 3166 long-form names into structured_data.srccountry /
 * dstcountry ("Russian Federation", "Korea, Republic of"). known_hosts, which is
 * where country_code comes from, is populated by GeoIP enrichment using common
 * names ("Russia", "South Korea"). An exact-match join therefore misses those
 * rows: the country still ranks with the right count, but resolves no ISO code,
 * so it loses its flag and — on the Threat Map, whose centroids are keyed by
 * alpha-2 — its map bubble too. It fails silently; nothing errors, a pin is just
 * quietly absent.
 *
 * The first five entries are the mismatches actually observed in this
 * deployment's own data (every distinct srccountry/dstcountry over 7 days with
 * no known_hosts counterpart). The rest are the other ISO long forms that would
 * hit the same problem the first time traffic from one appears — the failure is
 * invisible, so waiting to be told about each one is not a workable way to find
 * them.
 *
 * An alias whose target is absent from known_hosts is harmless: the join simply
 * misses as it does today. So over-listing costs nothing and under-listing costs
 * a silently missing pin.
 *
 * IMPORTANT: this maps a name only for the purpose of LOOKING UP a code. The
 * name shown to the user must stay the firewall's own spelling, because clicking
 * a country runs a free-text Log Explorer search on that string — display
 * "Russia" while the logs say "Russian Federation" and every drill-through comes
 * back empty.
 */

// [ what the firewall writes, what known_hosts calls it ]
const COUNTRY_ALIASES = [
  // ── Observed live in this deployment ──
  ['Czech Republic', 'Czechia'],
  ['Iran, Islamic Republic of', 'Iran'],
  ['Korea, Republic of', 'South Korea'],
  ["Lao People's Democratic Republic", 'Laos'],
  ['Russian Federation', 'Russia'],
  // ── Same ISO-long-form pattern, not yet seen here ──
  ['Korea, Democratic People\'s Republic of', 'North Korea'],
  ['Syrian Arab Republic', 'Syria'],
  ['Viet Nam', 'Vietnam'],
  ['Taiwan, Province of China', 'Taiwan'],
  ['Moldova, Republic of', 'Moldova'],
  ['Bolivia, Plurinational State of', 'Bolivia'],
  ['Venezuela, Bolivarian Republic of', 'Venezuela'],
  ['Tanzania, United Republic of', 'Tanzania'],
  ['Congo, The Democratic Republic of the', 'DR Congo'],
  ['Palestine, State of', 'Palestine'],
  ['Brunei Darussalam', 'Brunei'],
  ['Macao', 'Macau'],
  ['Micronesia, Federated States of', 'Micronesia'],
  ['Libyan Arab Jamahiriya', 'Libya'],
  ['Macedonia, the former Yugoslav Republic of', 'North Macedonia'],
  ['Bosnia and Herzegovina', 'Bosnia & Herzegovina'],
  ['Holy See (Vatican City State)', 'Vatican City'],
  ['Netherlands, Kingdom of the', 'Netherlands'],
];

// Single-quote escaping for the inlined VALUES list below. Every value here is a
// hardcoded literal from this file — no user input reaches it — but the list
// contains apostrophes ("Lao People's..."), which would otherwise break the SQL.
const q = (s) => `'${String(s).replace(/'/g, "''")}'`;

/**
 * A CTE mapping the firewall's spelling to the known_hosts spelling. Join it as:
 *
 *   WITH ${countryAliasCte()}, code_map AS (...), agg AS (...)
 *   SELECT ...
 *   FROM agg
 *   LEFT JOIN country_alias ca ON ca.raw = agg.country
 *   LEFT JOIN code_map cm ON cm.country_name = COALESCE(ca.common, agg.country)
 *
 * COALESCE means an unaliased name still joins on itself, so this only ever adds
 * matches — it can never remove one that works today.
 */
function countryAliasCte() {
  const values = COUNTRY_ALIASES.map(([raw, common]) => `(${q(raw)}, ${q(common)})`).join(', ');
  return `country_alias(raw, common) AS (VALUES ${values})`;
}

module.exports = { COUNTRY_ALIASES, countryAliasCte };
