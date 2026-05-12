const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  HeadingLevel, AlignmentType, BorderStyle, WidthType, ShadingType,
  PageNumber, Header, Footer, LevelFormat, PageBreak
} = require('docx');
const fs = require('fs');

const BLUE    = '1E3A5F';
const ACCENT  = '38BDF8';
const LIGHT   = 'F0F9FF';
const GRAY    = '64748B';
const RED     = 'DC2626';
const GREEN   = '16A34A';
const DARKBG  = '0F1117';

const cellBorder = { style: BorderStyle.SINGLE, size: 1, color: 'D1D5DB' };
const cellBorders = { top: cellBorder, bottom: cellBorder, left: cellBorder, right: cellBorder };

function h1(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_1,
    spacing: { before: 360, after: 160 },
    border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: ACCENT, space: 6 } },
    children: [new TextRun({ text, bold: true, size: 36, color: BLUE, font: 'Arial' })]
  });
}

function h2(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_2,
    spacing: { before: 280, after: 120 },
    children: [new TextRun({ text, bold: true, size: 28, color: BLUE, font: 'Arial' })]
  });
}

function h3(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_3,
    spacing: { before: 200, after: 80 },
    children: [new TextRun({ text, bold: true, size: 24, color: '1E40AF', font: 'Arial' })]
  });
}

function para(text, opts = {}) {
  return new Paragraph({
    spacing: { before: 60, after: 80 },
    children: [new TextRun({ text, size: 22, font: 'Arial', color: '1F2937', ...opts })]
  });
}

function code(text) {
  return new Paragraph({
    spacing: { before: 40, after: 40 },
    shading: { fill: '1E293B', type: ShadingType.CLEAR },
    border: {
      left: { style: BorderStyle.SINGLE, size: 12, color: ACCENT }
    },
    indent: { left: 240 },
    children: [new TextRun({ text, font: 'Consolas', size: 18, color: '7DD3FC' })]
  });
}

function note(text, color = '1D4ED8', bg = 'EFF6FF') {
  return new Paragraph({
    spacing: { before: 80, after: 80 },
    shading: { fill: bg, type: ShadingType.CLEAR },
    border: { left: { style: BorderStyle.SINGLE, size: 10, color } },
    indent: { left: 240 },
    children: [new TextRun({ text, size: 20, font: 'Arial', color: '1F2937', italics: true })]
  });
}

function spacer() {
  return new Paragraph({ spacing: { before: 60, after: 60 }, children: [new TextRun('')] });
}

function bullet(text, bold = false) {
  return new Paragraph({
    numbering: { reference: 'bullets', level: 0 },
    spacing: { before: 40, after: 40 },
    children: [new TextRun({ text, size: 22, font: 'Arial', bold, color: '1F2937' })]
  });
}

function tableRow(cells, isHeader = false) {
  return new TableRow({
    children: cells.map((cell, i) => new TableCell({
      borders: cellBorders,
      shading: { fill: isHeader ? BLUE : (i === 0 ? 'F8FAFC' : 'FFFFFF'), type: ShadingType.CLEAR },
      margins: { top: 80, bottom: 80, left: 120, right: 120 },
      children: [new Paragraph({
        children: [new TextRun({
          text: cell, size: 20, font: 'Arial',
          bold: isHeader, color: isHeader ? 'FFFFFF' : '1F2937'
        })]
      })]
    }))
  });
}

function makeTable(headers, rows, widths) {
  return new Table({
    width: { size: 9360, type: WidthType.DXA },
    columnWidths: widths,
    rows: [
      tableRow(headers, true),
      ...rows.map(r => tableRow(r))
    ]
  });
}

function pageBreak() {
  return new Paragraph({ children: [new PageBreak()] });
}

// ─────────────────────────────────────────────────────────────
const doc = new Document({
  numbering: {
    config: [{
      reference: 'bullets',
      levels: [{
        level: 0, format: LevelFormat.BULLET, text: '\u2022',
        alignment: AlignmentType.LEFT,
        style: { paragraph: { indent: { left: 480, hanging: 240 } } }
      }]
    }, {
      reference: 'numbers',
      levels: [{
        level: 0, format: LevelFormat.DECIMAL, text: '%1.',
        alignment: AlignmentType.LEFT,
        style: { paragraph: { indent: { left: 480, hanging: 240 } } }
      }]
    }]
  },
  styles: {
    default: { document: { run: { font: 'Arial', size: 22 } } },
    paragraphStyles: [
      { id: 'Heading1', name: 'Heading 1', basedOn: 'Normal', next: 'Normal', quickFormat: true,
        run: { size: 36, bold: true, font: 'Arial', color: BLUE },
        paragraph: { spacing: { before: 360, after: 160 }, outlineLevel: 0 } },
      { id: 'Heading2', name: 'Heading 2', basedOn: 'Normal', next: 'Normal', quickFormat: true,
        run: { size: 28, bold: true, font: 'Arial', color: BLUE },
        paragraph: { spacing: { before: 280, after: 120 }, outlineLevel: 1 } },
      { id: 'Heading3', name: 'Heading 3', basedOn: 'Normal', next: 'Normal', quickFormat: true,
        run: { size: 24, bold: true, font: 'Arial', color: '1E40AF' },
        paragraph: { spacing: { before: 200, after: 80 }, outlineLevel: 2 } },
    ]
  },
  sections: [{
    properties: {
      page: {
        size: { width: 12240, height: 15840 },
        margin: { top: 1440, right: 1260, bottom: 1440, left: 1260 }
      }
    },
    headers: {
      default: new Header({
        children: [new Paragraph({
          border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: ACCENT } },
          spacing: { after: 80 },
          children: [
            new TextRun({ text: 'LogVault', bold: true, size: 20, font: 'Arial', color: BLUE }),
            new TextRun({ text: '  |  Syslog Analyzer Installation & Setup Guide', size: 18, font: 'Arial', color: GRAY }),
            new TextRun({ text: '  |  NexVault Product Family', size: 18, font: 'Arial', color: GRAY }),
          ]
        })]
      })
    },
    footers: {
      default: new Footer({
        children: [new Paragraph({
          border: { top: { style: BorderStyle.SINGLE, size: 4, color: 'E5E7EB' } },
          spacing: { before: 80 },
          alignment: AlignmentType.CENTER,
          children: [
            new TextRun({ text: 'LogVault v1.0  |  Internal Use  |  Page ', size: 18, font: 'Arial', color: GRAY }),
            new TextRun({ children: [PageNumber.CURRENT], size: 18, font: 'Arial', color: GRAY }),
            new TextRun({ text: ' of ', size: 18, font: 'Arial', color: GRAY }),
            new TextRun({ children: [PageNumber.TOTAL_PAGES], size: 18, font: 'Arial', color: GRAY }),
          ]
        })]
      })
    },
    children: [

      // ── COVER ──────────────────────────────────────────────
      new Paragraph({
        spacing: { before: 1200, after: 80 },
        alignment: AlignmentType.CENTER,
        children: [new TextRun({ text: 'LogVault', bold: true, size: 72, font: 'Arial', color: BLUE })]
      }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { after: 40 },
        children: [new TextRun({ text: 'Syslog Analyzer', size: 40, font: 'Arial', color: '1E40AF' })]
      }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { after: 200 },
        children: [new TextRun({ text: 'Installation & Setup Guide', size: 28, font: 'Arial', color: GRAY })]
      }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { after: 60 },
        children: [new TextRun({ text: 'Version 1.0  |  NexVault Product Family', size: 22, font: 'Arial', color: GRAY })]
      }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { after: 60 },
        children: [new TextRun({ text: 'Windows Server  |  TimescaleDB  |  Node.js  |  Next.js', size: 20, font: 'Arial', color: GRAY, italics: true })]
      }),
      spacer(), spacer(),

      makeTable(
        ['Component', 'Detail'],
        [
          ['Syslog Ports',    'UDP + TCP 514 and 1514'],
          ['Web Interface',   'http://localhost:3004'],
          ['Internal API',    'http://localhost:3005'],
          ['Database',        'TimescaleDB — logvault database'],
          ['Services (NSSM)', 'LogVaultCollector, LogVaultAPI, LogVaultApp'],
          ['Retention',       '90 days (configurable)'],
          ['Vendor Parsers',  'Cisco, Palo Alto, Fortinet, Aruba, Sangfor, Generic'],
        ],
        [2800, 6560]
      ),
      pageBreak(),

      // ── OVERVIEW ───────────────────────────────────────────
      h1('1. Overview'),
      para('LogVault is the syslog collection and analysis product in the NexVault family. It runs entirely on Windows Server without Docker or cloud dependencies, following the same architecture pattern as NetVault and SpanVault. LogVault listens for syslog messages from any network device, parses them using vendor-specific parsers, stores them in TimescaleDB, and presents a real-time dashboard with log search, live streaming, and alert management.'),
      spacer(),

      h2('1.1 Architecture'),
      para('LogVault consists of three processes managed as Windows services via NSSM:'),
      spacer(),
      makeTable(
        ['Service', 'Description', 'Port'],
        [
          ['LogVaultCollector', 'Syslog UDP/TCP listener and parser. Receives raw syslog, runs vendor parsers, writes to TimescaleDB in batches.', '514, 1514'],
          ['LogVaultAPI',       'Express REST API and WebSocket server. Serves log queries, dashboard stats, alert rules, and live tail stream.',   '3005 (internal)'],
          ['LogVaultApp',       'Next.js frontend. Serves the web dashboard and proxies API calls to LogVaultAPI.',                                  '3004 (public)'],
        ],
        [2200, 5160, 2000]
      ),
      spacer(),

      h2('1.2 Vendor Parsers Included'),
      makeTable(
        ['Parser', 'Vendor/Device', 'Format'],
        [
          ['generic.js',   'Any device (RFC 3164 / RFC 5424)',    'Standard syslog with PRI header'],
          ['cisco.js',     'Cisco IOS, IOS-XE routers/switches',  '%FACILITY-SEVERITY-MNEMONIC pattern'],
          ['paloalto.js',  'Palo Alto PAN-OS firewalls',          'CSV log format (TRAFFIC, THREAT, SYSTEM)'],
          ['fortinet.js',  'Fortinet FortiOS firewalls',          'Key=value pair format'],
          ['aruba.js',     'Aruba/HP ProCurve APs, Controllers',  'RFC 3164 with embedded severity tags'],
          ['sangfor.js',   'Sangfor NGFW/SSL VPN/IAM',            'CEF format or RFC 3164'],
        ],
        [1600, 2800, 4960]
      ),
      pageBreak(),

      // ── PREREQUISITES ──────────────────────────────────────
      h1('2. Prerequisites'),
      para('LogVault shares the same runtime dependencies as NetVault and SpanVault. If those products are already running on this server, you only need to create the new database. No additional software installation is required.'),
      spacer(),
      makeTable(
        ['Requirement', 'Minimum Version', 'Notes'],
        [
          ['Windows Server',       '2016 or later',   'Same server as NetVault/SpanVault is fine'],
          ['Node.js',              '18.x LTS',        'Already installed for NetVault/SpanVault'],
          ['PostgreSQL',           '14+',             'Already installed'],
          ['TimescaleDB extension','2.x',             'Must be enabled on the logvault database'],
          ['NSSM',                 'Any version',     'Already installed for NetVault/SpanVault'],
          ['npm',                  '9+',              'Bundled with Node.js'],
        ],
        [2400, 2000, 4960]
      ),
      spacer(),

      note('Port 514 on Windows does not require elevated privileges for Node.js, unlike on Linux. Your Node.js process can bind directly. If another service is already on port 514, configure your devices to send to port 1514 only and remove 514 from the listener configuration.'),
      pageBreak(),

      // ── DATABASE SETUP ─────────────────────────────────────
      h1('3. Database Setup'),
      para('LogVault uses its own database on the existing TimescaleDB/PostgreSQL instance. It does not share a database with NetVault or SpanVault.'),
      spacer(),

      h2('3.1 Create Database and User'),
      para('Open pgAdmin or psql connected as the postgres superuser and run the following:'),
      spacer(),
      code("CREATE USER logvault_user WITH PASSWORD 'your-strong-password-here';"),
      code('CREATE DATABASE logvault OWNER logvault_user;'),
      code('GRANT ALL PRIVILEGES ON DATABASE logvault TO logvault_user;'),
      spacer(),
      para('Then connect to the logvault database and enable TimescaleDB:'),
      spacer(),
      code('\\c logvault'),
      code('CREATE EXTENSION IF NOT EXISTS timescaledb;'),
      spacer(),

      h2('3.2 Run the Schema Script'),
      para('Execute the schema.sql file from the scripts folder against the logvault database. In pgAdmin, connect to the logvault database, open the Query Tool, paste the contents of scripts/schema.sql, and run it. The schema creates the main syslog_entries hypertable, continuous aggregates for dashboard performance, alert rules and events tables, known hosts table, and default alert rules.'),
      spacer(),
      note('The schema automatically sets up a 90-day retention policy on syslog_entries using TimescaleDB\'s native retention policy feature. Older data is purged automatically without any manual intervention.'),
      pageBreak(),

      // ── INSTALLATION ───────────────────────────────────────
      h1('4. Installation'),

      h2('4.1 Deploy Application Files'),
      para('Copy the logvault folder to your server. The recommended location follows the same convention as NetVault and SpanVault:'),
      spacer(),
      code('C:\\Apps\\logvault\\'),
      spacer(),

      h2('4.2 Configure Environment'),
      para('Copy the .env.local.example file to .env.local and fill in the database password. The other values are correct by default for a standard installation:'),
      spacer(),
      code('copy C:\\Apps\\logvault\\.env.local.example C:\\Apps\\logvault\\.env.local'),
      spacer(),
      para('Edit .env.local and set LV_DB_PASS to the password you used when creating the logvault_user database account. All other settings can remain as-is for a default installation.'),
      spacer(),

      h2('4.3 Install Node.js Dependencies'),
      para('Open a Command Prompt in C:\\Apps\\logvault and run:'),
      spacer(),
      code('npm install'),
      code('cd frontend && npm install && cd ..'),
      spacer(),

      h2('4.4 Build the Frontend'),
      para('Build the Next.js frontend for production:'),
      spacer(),
      code('cd C:\\Apps\\logvault\\frontend'),
      code('npm run build'),
      code('cd ..'),
      spacer(),

      h2('4.5 Test Before Adding Services'),
      para('Before registering NSSM services, verify each process starts correctly by running them manually. Open three separate Command Prompt windows:'),
      spacer(),
      para('Window 1 — Collector:'),
      code('cd C:\\Apps\\logvault && node collector/collector.js'),
      spacer(),
      para('Window 2 — API:'),
      code('cd C:\\Apps\\logvault && node api/server.js'),
      spacer(),
      para('Window 3 — Frontend:'),
      code('cd C:\\Apps\\logvault\\frontend && npm start'),
      spacer(),
      para('Then open http://localhost:3004 in a browser. You should see the LogVault dashboard. Stop all three processes with Ctrl+C once confirmed.'),
      pageBreak(),

      // ── NSSM SERVICES ──────────────────────────────────────
      h1('5. Windows Service Registration (NSSM)'),
      para('Register LogVault as three Windows services using NSSM, following the same pattern as NetVault and SpanVault. Open an elevated Command Prompt (Run as Administrator).'),
      spacer(),

      h2('5.1 LogVault Collector Service'),
      code('nssm install LogVaultCollector "C:\\Program Files\\nodejs\\node.exe"'),
      code('nssm set LogVaultCollector AppParameters "C:\\Apps\\logvault\\collector\\collector.js"'),
      code('nssm set LogVaultCollector AppDirectory "C:\\Apps\\logvault"'),
      code('nssm set LogVaultCollector DisplayName "LogVault Collector"'),
      code('nssm set LogVaultCollector Description "LogVault syslog receiver and parser"'),
      code('nssm set LogVaultCollector AppStdout "C:\\Apps\\logvault\\logs\\collector.log"'),
      code('nssm set LogVaultCollector AppStderr "C:\\Apps\\logvault\\logs\\collector-err.log"'),
      code('nssm set LogVaultCollector AppRotateFiles 1'),
      code('nssm set LogVaultCollector Start SERVICE_AUTO_START'),
      spacer(),

      h2('5.2 LogVault API Service'),
      code('nssm install LogVaultAPI "C:\\Program Files\\nodejs\\node.exe"'),
      code('nssm set LogVaultAPI AppParameters "C:\\Apps\\logvault\\api\\server.js"'),
      code('nssm set LogVaultAPI AppDirectory "C:\\Apps\\logvault"'),
      code('nssm set LogVaultAPI DisplayName "LogVault API"'),
      code('nssm set LogVaultAPI Description "LogVault REST API and WebSocket server"'),
      code('nssm set LogVaultAPI AppStdout "C:\\Apps\\logvault\\logs\\api.log"'),
      code('nssm set LogVaultAPI AppStderr "C:\\Apps\\logvault\\logs\\api-err.log"'),
      code('nssm set LogVaultAPI AppRotateFiles 1'),
      code('nssm set LogVaultAPI Start SERVICE_AUTO_START'),
      spacer(),

      h2('5.3 LogVault App Service'),
      code('nssm install LogVaultApp "C:\\Program Files\\nodejs\\node.exe"'),
      code('nssm set LogVaultApp AppParameters "C:\\Apps\\logvault\\frontend\\node_modules\\.bin\\next start --port 3004"'),
      code('nssm set LogVaultApp AppDirectory "C:\\Apps\\logvault\\frontend"'),
      code('nssm set LogVaultApp DisplayName "LogVault App"'),
      code('nssm set LogVaultApp Description "LogVault Next.js web dashboard"'),
      code('nssm set LogVaultApp AppStdout "C:\\Apps\\logvault\\logs\\app.log"'),
      code('nssm set LogVaultApp AppStderr "C:\\Apps\\logvault\\logs\\app-err.log"'),
      code('nssm set LogVaultApp AppRotateFiles 1'),
      code('nssm set LogVaultApp Start SERVICE_AUTO_START'),
      spacer(),

      h2('5.4 Create Logs Directory and Start Services'),
      code('mkdir C:\\Apps\\logvault\\logs'),
      code('nssm start LogVaultCollector'),
      code('nssm start LogVaultAPI'),
      code('nssm start LogVaultApp'),
      spacer(),
      para('Verify all three services are running:'),
      code('nssm status LogVaultCollector'),
      code('nssm status LogVaultAPI'),
      code('nssm status LogVaultApp'),
      spacer(),
      para('All three should return SERVICE_RUNNING. Open http://localhost:3004 to confirm the dashboard is accessible.'),
      pageBreak(),

      // ── FIREWALL ───────────────────────────────────────────
      h1('6. Windows Firewall Rules'),
      para('Open Windows Defender Firewall with Advanced Security and create the following inbound rules to allow syslog traffic from your network devices:'),
      spacer(),
      code('netsh advfirewall firewall add rule name="LogVault Syslog UDP 514" protocol=UDP dir=in localport=514 action=allow'),
      code('netsh advfirewall firewall add rule name="LogVault Syslog TCP 514" protocol=TCP dir=in localport=514 action=allow'),
      code('netsh advfirewall firewall add rule name="LogVault Syslog UDP 1514" protocol=UDP dir=in localport=1514 action=allow'),
      code('netsh advfirewall firewall add rule name="LogVault Syslog TCP 1514" protocol=TCP dir=in localport=1514 action=allow'),
      code('netsh advfirewall firewall add rule name="LogVault Web" protocol=TCP dir=in localport=3004 action=allow'),
      spacer(),
      note('If LogVault is accessed only from within the same server, no firewall rules are needed for port 3004. Add that rule only if users will access it from other machines on the network.'),
      pageBreak(),

      // ── DEVICE CONFIGURATION ───────────────────────────────
      h1('7. Configuring Devices to Send Syslog'),
      para('Point your network devices to the LogVault server IP address on port 514 (standard) or 1514 (alternate). Below are configuration examples for the supported vendors.'),
      spacer(),

      h2('7.1 Cisco IOS / IOS-XE'),
      code('logging host <LogVault-Server-IP>'),
      code('logging trap informational'),
      code('logging on'),
      spacer(),

      h2('7.2 Palo Alto PAN-OS'),
      para('Go to Device > Server Profiles > Syslog. Create a new profile with the LogVault server IP and port 514, transport UDP, format BSD. Then under Device > Log Settings, assign this syslog profile to Traffic, Threat, System, and Config log types.'),
      spacer(),

      h2('7.3 Fortinet FortiOS'),
      code('config log syslogd setting'),
      code('    set status enable'),
      code('    set server <LogVault-Server-IP>'),
      code('    set port 514'),
      code('    set facility local7'),
      code('end'),
      spacer(),

      h2('7.4 Aruba / HP ProCurve'),
      para('For Aruba Mobility Controllers, navigate to Configuration > System > Logging. Set the syslog server IP and port 514. For HP ProCurve switches:'),
      code('logging <LogVault-Server-IP>'),
      code('logging severity informational'),
      spacer(),

      h2('7.5 Sangfor'),
      para('In the Sangfor management console, navigate to System > Log Settings > Remote Syslog. Enter the LogVault server IP and port 514. Enable CEF format if available for richer structured data.'),
      pageBreak(),

      // ── DASHBOARD GUIDE ────────────────────────────────────
      h1('8. Dashboard Guide'),

      h2('8.1 Dashboard Tab'),
      para('The main dashboard shows four KPI tiles at the top: total log count, critical/alert count, error count, and warning count, all for the selected time range. Below the tiles, a log volume timeline chart shows ingestion rates over time broken down by severity. The Top Talkers bar chart shows the most active source hosts by log volume. The Vendor Breakdown shows log distribution across device types with critical and error counts highlighted. Recent Critical Events lists the latest severity 0-3 events.'),
      para('The time range selector in the top navigation bar switches all charts simultaneously between 6h, 24h, 48h, and 7d views.'),
      spacer(),

      h2('8.2 Log Explorer Tab'),
      para('The Log Explorer provides full-text search and filtering across all stored logs. Search by message content using the text field. Filter by vendor (Cisco, Fortinet, etc.), severity level, and source host. The time range filter controls how far back to search. Results are paginated and clicking any row expands it to show the full message, all parsed fields from the structured_data column, and metadata such as device timestamp and IP address.'),
      spacer(),

      h2('8.3 Live Tail Tab'),
      para('Live Tail streams new log entries in real time via WebSocket. Logs appear as they are received by the collector, with color-coded severity indicators. Use the filter field to show only messages matching a keyword or hostname. The Pause button freezes the display while still accumulating messages in the buffer. Click Resume to catch up. The maximum buffer size is 500 lines; older lines scroll off the top.'),
      spacer(),

      h2('8.4 Alerts Tab'),
      para('The Alerts tab shows the configured alert rules and the history of fired alerts. Each rule can be enabled or disabled by clicking the status button. The three default rules cover emergency events, sustained critical events, and repeated authentication failures. Fired alerts can be acknowledged using the Ack button, which clears them from the active alert count.'),
      pageBreak(),

      // ── TROUBLESHOOTING ────────────────────────────────────
      h1('9. Troubleshooting'),
      spacer(),
      makeTable(
        ['Symptom', 'Likely Cause', 'Resolution'],
        [
          ['No logs appearing in dashboard', 'Firewall blocking port 514 or device not configured', 'Check Windows Firewall rules. Test with: Test-NetConnection -Port 514'],
          ['Collector service fails to start', 'Database connection error or port 514 in use', 'Check collector.log. Run manually to see error. netstat -an | find ":514"'],
          ['Dashboard shows 0 logs but collector log is active', 'Database write error', 'Check collector-err.log. Verify logvault database and user exist.'],
          ['All logs showing as vendor=generic', 'Parser not matching device format', 'Enable LOG_LEVEL=debug in .env.local and check collector.log for raw messages.'],
          ['Live Tail not updating', 'WebSocket connection blocked or API not running', 'Check browser console for WS errors. Verify LogVaultAPI service is running.'],
          ['High memory usage on collector', 'Very high log volume filling write buffer', 'Reduce BATCH_INTERVAL in collector.js or add more specific syslog filters on devices.'],
        ],
        [2200, 3000, 4160]
      ),
      pageBreak(),

      // ── MANAGEMENT ─────────────────────────────────────────
      h1('10. Ongoing Management'),

      h2('10.1 Service Management'),
      makeTable(
        ['Action', 'Command'],
        [
          ['Start all services',   'nssm start LogVaultCollector && nssm start LogVaultAPI && nssm start LogVaultApp'],
          ['Stop all services',    'nssm stop LogVaultCollector && nssm stop LogVaultAPI && nssm stop LogVaultApp'],
          ['Restart collector',    'nssm restart LogVaultCollector'],
          ['Check service status', 'nssm status LogVaultCollector'],
          ['View logs (live)',      'Get-Content C:\\Apps\\logvault\\logs\\collector.log -Wait -Tail 50'],
        ],
        [3000, 6360]
      ),
      spacer(),

      h2('10.2 Adding a New Vendor Parser'),
      para('To add support for a new device type, create a new file in the parsers folder following the same pattern as the existing parsers. The parser must export a single function that accepts (rawMessage, sourceIp) and returns either a normalized entry object or null. Register the parser in collector.js by importing it and adding it to the PARSERS array before the generic parser entry. A parser that returns null falls through to the next parser in the chain, so order matters only for performance.'),
      spacer(),

      h2('10.3 Adjusting Retention'),
      para('The retention policy is managed by TimescaleDB and was set to 90 days during schema creation. To change it, connect to the logvault database and run:'),
      spacer(),
      code("SELECT remove_retention_policy('syslog_entries');"),
      code("SELECT add_retention_policy('syslog_entries', INTERVAL '180 days');"),
      spacer(),

      h2('10.4 Performance Tuning'),
      para('For environments sending very high log volumes (more than 10,000 events per minute), consider increasing the BATCH_SIZE constant in collector.js from 100 to 500, and reducing BATCH_INTERVAL from 2000ms to 500ms. This increases throughput at the cost of slightly higher memory usage in the write buffer. TimescaleDB handles high-volume time-series inserts very efficiently and should not be a bottleneck at typical enterprise volumes.'),
    ]
  }]
});

Packer.toBuffer(doc).then(buf => {
  fs.writeFileSync('/mnt/user-data/outputs/LogVault_Setup_Guide_v1.0.docx', buf);
  console.log('Done.');
});
