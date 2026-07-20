export default {
  id: "detecting-web-shells",
  title: "Detecting Web Shells",
  src: "Detecting Web Shells",
  icon: "🐚",
  cards: [
    {
      title: "What a web shell is",
      blocks: [
        { t: "txt", text: "A script an attacker uploads onto a compromised server (via a file-upload vuln, RCE, etc.) that gives them a persistent, <b>browser-accessible</b> command interface — no need to maintain an active exploit connection, they just revisit the uploaded file's URL. This is why web shells are a favorite for <b>persistence</b>, not just initial access." },
        { t: "txt", text: "Three detection angles, same triad as the rest of this module: <b>file system</b> analysis (where it lives), <b>log</b> analysis (how it arrived + was used), <b>network traffic</b> analysis (what the upload/commands looked like on the wire)." },
      ],
    },
    {
      title: "File system analysis",
      span2: true,
      blocks: [
        { t: "table", head: ["Where to look", "Why"], rows: [
          ["/var/www/html/", "standard Apache web root"],
          ["/usr/share/nginx/html/", "standard Nginx web root"],
          ["/tmp", "abused if directory permissions let a web-facing process write + execute there"],
        ]},
        { t: "note", kind: "warn", title: "filename evasion tell — double extensions", text: "e.g. <code>image.jpg.php</code> — exploits lax server config to get PHP executed despite looking like a harmless image upload. Random/suspicious filenames are the other common tell." },
        { t: "cmd", label: "hunt PHP files in the web root", code: "find /var/www/html -name \"*.php\"" },
        { t: "cmd", label: "search file contents for shell indicators", code: "grep -r \"eval(\\|base64_decode(\\|system(\" /var/www/html" },
        { t: "note", kind: "info", title: "why find + grep", text: "<code>find</code> locates candidate files by name/pattern/modification time; <code>grep</code> confirms by searching file contents for shell-typical function calls. Used together — filename alone isn't proof, content is." },
      ],
    },
    {
      title: "Network traffic indicators",
      blocks: [
        { t: "note", kind: "danger", title: "web server spawning a shell", text: "The most damning host-side signal: <code>apache2</code>/<code>nginx</code>/<code>php-fpm</code> forking <code>bash</code>/<code>whoami</code>/<code>id</code>. A web server has no legitimate reason to spawn a command-line shell on its own." },
        { t: "txt", text: "Other tells: unusual HTTP methods (a <b>PUT</b> where the app normally only does GET/POST — PUT is literally the method meant for uploading/replacing a resource), suspicious User-Agents, encoded payloads in the request body, unexpected ports/protocols." },
        { t: "note", kind: "info", title: "what PCAP proves that logs often can't", text: "The <b>direct upload</b> of the shell file itself (visible in the request body when captured), and the actual <b>command payload</b> sent on subsequent requests — same \"network captures see the body, logs often don't\" principle as the Detecting Web Attacks room." },
      ],
    },
    {
      title: "Wireshark filters",
      blocks: [
        { t: "cmd", label: "flag an anomalous HTTP method (upload vector)", code: "http.request.method == \"PUT\"" },
        { t: "cmd", label: "narrow to requests touching PHP files", code: "http.request.uri contains \".php\"" },
        { t: "cmd", label: "surface the requesting client's UA for tool-signature hunting", code: "http.user_agent" },
      ],
    },
  ],
};
