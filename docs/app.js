'use strict';
const USE_BACKEND = false;

const $ = (s) => document.querySelector(s);
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
const esc = (s) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const chipify = (s) => esc(s).replace(/\[REDACTED\]/g, '<span class="chip">[REDACTED]</span>');
const LABEL = { high: 'High', medium: 'Medium', low: 'Low' };

const SAMPLE = `const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
app.get("/user", (req, res) => {
  const q = "SELECT * FROM users WHERE id = " + req.query.id;
  db.query(q);
});
eval(req.body.expression);`;


const RULES = [
  { id: 'aws', sev: 'high', secret: true, re: /AKIA[0-9A-Z]{16}/, title: 'Hardcoded AWS access key',
    why: 'Anyone who sees this file, including in a public repo, can use your cloud account.',
    fix: 'Use an environment variable, add .env to .gitignore, and rotate the exposed key.',
    after: 'const AWS_KEY = process.env.AWS_KEY;' },
  { id: 'secret', sev: 'high', secret: true, re: /(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*["'][^"']{6,}["']/i, title: 'Hardcoded password or token',
    why: 'Secrets in source code get copied, committed and leaked. Attackers scan public code for them.',
    fix: 'Move it to an environment variable and rotate it if it was ever shared.',
    after: 'const secret = process.env.SECRET;' },
  { id: 'sql', sev: 'high', re: /(select|insert|update|delete)\b[^\n]*["'`]\s*\+/i, title: 'SQL built by joining strings',
    why: 'An attacker can change the query by sending specially crafted input.',
    fix: 'Use a parameterized query so input is always treated as data.',
    after: 'db.query("SELECT * FROM users WHERE id = ?", [req.query.id]);' },
  { id: 'eval', sev: 'medium', re: /\beval\s*\(/, title: 'Use of eval()',
    why: 'eval runs any text as code, so user input can become running code.',
    fix: 'Parse the input safely instead of executing it.',
    after: 'const value = JSON.parse(req.body.expression);' },
  { id: 'cunsafe', sev: 'high', re: /\b(gets|strcpy)\s*\(/, title: 'Unsafe C function',
    why: 'These functions do not check length, so long input can overwrite memory.',
    fix: 'Use fgets() or strncpy() with an explicit size limit.',
    after: 'fgets(buf, sizeof(buf), stdin);' },
];


function scan(code) {
  const findings = [];
  const out = code.split('\n').map((ln, i) => {
    let safe = ln, hit = false;
    for (const r of RULES) {
      if ((r.secret && hit) || !r.re.test(ln)) continue;
      if (r.secret) {
        hit = true;
        safe = ln.replace(r.re, (m) => (r.id === 'secret' ? m.replace(/(["'])[^"']+\1/, '$1[REDACTED]$1') : '[REDACTED]'));
      }
      findings.push({ ...r, line: i + 1 });
    }
    return safe;
  });
  findings.forEach((f) => (f.snippet = out[f.line - 1].trim()));
  return { findings, redacted: out.join('\n') };
}


async function backendExplain(r) {
  // Send ONLY redacted code and minimal finding info. Never the matched secret text.
  const res = await fetch('/api/review', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code: r.redacted, findings: r.findings.map((f) => ({ id: f.id, line: f.line, severity: f.sev })) }),
  });
  if (!res.ok) throw new Error('Backend error');
  const data = await res.json(); // expected: { explanations: { [id]: { why, fix } } }
  r.findings.forEach((f) => Object.assign(f, data.explanations?.[f.id] || {}));
}


function card(f, open) {
  return `<details class="finding ${f.sev}" ${open ? 'open' : ''}><summary>
    <span class="badge ${f.sev}">${LABEL[f.sev]}</span><span class="ftitle">${esc(f.title)}</span><span class="line-chip">Line ${f.line}</span></summary>
    <div class="fbody"><pre class="snip">${chipify(f.snippet)}</pre>
    <h4>Why it's dangerous</h4><p>${esc(f.why)}</p>
    <h4>How to fix it</h4><p>${esc(f.fix)}</p>
    <pre class="diff"><span class="del">- ${chipify(f.snippet)}</span><span class="add">+ ${esc(f.after)}</span></pre></div></details>`;
}

const STEPS = ['Detect', 'Protect', 'Explain'];
function setSteps(el, n) { // n = index of active step; 3 = all done
  el.innerHTML = STEPS.map((s, i) => `<li data-n="${i + 1}" class="${i < n ? 'done' : i === n ? 'active' : ''}">${s}</li>`).join('');
}
const counts = (fs) => fs.reduce((c, f) => ((c[f.sev]++), c), { high: 0, medium: 0, low: 0 });

/* ---------- App flow ---------- */
const rp = $('#rp'), code = $('#code');
const setState = (s) => (rp.dataset.state = s);

async function review() {
  if (!code.value.trim()) return setState('empty');
  try {
    setState('loading'); setSteps($('#appSteps'), 0);
    await wait(reduce ? 0 : 500);
    const r = scan(code.value);
    setSteps($('#appSteps'), 1); await wait(reduce ? 0 : 600);
    setSteps($('#appSteps'), 2);
    if (USE_BACKEND) await backendExplain(r); else await wait(reduce ? 0 : 500);
    setSteps($('#appSteps'), 3);
    const c = counts(r.findings);
    $('#total').textContent = `${r.findings.length} finding${r.findings.length === 1 ? '' : 's'}`;
    $('#counts').innerHTML = ['high', 'medium', 'low'].map((k) => `<span class="badge ${k}">${LABEL[k]} ${c[k]}</span>`).join('');
    $('#results').innerHTML = r.findings.map((f, i) => card(f, i === 0)).join('');
    $('#redacted').innerHTML = chipify(r.redacted);
    setState(r.findings.length ? 'results' : 'ok');
  } catch (e) { setState('error'); }
}

const updateGutter = () => {
  $('#gutter').textContent = code.value.split('\n').map((_, i) => i + 1).join('\n');
};
code.addEventListener('input', updateGutter);
code.addEventListener('scroll', () => ($('#gutter').scrollTop = code.scrollTop));
$('#sample').onclick = () => { code.value = SAMPLE; updateGutter(); };
$('#review').onclick = review;
$('#retry').onclick = review;


const words = ['Detects', 'Protects', 'Explains'];
if (!reduce) {
  let w = 0; const rot = $('#rot');
  setInterval(() => {
    rot.className = 'rot out';
    setTimeout(() => { w = (w + 1) % 3; rot.textContent = words[w]; rot.className = 'rot in'; }, 250);
  }, 2500);
}


const demo = scan(SAMPLE);
const lines = SAMPLE.split('\n');
function countUp(el, to, label) {
  let n = 0; const t = setInterval(() => { el.textContent = `${label} ${n}`; if (n++ >= to) clearInterval(t); }, 250);
}
function runDemo() {
  const codeEl = $('#demoCode'), cards = $('#demoCards'), info = $('#demoCounts'), scanEl = $('#scan');
  codeEl.innerHTML = lines.map((l) => `<span class="ln">${l.includes('AKIA') ? esc(l).replace(/AKIA\w+/, '<span class="key">$&</span>') : esc(l)}</span>`).join('');
  cards.innerHTML = ''; info.textContent = ''; setSteps($('#demoSteps'), 0);
  const c = counts(demo.findings), key = () => codeEl.querySelector('.key');
  const finish = () => {
    codeEl.querySelectorAll('.ln').forEach((l) => l.classList.add('show'));
    key().className = 'chip'; key().textContent = '[REDACTED]';
    setSteps($('#demoSteps'), 2);
    cards.innerHTML = demo.findings.map((f, i) => card(f, i === 0)).join('');
    info.textContent = `High ${c.high} · Medium ${c.medium} · Low ${c.low}`;
  };
  if (reduce) return finish();
  const at = (ms, fn) => setTimeout(fn, ms);
  codeEl.querySelectorAll('.ln').forEach((l, i) => at(i * 250, () => l.classList.add('show')));
  at(1500, () => { scanEl.classList.add('go'); });
  at(2500, () => key().classList.add('hot'));
  at(3000, () => { key().className = 'chip'; key().textContent = '[REDACTED]'; scanEl.classList.remove('go'); setSteps($('#demoSteps'), 2); });
  demo.findings.forEach((f, i) => at(3500 + i * 250, () => cards.insertAdjacentHTML('beforeend', card(f, i === 0))));
  at(5500, () => { countUp(info, 0, ''); info.textContent = `High ${c.high} · Medium ${c.medium} · Low ${c.low}`; });
  at(6500, () => setSteps($('#demoSteps'), 3));
  at(8500, runDemo);
}
runDemo();
updateGutter();
