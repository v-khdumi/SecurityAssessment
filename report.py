"""Self-contained HTML with escaped evidence and a restrictive Content Security Policy."""

import base64
import hashlib
import html

from microsoft_guidance import LINK_TITLES

STYLE = """
*{box-sizing:border-box}
:root{color-scheme:light;--bg:#edf2f8;--fg:#15253d;--muted:#4b617c;--card:#fff;--line:#cbd8e8;--accent:#154eaa;--soft:#f4f7fb;--high:#9a263d;--high-bg:#fde7ec;--medium:#744800;--medium-bg:#fff0d6}
:root[data-theme=dark]{color-scheme:dark;--bg:#0e1728;--fg:#ecf3ff;--muted:#b3c5df;--card:#17243a;--line:#394c68;--accent:#a9caff;--soft:#111e33;--high:#ffc1cd;--high-bg:#522639;--medium:#ffdd91;--medium-bg:#48371c}
@media(prefers-color-scheme:dark){:root:not([data-theme=light]){color-scheme:dark;--bg:#0e1728;--fg:#ecf3ff;--muted:#b3c5df;--card:#17243a;--line:#394c68;--accent:#a9caff;--soft:#111e33;--high:#ffc1cd;--high-bg:#522639;--medium:#ffdd91;--medium-bg:#48371c}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
.shell,main{max-width:76rem;margin:auto;padding-inline:clamp(.85rem,3vw,2rem)}
header{background:#152743;color:#f5f8ff;padding:1.55rem 0 1.65rem}
header h1{margin:.25rem 0;font-size:clamp(1.7rem,4vw,2.4rem);line-height:1.14;letter-spacing:-.04em}
header p{margin:.35rem 0;color:#d4e4fa}
.eyebrow{text-transform:uppercase;letter-spacing:.13em;font-weight:720;font-size:.73rem}
nav{position:sticky;top:0;z-index:2;background:var(--card);border-bottom:1px solid var(--line)}
.navigation{min-height:3.5rem;display:flex;align-items:center;gap:.45rem;flex-wrap:wrap;padding-block:.44rem}
a{color:var(--accent);text-underline-offset:.18em}
.jump{font-weight:680;white-space:nowrap;padding:.42rem .65rem;text-decoration:none;border-radius:.45rem}
.jump[aria-current=page]{color:var(--accent);background:var(--soft);box-shadow:inset 0 0 0 1px var(--line)}
label.menu{margin-left:auto;display:flex;align-items:center;gap:.5rem;font-size:.84rem;color:var(--muted)}
button,input,select{font:inherit;color:inherit;background:var(--card);border:1px solid var(--line);border-radius:.5rem;padding:.38rem .63rem;min-width:0}
button,select{cursor:pointer}
:focus-visible{outline:2px solid var(--accent);outline-offset:3px}
.theme{float:right;margin-left:.5rem;background:#243954;color:#fff;border-color:#637592}
main{padding-block:1.2rem 2rem} h2{margin:0 0 .75rem;letter-spacing:-.025em} h3{margin:0}
.section-nav-label{white-space:nowrap}
article{background:var(--card);border:1px solid var(--line);border-radius:.8rem;padding:.95rem 1rem;margin:0 0 .9rem}
article>p{margin:.4rem 0;color:var(--muted)}
.wrap{overflow-x:auto;margin-top:.7rem}
table{border-collapse:collapse;width:100%;min-width:36rem}
th,td{text-align:left;vertical-align:top;padding:.58rem .65rem;border-bottom:1px solid var(--line)}
th{background:var(--soft)} td{overflow-wrap:break-word}
code{font: .92em ui-monospace,Consolas,monospace;overflow-wrap:anywhere}
.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:.65rem;margin-bottom:.9rem}
.metric{background:var(--card);border:1px solid var(--line);border-radius:.7rem;padding:.72rem .85rem;color:var(--muted)}
.metric b{display:block;color:var(--fg);font:700 1.65rem/1.2 ui-monospace,Consolas,monospace}
.notice{border-left:3px solid var(--accent);padding:.55rem .75rem;background:var(--soft);margin:.55rem 0 .9rem}
.filters{display:flex;gap:.7rem;align-items:end;flex-wrap:wrap;margin:.62rem 0}
.filters label{display:grid;gap:.2rem;font-size:.84rem;color:var(--muted);max-width:100%}
.filters input{width:min(20rem,100%);color:var(--fg)}
.filters select{color:var(--fg)}
.finding{background:var(--soft);border:1px solid var(--line);border-radius:.68rem;padding:.75rem .85rem;margin:.5rem 0}
.finding-heading{display:flex;align-items:center;gap:.5rem;flex-wrap:wrap}
.finding h4{margin:0;font-size:1.06rem}
.pill{display:inline-block;font-size:.76rem;font-weight:730;padding:.1rem .49rem;border-radius:20px;background:var(--card);border:1px solid var(--line)}
.pill.high{color:var(--high);background:var(--high-bg);border-color:transparent}
.pill.medium{color:var(--medium);background:var(--medium-bg);border-color:transparent}
.finding p{margin:.45rem 0}
.finding details{margin-top:.55rem;border-top:1px solid var(--line);padding-top:.42rem}
.finding summary{color:var(--accent);cursor:pointer;font-weight:650}
.facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,13rem),1fr));gap:.55rem .8rem;margin:.6rem 0 0}
.facts dt{font-size:.77rem;color:var(--muted)} .facts dd{margin:0}
.finding-owner,.evidence-notes{color:var(--muted);font-size:.9rem}
.remediation{margin:.65rem 0;padding-left:1.55rem}
.remediation li{padding:.32rem 0}
.remediation li::marker{font-weight:700;color:var(--accent)}
.remediation p{margin:.14rem 0 .24rem}
.review-guide summary{color:var(--accent);cursor:pointer;font-weight:700}
.review-guide details[open] summary{margin-bottom:.55rem}
.review-guide p{color:var(--muted)}
.reference-list{list-style:none;padding:0;margin:.5rem 0 0}
.reference-list li{padding:.52rem 0;border-top:1px solid var(--line)}
.reference-list p{color:var(--muted);margin:.2rem 0 0}
.doc-links{display:flex;flex-wrap:wrap;gap:.45rem .8rem;margin:.5rem 0 0;font-size:.86rem}
.doc-links a,.reference-list a{font-weight:650}
.entra-review{padding:.72rem .85rem;margin:.55rem 0;background:var(--soft);border:1px solid var(--line);border-radius:.58rem}
.entra-review h4,.entra-review p{margin:0 0 .4rem}
.priority{padding:0;list-style:none;margin:.5rem 0}
.priority li{padding:.62rem 0;border-bottom:1px solid var(--line)}
.priority li:last-child{border:0}
.priority span{margin-right:.45rem}
.priority p{margin:.28rem 0 0;color:var(--muted)}
[hidden]{display:none!important}
@media(max-width:640px){.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.navigation .jump{display:none}label.menu{margin-left:0;width:100%}label.menu select{flex:1}.theme{font-size:.8rem}article{padding:.8rem}}
"""
SCRIPT = """
const pageSections = Array.from(document.querySelectorAll('main > section'));
const menu = document.getElementById('section-menu');
function showPanel(scroll) {
  const selected = pageSections.find(section => '#' + section.id === location.hash) || pageSections[0];
  for (const panel of pageSections) panel.hidden = panel !== selected;
  for (const link of document.querySelectorAll('nav .jump')) {
    if (link.hash === '#' + selected.id) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  }
  menu.value = selected.id;
  if (scroll) {
    selected.querySelector('h2').focus({preventScroll: true});
    window.scrollTo(0, 0);
  }
}
menu.addEventListener('change', () => { location.hash = menu.value; });
window.addEventListener('hashchange', () => showPanel(true));
showPanel(false);
for (const article of document.querySelectorAll('article[data-filter]')) {
  const search = article.querySelector('input');
  const severity = article.querySelector('select');
  const items = Array.from(article.querySelectorAll('[data-filter-item]'), node =>
    [node, node.textContent.toLocaleLowerCase()]);
  const empty = article.querySelector('.no-matches');
  function filter() {
    const terms = search.value.toLocaleLowerCase().trim().split(/\\s+/);
    let visible = 0;
    for (const [node, text] of items) {
      node.hidden = !terms.every(term => text.includes(term)) ||
        Boolean(severity && severity.value && node.dataset.severity !== severity.value);
      if (!node.hidden) visible++;
    }
    empty.hidden = visible !== 0 || !items.length;
  }
  search.addEventListener('input', filter);
  if (severity) severity.addEventListener('change', filter);
}
document.querySelector('.theme').addEventListener('click', () => {
  const root = document.documentElement;
  const dark = root.dataset.theme === 'dark' ||
    (!root.dataset.theme && matchMedia('(prefers-color-scheme:dark)').matches);
  root.dataset.theme = dark ? 'light' : 'dark';
});
"""

PRIMARY = {"Summary", "Findings", "Systems", "Security posture", "Resources", "Method and limits"}


def hash_source(script):
    return base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()


def esc(value):
    return html.escape(str(value), quote=True)


def cell(value):
    if value is None:
        return "—"
    if type(value) is bool:
        return "Yes" if value else "No"
    text = esc(value)
    if isinstance(value, (int, float)) or str(value).startswith(("res-", "rg-", "sub-", "fn-", "SYS-")) or (
        len(str(value)) == 36 and str(value).count("-") == 4
    ):
        return f"<code>{text}</code>"
    return text


def badge(severity):
    return f'<span class="pill {esc(severity.lower())}">{esc(severity)}</span>'


def learn_link(href):
    if href is None:
        return ""
    return (f'<a href="{esc(href)}" target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer">'
            f'{esc(LINK_TITLES[href])}</a>')


def learn_links(primary, follow_up):
    return f'<div class="doc-links">{learn_link(primary)}{learn_link(follow_up)}</div>'


def finding_cards(headers, rows):
    cards = []
    for row in rows:
        entry = dict(zip(headers, row))
        key, severity, title = (entry[label] for label in ("Key", "Severity", "Control"))
        facts = ("Field", "Value", "Source", "Resource", "System", "Affected (control and severity)",
                 "Status", "Technical compliance mapping")
        details = "".join(f"<div><dt>{esc(label)}</dt><dd>{cell(entry[label])}</dd></div>" for label in facts)
        notes = "".join(f"<p><strong>{esc(label)}:</strong> {esc(entry[label])}</p>"
                        for label in ("What this does not prove", "Related evidence", "Related evidence not observed", "Severity rationale")
                        if entry[label] is not None)
        steps = "".join(f"<li><strong>{esc(label[3:])}</strong><p>{esc(entry[label])}</p></li>"
                        for label in ("1. Verify before acting", "2. Plan the change", "3. Evidence to close"))
        questions = "".join(f"<p>{esc(entry[label])}</p>" for label in
                            ("Foundry question — posture", "Foundry question — compliance") if entry[label])
        links = learn_links(entry["Microsoft Learn — primary"], entry["Microsoft Learn — follow-up"])
        cards.append(f"""<div class="finding" data-filter-item data-severity="{esc(severity)}">
<div class="finding-heading">{badge(severity)} <code>{esc(key)}</code><h4>{esc(title)}</h4></div>
<p>{esc(entry["Why it matters"])}</p><p><strong>Next step:</strong> {esc(entry["Proposed action"])}</p>
<p class="finding-owner"><strong>Suggested owners:</strong> {esc(entry["Suggested owners"])}</p>
<div class="evidence-notes"><strong>Microsoft Learn</strong>{links}</div>
<details><summary>Evidence and remediation plan</summary><dl class="facts">{details}</dl>
<div class="evidence-notes">{notes}</div><ol class="remediation">{steps}</ol>
{('<div class="evidence-notes"><strong>Optional AI review prompts</strong>' + questions + '</div>') if questions else ''}
</details></div>""")
    return "".join(cards)


def entra_cards(rows):
    return "".join(f"""<div class="entra-review" data-filter-item>
<h4>{esc(topic)}</h4><p><strong>Observed:</strong> {esc(observed)}</p>
<p><strong>Not established:</strong> {esc(limit)}</p>
<p><strong>Recommended verification:</strong> {esc(action)}</p>{learn_links(primary, follow_up)}</div>"""
                   for topic, observed, limit, action, primary, follow_up in rows)


def render(tables, timestamp, summary):
    nav, options, panels = [], [], []
    priorities = "".join(f'<li>{badge(p["severity"])}<strong>{esc(p["title"])}</strong> '
                         f'· <code>{p["affected"]}</code> affected<p>{esc(p["action"])}</p></li>' for p in summary["priority"])
    overview = f"""<div class="metrics">
<div class="metric"><b>{summary["high"]}</b>High-priority findings</div>
<div class="metric"><b>{summary["findings"]}</b>Total findings</div>
<div class="metric"><b>{summary["resources"]}</b>Resources observed</div>
<div class="metric"><b>{summary["graph_observations"]}</b>Graph observations</div></div>
<p class="notice"><code>{summary["controls_with_evidence"]}</code> of <code>{summary["available_controls"]}</code> resource controls had configuration evidence. This is coverage, not a pass rate. Graph observations are policy settings, not resource findings.</p>
<article><h3>What to review first</h3>
{('<ul class="priority">' + priorities + '</ul><a href="#findings">See all findings</a>') if priorities else
  '<p>No configuration findings were produced from the evidence available. Check coverage before drawing conclusions.</p>'}
</article>"""
    for index, (area, rows) in enumerate(tables.items()):
        section_id = area.lower().replace(" & ", "-").split(" (")[0].replace(" ", "-")
        options.append(f'<option value="{section_id}">{esc(area)}</option>')
        if area in PRIMARY:
            nav.append(f'<a class="jump" href="#{section_id}">{esc(area)}</a>')
        content = [overview] if index == 0 else []
        for slug, title, headers, data, note in rows:
            search = f'filter-{index}-{slug}'
            description = f"<p>{esc(note)}</p>" if note else ""
            if not data:
                description += "<p>No evidence is available for this section.</p>"
            severity = ""
            if slug == "microsoft-guidance":
                items = "".join(f"<li>{learn_link(href)}<p>{esc(instruction)}</p></li>" for _, href, instruction in data)
                guidance = f'<article><h3>{esc(title)}</h3>{description}<ul class="reference-list">{items}</ul></article>'
                content.insert(2 if index == 0 else 1, guidance)
                continue
            if area == "Findings" and slug == "details":
                body = finding_cards(headers, data)
                severity = ('<label>Severity<select><option value="">All severities</option>'
                            '<option>High</option><option>Medium</option><option>Low</option></select></label>')
            elif slug == "entra-review":
                body = entra_cards(data)
            else:
                cols = "".join(f'<th scope="col">{esc(col)}</th>' for col in headers)
                entries = "".join("<tr data-filter-item>" + "".join(f"<td>{cell(v)}</td>" for v in row) + "</tr>" for row in data)
                body = f'<div class="wrap"><table><thead><tr>{cols}</tr></thead><tbody>{entries}</tbody></table></div>' if data else ""
            filters = (f'<div class="filters"><label for="{search}">Search {("findings" if severity else "table")}'
                       f'<input id="{search}" type="search" autocomplete="off"></label>{severity}</div>') if data else ""
            panel = f'{description}{filters}{body}<p class="no-matches" role="status" hidden>No results match these filters.</p>'
            if slug == "review-plan":
                card = f'<article class="review-guide" data-filter><details><summary>{esc(title)}</summary>{panel}</details></article>'
                content.insert(1 if index == 0 else 0, card)
            else:
                content.append(f'<article{" data-filter" if data else ""}><h3>{esc(title)}</h3>{panel}</article>')
        panels.append(f'<section id="{section_id}"{" hidden" if index else ""}><h2 tabindex="-1">{esc(area)}</h2>{"".join(content)}</section>')
    notice = ('<p class="notice"><strong>Synthetic sample:</strong> This report does not represent a real tenant.</p>' if summary["sample"] else "")
    csp = f"default-src 'none'; script-src 'sha256-{hash_source(SCRIPT)}'; style-src 'sha256-{hash_source(STYLE)}'; base-uri 'none'; form-action 'none'"
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{csp}">
<title>Azure Tenant Inventory</title><style>{STYLE}</style></head>
<body><header><div class="shell"><button type="button" class="theme">Toggle theme</button>
<p class="eyebrow">Confidential - internal</p><h1>Azure Tenant Inventory</h1>
<p>Assessment engine: <strong>{esc(summary["analysis_mode"])}</strong></p>
<p>Configuration evidence only. Not a breach investigation or a compliance verdict.</p>
<p>Audience: assessment team, authorized owners, DPO, and legal team · <code>{timestamp.isoformat(timespec='seconds')}</code></p>
</div></header><nav aria-label="Report sections"><div class="shell navigation">{"".join(nav)}
<label class="menu"><span class="section-nav-label">Report section</span><select id="section-menu">{"".join(options)}</select></label>
</div></nav><main>{notice}{"".join(panels)}</main><script>{SCRIPT}</script></body></html>"""
