/* WatchTower SIEM — Utilities */
'use strict';

const SEV_COL  = {critical:'#ff4d6d',high:'#ff8a65',medium:'#ffd600',low:'#00c8ff',info:'#5a7098'};
const SEV_BG   = {critical:'rgba(255,29,68,.12)',high:'rgba(255,112,67,.12)',medium:'rgba(255,214,0,.1)',low:'rgba(0,200,255,.08)',info:'rgba(90,112,152,.1)'};
const SEV_ICON = {critical:'fa-skull-crossbones',high:'fa-circle-exclamation',medium:'fa-triangle-exclamation',low:'fa-circle-info',info:'fa-circle'};

function sevBadge(sev) {
  return `<span class="sev sev-${sev}"><i class="fa-solid ${SEV_ICON[sev]||'fa-circle'} me-1" style="font-size:.65em"></i>${(sev||'').toUpperCase()}</span>`;
}
function statusBadge(status) {
  const icons = {open:'fa-circle-dot',investigating:'fa-magnifying-glass',contained:'fa-shield',resolved:'fa-circle-check',false_positive:'fa-xmark-circle',closed:'fa-lock'};
  return `<span class="status-badge status-${status}"><i class="fa-solid ${icons[status]||'fa-circle'} me-1" style="font-size:.7em"></i>${(status||'').replace(/_/g,' ')}</span>`;
}
function mitreTags(arr) {
  if (!arr || !arr.length) return '<span style="color:var(--wt-muted);font-size:.75rem">—</span>';
  return arr.slice(0,3).map(t=>`<span class="mitre-tag">${escHtml(t)}</span>`).join('')
    + (arr.length>3?`<span class="mitre-tag">+${arr.length-3}</span>`:'');
}

// ── Date helpers ──────────────────────────────────────────────────────────────
function relTime(iso) {
  if (!iso) return '—';
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 0) return 'just now';
  if (s < 60)  return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s/60)}m ago`;
  if (s < 86400) return `${Math.floor(s/3600)}h ago`;
  if (s < 604800) return `${Math.floor(s/86400)}d ago`;
  return fmtDateShort(iso);
}
function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString('en-GB',{day:'2-digit',month:'short',year:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit'});
}
function fmtDateShort(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString('en-GB',{month:'short',day:'2-digit',hour:'2-digit',minute:'2-digit'});
}

// ── Toast ─────────────────────────────────────────────────────────────────────
function toast(message, type='info', duration=4000) {
  const id = 'toast-'+Date.now();
  const icons = {success:'fa-circle-check',error:'fa-circle-xmark',info:'fa-circle-info',warning:'fa-triangle-exclamation'};
  const col   = {success:'var(--wt-green)',error:'var(--wt-red)',info:'var(--wt-accent)',warning:'var(--wt-yellow)'};
  document.getElementById('toastContainer').insertAdjacentHTML('beforeend',`
    <div id="${id}" class="toast wt-toast ${type} show" role="alert">
      <div class="toast-body d-flex align-items-center gap-2 px-3 py-2">
        <i class="fa-solid ${icons[type]||icons.info}" style="color:${col[type]||col.info}"></i>
        <span style="font-size:.83rem;flex:1">${escHtml(message)}</span>
        <button type="button" class="btn-close btn-close-white btn-close-sm ms-auto" onclick="this.closest('.toast').remove()"></button>
      </div>
    </div>`);
  if (duration>0) setTimeout(()=>document.getElementById(id)?.remove(), duration);
}

// ── Pagination ─────────────────────────────────────────────────────────────────
function buildPagination(container, cur, total, cb) {
  if (!container || total<=1) { if(container) container.innerHTML=''; return; }
  let pages=[];
  if (total<=7) pages=Array.from({length:total},(_,i)=>i+1);
  else {
    pages=[1];
    const s=Math.max(2,cur-2), e=Math.min(total-1,cur+2);
    if (s>2) pages.push('…');
    for(let i=s;i<=e;i++) pages.push(i);
    if (e<total-1) pages.push('…');
    pages.push(total);
  }
  let h=`<button class="pg-btn"${cur===1?' disabled':''} data-pg="${cur-1}">‹</button>`;
  pages.forEach(p=>{
    if(p==='…') h+=`<span class="pg-btn" style="cursor:default">…</span>`;
    else h+=`<button class="pg-btn${p===cur?' active':''}" data-pg="${p}">${p}</button>`;
  });
  h+=`<button class="pg-btn"${cur===total?' disabled':''} data-pg="${cur+1}">›</button>`;
  container.innerHTML=h;
  container.querySelectorAll('[data-pg]:not([disabled])').forEach(b=>
    b.addEventListener('click',()=>cb(parseInt(b.dataset.pg))));
}

// ── Markdown renderer ─────────────────────────────────────────────────────────
function renderMarkdown(md) {
  if (!md) return '';
  return md
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/^######\s(.+)$/gm,'<h6>$1</h6>')
    .replace(/^#####\s(.+)$/gm,'<h5>$1</h5>')
    .replace(/^####\s(.+)$/gm,'<h4>$1</h4>')
    .replace(/^###\s(.+)$/gm,'<h3>$1</h3>')
    .replace(/^##\s(.+)$/gm,'<h2>$1</h2>')
    .replace(/^#\s(.+)$/gm,'<h2>$1</h2>')
    .replace(/\*\*(.+?)\*\*/g,'<strong>$1</strong>')
    .replace(/\*(.+?)\*/g,'<em>$1</em>')
    .replace(/`([^`\n]+)`/g,'<code>$1</code>')
    .replace(/```[\s\S]*?```/g,m=>`<pre>${m.replace(/```\w*\n?/g,'')}</pre>`)
    .replace(/^[-*]\s(.+)$/gm,'<li>$1</li>')
    .replace(/^(\d+)\.\s(.+)$/gm,'<li>$2</li>')
    .replace(/(<li>[\s\S]+?<\/li>)/g,'<ul>$1</ul>')
    .replace(/\n{2,}/g,'</p><p>')
    .replace(/^(?!<[hup])(.+)$/gm,'<p>$1</p>');
}

// ── HTML escape ───────────────────────────────────────────────────────────────
function escHtml(str) {
  const d=document.createElement('div');
  d.textContent=str??'';
  return d.innerHTML;
}

// ── Debounce ──────────────────────────────────────────────────────────────────
function debounce(fn, ms) {
  let t;
  return (...args)=>{ clearTimeout(t); t=setTimeout(()=>fn(...args),ms); };
}

// ── Modal helpers ─────────────────────────────────────────────────────────────
function showModal(id) { new bootstrap.Modal(document.getElementById(id)).show(); }
function hideModal(id) { bootstrap.Modal.getInstance(document.getElementById(id))?.hide(); }

// ── Copy to clipboard ─────────────────────────────────────────────────────────
function copyText(text, label='Copied!') {
  navigator.clipboard.writeText(text).then(()=>toast(label,'success')).catch(()=>toast('Copy failed','error'));
}
