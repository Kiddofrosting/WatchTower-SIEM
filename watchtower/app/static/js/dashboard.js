/* WatchTower SIEM — Dashboard SPA */
'use strict';

// ── Auth guard ─────────────────────────────────────────────────────────────────
const currentUser = API.getUser();
if (!currentUser) window.location.href = '/login';

// ── State ──────────────────────────────────────────────────────────────────────
const State = {
  currentPage: 'dashboard', charts: {},
  eventsPage: 1, incidentsPage: 1, auditPage: 1, iocPage: 1, usersPage: 1,
  refreshInterval: null, notifInterval: null,
  currentIncidentId: null, forceReload: false,
};

// ── Init ───────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initUser(); initSidebar(); initNavigation(); initTopbar();
  loadPage('dashboard'); startAutoRefresh();
  loadNotifications();
  State.notifInterval = setInterval(loadNotifications, 30000);
});

// ── User ───────────────────────────────────────────────────────────────────────
function initUser() {
  const u = currentUser;
  document.getElementById('userNameSidebar').textContent = u.username || u.full_name || 'User';
  document.getElementById('userRoleSidebar').textContent = (u.role||'').replace(/_/g,' ');
  document.getElementById('userAvatarSidebar').textContent = (u.full_name||u.username||'U').charAt(0).toUpperCase();
  if (!['super_admin','admin'].includes(u.role)) {
    document.querySelectorAll('.nav-admin-only').forEach(el=>el.closest('.nav-item')?.remove());
  }
}

// ── Sidebar ────────────────────────────────────────────────────────────────────
function initSidebar() {
  const sb=document.getElementById('sidebar'), wr=document.getElementById('mainWrapper');
  const overlay=document.getElementById('sidebarOverlay');
  const isMobile=()=>window.innerWidth<=768;

  // Desktop: restore collapsed state from localStorage
  if (!isMobile() && localStorage.getItem('wt_sidebar_collapsed')==='true') {
    sb.classList.add('collapsed'); wr.classList.add('sidebar-collapsed');
  }

  // Desktop toggle button (inside sidebar header)
  document.getElementById('sidebarToggle')?.addEventListener('click',()=>{
    if (isMobile()) return; // handled by mobile button
    const c=sb.classList.toggle('collapsed');
    wr.classList.toggle('sidebar-collapsed',c);
    localStorage.setItem('wt_sidebar_collapsed',String(c));
  });

  // Mobile menu button (in topbar)
  document.getElementById('mobileMenuBtn')?.addEventListener('click',()=>{
    const open=sb.classList.toggle('mobile-open');
    overlay.classList.toggle('visible', open);
  });

  // Close mobile sidebar when overlay clicked
  overlay?.addEventListener('click',closeMobileSidebar);

  // Close mobile sidebar when nav item clicked
  document.querySelectorAll('.nav-item[data-page]').forEach(item=>{
    item.addEventListener('click',()=>{ if(isMobile()) closeMobileSidebar(); });
  });

  function closeMobileSidebar() {
    sb.classList.remove('mobile-open');
    overlay.classList.remove('visible');
  }

  // Reapply on resize
  window.addEventListener('resize', ()=>{
    if (!isMobile()) {
      sb.classList.remove('mobile-open');
      overlay.classList.remove('visible');
    }
  });

  document.getElementById('logoutBtn')?.addEventListener('click',async()=>{
    try { await API.post('/auth/logout'); } catch {}
    API.clearTokens(); window.location.href='/login';
  });
}

// ── Navigation ─────────────────────────────────────────────────────────────────
const PAGE_TITLES = {
  dashboard:['Dashboard','Overview'], events:['Event Explorer','Events'],
  incidents:['Incidents','Security Incidents'], rules:['Detection Rules','Rules'],
  agents:['Agents','Monitored Endpoints'], users:['Users','User Management'],
  compliance:['Compliance','Reports'], 'audit-log':['Audit Log','System Audit'],
  settings:['Settings','Configuration'], 'threat-intel':['Threat Intelligence','IOC Feed'],
};
function initNavigation() {
  document.querySelectorAll('.nav-item[data-page]').forEach(item=>{
    item.addEventListener('click',e=>{ e.preventDefault(); loadPage(item.dataset.page); });
  });
  window.addEventListener('popstate',e=>{ if(e.state?.page) loadPage(e.state.page,false); });
}
function setActiveNav(page) {
  document.querySelectorAll('.nav-item').forEach(i=>i.classList.remove('active'));
  document.querySelector(`.nav-item[data-page="${page}"]`)?.classList.add('active');
}
async function loadPage(page, pushState=true) {
  if (page===State.currentPage && page!=='dashboard' && !State.forceReload) return;
  State.currentPage=page; State.forceReload=false;
  setActiveNav(page);
  const [title,bc]=PAGE_TITLES[page]||[page,page];
  document.getElementById('pageTitle').textContent=title;
  document.getElementById('breadcrumb').textContent=bc;
  if (pushState) history.pushState({page},'','/dashboard/'+page);
  const content=document.getElementById('pageContent');
  const tpl=document.getElementById('tpl-'+page);
  content.innerHTML=tpl ? tpl.innerHTML : '<div class="loading-spinner"><div class="spinner-border text-info"></div><p>Loading…</p></div>';
  switch(page) {
    case 'dashboard':    loadDashboard(); break;
    case 'events':       initEventsPage(); break;
    case 'incidents':    initIncidentsPage(); break;
    case 'rules':        loadRules(); break;
    case 'agents':       loadAgents(); break;
    case 'users':        loadUsers(); break;
    case 'compliance':   initCompliancePage(); break;
    case 'audit-log':    loadAuditLog(); break;
    case 'settings':     loadSettings(); break;
    case 'threat-intel': loadThreatIntel(); break;
  }
}

// ── Topbar ─────────────────────────────────────────────────────────────────────
function initTopbar() {
  document.getElementById('refreshBtn').addEventListener('click',()=>{
    State.forceReload=true; loadPage(State.currentPage,false);
  });
  const nb=document.getElementById('notifBtn'), nd=document.getElementById('notifDropdown');
  nb.addEventListener('click',e=>{ e.stopPropagation(); nd.classList.toggle('open'); });
  document.addEventListener('click',()=>nd.classList.remove('open'));
  nd.addEventListener('click',e=>e.stopPropagation());
  document.getElementById('markAllReadBtn').addEventListener('click',async()=>{
    await API.post('/alerts/notifications/read-all'); loadNotifications(); toast('All marked read','success');
  });
  const gs=document.getElementById('globalSearch');
  gs.addEventListener('keydown',e=>{
    if (e.key==='Enter'&&gs.value.trim()) {
      loadPage('events',true);
      setTimeout(()=>{ const s=document.getElementById('evtSearch'); if(s){s.value=gs.value.trim();fetchEvents();} },300);
    }
  });
}
function startAutoRefresh() {
  State.refreshInterval=setInterval(()=>{
    if(State.currentPage==='dashboard') loadDashboardMetrics();
    updateIncidentBadge();
  },30000);
}

// ── Notifications ──────────────────────────────────────────────────────────────
async function loadNotifications() {
  try {
    const d=await API.get('/alerts/notifications',{unread_only:false});
    if(!d) return;
    const cnt=document.getElementById('notifCount');
    if (d.unread_count>0) { cnt.textContent=d.unread_count>99?'99+':d.unread_count; cnt.style.display='flex'; }
    else cnt.style.display='none';
    const list=document.getElementById('notifList');
    if (!d.data.length) { list.innerHTML='<div class="notif-empty">No notifications</div>'; return; }
    list.innerHTML=d.data.slice(0,20).map(n=>`
      <div class="notif-item${!n.read?' unread':''}" onclick="handleNotifClick('${n._id}','${n.incident_id||''}')">
        <div class="notif-item-title">${escHtml(n.title)}</div>
        <div class="notif-item-msg">${escHtml(n.message)}</div>
        <div class="notif-item-time">${relTime(n.created_at)}</div>
      </div>`).join('');
  } catch {}
}
async function handleNotifClick(nid,incId) {
  await API.post(`/alerts/notifications/${nid}/read`);
  if(incId) { document.getElementById('notifDropdown').classList.remove('open'); showIncidentDetail(incId); }
  loadNotifications();
}
async function updateIncidentBadge() {
  try {
    const d=await API.get('/incidents/stats/summary');
    const badge=document.getElementById('incidentBadge');
    if(d&&d.open>0){badge.textContent=d.open;badge.style.display='';}
    else badge.style.display='none';
  } catch {}
}

// ═══════════════════════════════════════════════════════════════════════════════
// DASHBOARD
// ═══════════════════════════════════════════════════════════════════════════════
async function loadDashboard() {
  const tpl=document.getElementById('tpl-dashboard');
  document.getElementById('pageContent').innerHTML=tpl.innerHTML;
  await Promise.all([loadDashboardMetrics(),loadDashboardCharts(),loadRecentIncidents()]);
  document.querySelectorAll('[data-page]').forEach(el=>el.addEventListener('click',()=>loadPage(el.dataset.page)));
  document.querySelectorAll('.btn-chip[data-days]').forEach(btn=>
    btn.addEventListener('click',()=>{
      document.querySelectorAll('.btn-chip[data-days]').forEach(b=>b.classList.remove('active'));
      btn.classList.add('active');
      loadDashboardCharts(parseInt(btn.dataset.days));
    })
  );
}
async function loadDashboardMetrics() {
  try {
    const [sum,inc]=await Promise.all([API.get('/dashboard/summary'),API.get('/incidents/stats/summary')]);
    if (!sum) return;
    const m=sum.metrics;
    document.getElementById('m-critical-incidents').textContent=inc?.critical_open??m.critical_incidents??0;
    document.getElementById('m-open-incidents').textContent=m.open_incidents;
    document.getElementById('m-events-24h').textContent=m.total_events_24h.toLocaleString();
    document.getElementById('m-online-agents').textContent=m.online_agents;
    const tot=document.getElementById('m-total-agents');
    if(tot) tot.textContent=`of ${m.active_agents} active`;
  } catch(e){console.warn('Metrics',e)}
}
async function loadDashboardCharts(days=7) {
  try {
    const [evts,inc]=await Promise.all([API.get('/events/stats/summary'),API.get('/incidents/stats/summary')]);
    // Severity donut
    const sevCtx=document.getElementById('severityDonutChart')?.getContext('2d');
    if (sevCtx&&evts) {
      const sevs=evts.by_severity||{}, labels=['critical','high','medium','low','info'];
      const colors=['#ff1744','#ff7043','#ffd600','#00c8ff','#5a7098'];
      if(State.charts.sev) State.charts.sev.destroy();
      State.charts.sev=new Chart(sevCtx,{type:'doughnut',
        data:{labels,datasets:[{data:labels.map(l=>sevs[l]||0),backgroundColor:colors,borderWidth:2,borderColor:'#0c1120',hoverOffset:4}]},
        options:{responsive:true,maintainAspectRatio:true,cutout:'65%',plugins:{legend:{position:'right',labels:{color:'#8892aa',font:{size:11},padding:12,usePointStyle:true}}}}
      });
    }
    // Incident trend
    const trendCtx=document.getElementById('incidentTrendChart')?.getContext('2d');
    if(trendCtx&&inc?.incident_trend) {
      const trend=inc.incident_trend;
      if(State.charts.trend) State.charts.trend.destroy();
      State.charts.trend=new Chart(trendCtx,{type:'bar',
        data:{labels:trend.map(t=>t.date),datasets:[{label:'Incidents',data:trend.map(t=>t.count),backgroundColor:'rgba(108,92,231,.55)',borderColor:'rgba(108,92,231,.9)',borderRadius:4,borderWidth:1}]},
        options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},
          scales:{x:{grid:{color:'rgba(255,255,255,.04)'},ticks:{color:'#5a7098',font:{size:10}}},
                  y:{grid:{color:'rgba(255,255,255,.04)'},ticks:{color:'#5a7098',stepSize:1,font:{size:10}}}}}
      });
    }
    // Top hosts bar chart
    if(evts?.top_hosts) {
      const el=document.getElementById('topHostsList'); if(!el) return;
      const max=evts.top_hosts[0]?.count||1;
      el.innerHTML=evts.top_hosts.map(h=>`
        <div class="host-bar-item">
          <div class="host-name" title="${escHtml(h.hostname)}">${escHtml(h.hostname)}</div>
          <div class="host-bar-wrap"><div class="host-bar-fill" style="width:${Math.round(h.count/max*100)}%"></div></div>
          <div class="host-count">${h.count.toLocaleString()}</div>
        </div>`).join('');
    }
    // MITRE horizontal bar
    if(inc?.mitre_breakdown) {
      const mCtx=document.getElementById('mitreChart')?.getContext('2d');
      if(mCtx) {
        const md=inc.mitre_breakdown.slice(0,8);
        if(State.charts.mitre) State.charts.mitre.destroy();
        State.charts.mitre=new Chart(mCtx,{type:'bar',
          data:{labels:md.map(m=>m.technique),datasets:[{data:md.map(m=>m.count),backgroundColor:'rgba(0,200,255,.35)',borderColor:'rgba(0,200,255,.75)',borderRadius:4,borderWidth:1}]},
          options:{indexAxis:'y',responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},
            scales:{x:{grid:{color:'rgba(255,255,255,.04)'},ticks:{color:'#5a7098',font:{size:10}}},
                    y:{grid:{display:false},ticks:{color:'#8892aa',font:{size:10}}}}}
        });
      }
    }
  } catch(e){console.warn('Charts',e)}
}
async function loadRecentIncidents() {
  try {
    const d=await API.get('/incidents/',{status:'open',per_page:8});
    const tb=document.getElementById('recentIncidentsTbody'); if(!tb||!d) return;
    if(!d.data.length) { tb.innerHTML='<tr><td colspan="7" class="text-center text-muted py-4"><i class="fa-solid fa-shield-check me-2 text-success"></i>No active incidents</td></tr>'; return; }
    tb.innerHTML=d.data.map(inc=>`
      <tr style="cursor:pointer" onclick="showIncidentDetail('${inc._id}')">
        <td>${sevBadge(inc.severity)}</td>
        <td style="max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(inc.title)}">${escHtml(inc.title)}</td>
        <td><code style="font-size:.75rem">${escHtml(inc.hostname)}</code></td>
        <td>${mitreTags(inc.mitre_technique)}</td>
        <td>${relTime(inc.created_at)}</td>
        <td>${statusBadge(inc.status)}</td>
        <td><button class="btn-wt btn-sm" onclick="event.stopPropagation();showIncidentDetail('${inc._id}')">View</button></td>
      </tr>`).join('');
    updateIncidentBadge();
  } catch(e){console.warn('Recent incidents',e)}
}

// ═══════════════════════════════════════════════════════════════════════════════
// EVENTS PAGE
// ═══════════════════════════════════════════════════════════════════════════════
function initEventsPage() {
  State.eventsPage=1; fetchEvents();
  document.getElementById('evtSearchBtn')?.addEventListener('click',()=>{State.eventsPage=1;fetchEvents();});
  document.getElementById('evtExportBtn')?.addEventListener('click',exportEventsCSV);
  ['evtSeverityFilter','evtCategoryFilter'].forEach(id=>
    document.getElementById(id)?.addEventListener('change',()=>{State.eventsPage=1;fetchEvents();}));
  document.getElementById('evtSearch')?.addEventListener('keydown',e=>{if(e.key==='Enter'){State.eventsPage=1;fetchEvents();}});
}
async function fetchEvents() {
  const tb=document.getElementById('eventsTbody'); if(!tb) return;
  tb.innerHTML='<tr><td colspan="9" class="text-center py-4"><div class="spinner-border spinner-border-sm text-info me-2"></div>Loading…</td></tr>';
  try {
    const d=await API.get('/events/',{
      page:State.eventsPage, per_page:50,
      severity:document.getElementById('evtSeverityFilter')?.value||'',
      category:document.getElementById('evtCategoryFilter')?.value||'',
      hostname:document.getElementById('evtHostFilter')?.value||'',
      search:document.getElementById('evtSearch')?.value||'',
      start_time:document.getElementById('evtStartTime')?.value||'',
      end_time:document.getElementById('evtEndTime')?.value||'',
    });
    if(!d) return;
    document.getElementById('evtTotal').textContent=d.pagination.total.toLocaleString();
    document.getElementById('evtPaginationInfo').textContent=`Page ${d.pagination.page} of ${d.pagination.pages}`;
    if(!d.data.length) { tb.innerHTML='<tr><td colspan="9" class="text-center text-muted py-5">No events found</td></tr>'; }
    else {
      tb.innerHTML=d.data.map(ev=>`
        <tr style="cursor:pointer" onclick="showEventDetail('${ev._id}')">
          <td style="font-size:.75rem;white-space:nowrap">${fmtDateShort(ev.timestamp)}</td>
          <td><code style="font-size:.72rem">${escHtml(ev.hostname)}</code></td>
          <td><span style="font-size:.78rem;font-weight:600;color:var(--wt-accent)">${ev.event_id}</span></td>
          <td><span style="font-size:.75rem;color:var(--wt-muted)">${(ev.category||'').replace(/_/g,' ')}</span></td>
          <td>${sevBadge(ev.severity)}</td>
          <td style="font-size:.78rem">${escHtml(ev.subject_username||ev.target_username||'—')}</td>
          <td style="font-size:.75rem;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(ev.process_name||ev.source_ip||'')}">${escHtml(ev.process_name||ev.source_ip||'—')}</td>
          <td>${mitreTags(ev.mitre_technique)}</td>
          <td><button class="btn-wt btn-sm" onclick="event.stopPropagation();showEventDetail('${ev._id}')"><i class="fa-solid fa-magnifying-glass"></i></button></td>
        </tr>`).join('');
    }
    buildPagination(document.getElementById('evtPaginationBar'),d.pagination.page,d.pagination.pages,p=>{State.eventsPage=p;fetchEvents();});
  } catch(e){toast('Failed to load events: '+e.message,'error');}
}
async function showEventDetail(id) {
  try {
    const ev=await API.get(`/events/${id}`); if(!ev) return;
    document.getElementById('eventDetailBody').innerHTML=`
      <div class="d-flex align-items-center gap-2 mb-3">
        ${sevBadge(ev.severity)}
        <span style="font-size:.9rem;font-weight:600">${escHtml(ev.message||'Event '+ev.event_id)}</span>
      </div>
      <div class="ev-detail-grid">
        ${evRow('Event ID',`<strong style="color:var(--wt-accent)">${ev.event_id}</strong>`)}
        ${evRow('Timestamp',fmtDate(ev.timestamp))}
        ${evRow('Host',`<code>${escHtml(ev.hostname)}</code>`)}
        ${evRow('Channel',escHtml(ev.channel||'—'))}
        ${evRow('Category',escHtml((ev.category||'').replace(/_/g,' ')))}
        ${evRow('Provider',escHtml(ev.provider||'—'))}
        ${evRow('Subject User',escHtml(ev.subject_username||'—'))}
        ${evRow('Target User',escHtml(ev.target_username||'—'))}
        ${evRow('Logon Type',escHtml(ev.logon_type||'—'))}
        ${evRow('Process',escHtml(ev.process_name||'—'))}
        ${evRow('Source IP',escHtml(ev.source_ip||'—'))}
        ${evRow('Dest IP',escHtml(ev.destination_ip||'—')+(ev.destination_port?':'+ev.destination_port:''))}
        ${ev.command_line?evRow('Command Line',`<code style="font-size:.72rem;word-break:break-all">${escHtml(ev.command_line)}</code>`,true):''}
        ${ev.file_path?evRow('File Path',escHtml(ev.file_path),true):''}
        ${ev.registry_key?evRow('Registry Key',escHtml(ev.registry_key),true):''}
        ${ev.mitre_technique?.length?evRow('MITRE',mitreTags(ev.mitre_technique),true):''}
      </div>
      ${ev.raw_event?`<div class="mt-3"><div class="ev-detail-key mb-1">Raw Event</div><div class="raw-event-block">${escHtml(JSON.stringify(ev.raw_event,null,2))}</div></div>`:''}`;
    showModal('eventDetailModal');
  } catch(e){toast('Failed to load event: '+e.message,'error');}
}
function evRow(label,val,full=false){return `<div class="ev-detail-row${full?' full':''}"><div class="ev-detail-key">${label}</div><div class="ev-detail-val">${val}</div></div>`;}
function exportEventsCSV() {
  const p=new URLSearchParams({
    severity:document.getElementById('evtSeverityFilter')?.value||'',
    category:document.getElementById('evtCategoryFilter')?.value||'',
    hostname:document.getElementById('evtHostFilter')?.value||'',
    search:document.getElementById('evtSearch')?.value||'',
  });
  window.open('/api/v1/events/export/csv?'+p,'_blank');
}

// ═══════════════════════════════════════════════════════════════════════════════
// INCIDENTS PAGE
// ═══════════════════════════════════════════════════════════════════════════════
function initIncidentsPage() {
  State.incidentsPage=1; fetchIncidents();
  document.getElementById('incSearchBtn')?.addEventListener('click',()=>{State.incidentsPage=1;fetchIncidents();});
  ['incStatusFilter','incSeverityFilter'].forEach(id=>
    document.getElementById(id)?.addEventListener('change',()=>{State.incidentsPage=1;fetchIncidents();}));
  document.getElementById('incHostFilter')?.addEventListener('keydown',e=>{if(e.key==='Enter'){State.incidentsPage=1;fetchIncidents();}});
}
async function fetchIncidents() {
  const tb=document.getElementById('incidentsTbody'); if(!tb) return;
  tb.innerHTML='<tr><td colspan="8" class="text-center py-4"><div class="spinner-border spinner-border-sm text-info me-2"></div>Loading…</td></tr>';
  try {
    const d=await API.get('/incidents/',{
      page:State.incidentsPage, per_page:25,
      status:document.getElementById('incStatusFilter')?.value||'',
      severity:document.getElementById('incSeverityFilter')?.value||'',
      hostname:document.getElementById('incHostFilter')?.value||'',
    });
    if(!d) return;
    document.getElementById('incTotal').textContent=d.pagination.total.toLocaleString();
    if(!d.data.length) {
      tb.innerHTML='<tr><td colspan="8" class="text-center text-muted py-5"><i class="fa-solid fa-shield-check me-2 text-success"></i>No incidents found</td></tr>';
    } else {
      tb.innerHTML=d.data.map(inc=>`
        <tr style="cursor:pointer" onclick="showIncidentDetail('${inc._id}')">
          <td>${sevBadge(inc.severity)}</td>
          <td style="max-width:280px"><div style="font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${escHtml(inc.title)}</div><div style="font-size:.72rem;color:var(--wt-muted)">${escHtml(inc.rule_name)}</div></td>
          <td><code style="font-size:.75rem">${escHtml(inc.hostname)}</code></td>
          <td>${mitreTags(inc.mitre_technique)}</td>
          <td>${statusBadge(inc.status)}</td>
          <td style="font-size:.78rem;color:var(--wt-muted)">${inc.assigned_to?escHtml(inc.assigned_to):'<span style="color:var(--wt-border2)">Unassigned</span>'}</td>
          <td style="font-size:.75rem;white-space:nowrap">${relTime(inc.created_at)}</td>
          <td><button class="btn-wt btn-sm">View</button></td>
        </tr>`).join('');
    }
    buildPagination(document.getElementById('incPaginationBar'),d.pagination.page,d.pagination.pages,p=>{State.incidentsPage=p;fetchIncidents();});
  } catch(e){toast('Failed to load incidents: '+e.message,'error');}
}
async function showIncidentDetail(id) {
  State.currentIncidentId=id;
  const tpl=document.getElementById('tpl-incident-detail');
  document.getElementById('pageContent').innerHTML=tpl.innerHTML;
  document.getElementById('pageTitle').textContent='Incident Detail';
  document.getElementById('breadcrumb').textContent='Incidents → Detail';
  setActiveNav('incidents');
  document.getElementById('incBackBtn').addEventListener('click',()=>loadPage('incidents'));
  try {
    const inc=await API.get(`/incidents/${id}`); if(!inc) return;
    renderIncidentDetail(inc);
  } catch(e){toast('Failed to load incident: '+e.message,'error');}
}
function renderIncidentDetail(inc) {
  const sc={critical:'#ff1744',high:'#ff7043',medium:'#ffd600',low:'#00c8ff',info:'#5a7098'};
  const si={critical:'fa-skull-crossbones',high:'fa-circle-exclamation',medium:'fa-triangle-exclamation',low:'fa-circle-info',info:'fa-circle'};
  document.getElementById('incDetailSev').innerHTML=`<i class="fa-solid ${si[inc.severity]}" style="color:${sc[inc.severity]};font-size:1.2rem"></i>`;
  document.getElementById('incDetailTitle').textContent=inc.title;
  document.getElementById('incDetailDesc').textContent=inc.description;
  document.getElementById('incDetailMeta').innerHTML=[
    `<span><i class="fa-solid fa-server me-1"></i>${escHtml(inc.hostname)}</span>`,
    `<span><i class="fa-solid fa-tag me-1"></i>${escHtml((inc.category||'').replace(/_/g,' '))}</span>`,
    `<span><i class="fa-solid fa-clock me-1"></i>${fmtDate(inc.created_at)}</span>`,
    `<span><i class="fa-solid fa-hashtag me-1"></i>${inc.event_count} events</span>`,
  ].join('');
  document.getElementById('incDetailMitre').innerHTML=
    [...(inc.mitre_technique||[]).map(t=>`<span class="mitre-tag">${escHtml(t)}</span>`),
     ...(inc.mitre_tactic||[]).map(t=>`<span class="mitre-tag" style="background:rgba(0,200,255,.08);color:var(--wt-accent)">${escHtml(t)}</span>`)
    ].join('');
  document.getElementById('incDetailKV').innerHTML=[
    ['Status',statusBadge(inc.status)],['Severity',sevBadge(inc.severity)],
    ['Rule',escHtml(inc.rule_name)],['Host',`<code style="font-size:.75rem">${escHtml(inc.hostname)}</code>`],
    ['Assigned',inc.assigned_to?escHtml(inc.assigned_to):'<em style="color:var(--wt-muted)">Unassigned</em>'],
    ['Created',fmtDate(inc.created_at)],['Updated',relTime(inc.updated_at)],['Events',inc.event_count],
  ].map(([k,v])=>`<div class="kv-row"><span class="kv-key">${k}</span><span class="kv-val">${v}</span></div>`).join('');
  const statuses=['open','investigating','contained','resolved','false_positive','closed'];
  document.getElementById('incStatusUpdate').innerHTML=statuses.map(s=>`<option value="${s}"${s===inc.status?' selected':''}>${s.replace(/_/g,' ')}</option>`).join('');
  document.getElementById('incAssigneeUpdate').value=inc.assigned_to||'';
  document.getElementById('incUpdateBtn').addEventListener('click',()=>updateIncidentStatus(inc._id));
  if (inc.ai_remediation) document.getElementById('aiContent').innerHTML=renderMarkdown(inc.ai_remediation);
  document.getElementById('genAiBtn').addEventListener('click',async()=>{
    const btn=document.getElementById('genAiBtn');
    btn.disabled=true; btn.innerHTML='<span class="spinner-border spinner-border-sm me-1"></span>Queuing…';
    try { await API.post(`/incidents/${inc._id}/ai-remediation`); toast('AI remediation queued — refresh in a few seconds','info'); }
    catch(e){toast('Failed: '+e.message,'error');}
    btn.disabled=false; btn.innerHTML='<i class="fa-solid fa-robot me-1"></i>Generate';
  });
  renderNotes(inc.analyst_notes||[]);
  document.getElementById('addNoteBtn').addEventListener('click',()=>addNote(inc._id));
  renderTimeline(inc.timeline||[]);
  const evList=document.getElementById('triggeringEventsList');
  if(inc.triggering_event_ids?.length) {
    evList.innerHTML=inc.triggering_event_ids.slice(0,20).map(eid=>
      `<div class="ev-item" onclick="showEventDetail('${eid}')">
        <i class="fa-solid fa-file-lines me-1" style="color:var(--wt-muted)"></i>
        <code style="font-size:.7rem">${eid.slice(-12)}</code>
      </div>`).join('');
  } else { evList.innerHTML='<div style="font-size:.8rem;color:var(--wt-muted)">No events linked</div>'; }
  // Detail actions
  document.getElementById('incDetailActions').innerHTML=`
    <button class="btn-wt" onclick="exportIncidentPDF('${inc._id}')"><i class="fa-solid fa-file-pdf me-1" style="color:var(--wt-red)"></i>Export PDF</button>
    <button class="btn-wt btn-danger" onclick="suppressIncident('${inc._id}')"><i class="fa-solid fa-bell-slash me-1"></i>Suppress</button>`;
}
function renderNotes(notes) {
  const el=document.getElementById('analystNotes'); if(!el) return;
  el.innerHTML=notes.length?notes.map(n=>`
    <div class="note-item">
      <div class="note-header"><span class="note-author"><i class="fa-solid fa-user me-1"></i>${escHtml(n.author)}</span><span class="note-time">${fmtDate(n.created_at)}</span></div>
      <div class="note-text">${escHtml(n.text)}</div>
    </div>`).join(''):'<div style="font-size:.8rem;color:var(--wt-muted);padding:4px 0">No notes yet.</div>';
}
function renderTimeline(tl) {
  const el=document.getElementById('incidentTimeline'); if(!el) return;
  if(!tl.length){el.innerHTML='<div style="font-size:.8rem;color:var(--wt-muted)">No timeline entries</div>';return;}
  el.innerHTML=[...tl].reverse().map(t=>`
    <div class="timeline-item">
      <div class="timeline-dot"></div>
      <div class="timeline-body">
        <div class="timeline-action">${escHtml((t.action||'').replace(/_/g,' '))}</div>
        ${t.detail?`<div class="timeline-detail">${escHtml(t.detail)}</div>`:''}
        <div class="timeline-meta"><i class="fa-solid fa-user me-1"></i>${escHtml(t.actor)} · ${relTime(t.timestamp)}</div>
      </div>
    </div>`).join('');
}
async function addNote(id) {
  const ta=document.getElementById('noteTextarea'), text=ta?.value.trim();
  if(!text){toast('Please enter a note','warning');return;}
  try {
    const upd=await API.patch(`/incidents/${id}`,{note:text});
    if(upd){renderNotes(upd.analyst_notes||[]);ta.value='';toast('Note added','success');}
  } catch(e){toast('Failed: '+e.message,'error');}
}
async function updateIncidentStatus(id) {
  const status=document.getElementById('incStatusUpdate')?.value;
  const assigned_to=document.getElementById('incAssigneeUpdate')?.value.trim()||null;
  try {
    const upd=await API.patch(`/incidents/${id}`,{status,assigned_to});
    if(upd){toast('Incident updated','success');renderIncidentDetail(upd);}
  } catch(e){toast('Failed: '+e.message,'error');}
}
async function suppressIncident(id) {
  if(!confirm('Suppress this incident for 24 hours?')) return;
  try {
    await API.patch(`/incidents/${id}`,{status:'false_positive'});
    toast('Incident suppressed','success');loadPage('incidents');
  } catch(e){toast('Failed: '+e.message,'error');}
}
async function exportIncidentPDF(id) {
  const btn = document.querySelector('[onclick*="exportIncidentPDF"]');
  if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Generating PDF…'; }
  try {
    // Use API helper so the JWT Authorization header is included
    const blob = await API.get(`/incidents/${id}/export`);
    if (!blob) throw new Error('No response from server');
    // blob is returned as a Blob by the API helper when content-type is not JSON
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `WatchTower_Incident_${id.slice(0,8)}.pdf`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast('PDF downloaded successfully', 'success');
  } catch(e) {
    toast('PDF generation failed: ' + e.message, 'error');
  }
  if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fa-solid fa-file-pdf me-1"></i>Export PDF'; }
}

// ═══════════════════════════════════════════════════════════════════════════════
// RULES PAGE — full builder
// ═══════════════════════════════════════════════════════════════════════════════
async function loadRules() {
  await fetchRules();
  document.getElementById('seedRulesBtn')?.addEventListener('click',seedBuiltinRules);
  document.getElementById('createRuleBtn')?.addEventListener('click',showRuleBuilder);
  const si=document.getElementById('ruleSearch');
  if(si) si.addEventListener('input',debounce(()=>filterRulesTable(si.value),200));
  ['ruleSeverityFilter','ruleEnabledFilter','ruleCategoryFilter'].forEach(id=>
    document.getElementById(id)?.addEventListener('change',()=>fetchRules()));
}
async function fetchRules() {
  const tb=document.getElementById('rulesTbody'); if(!tb) return;
  tb.innerHTML='<tr><td colspan="8" class="text-center py-4"><div class="spinner-border spinner-border-sm text-info me-2"></div></td></tr>';
  try {
    const params={};
    const sv=document.getElementById('ruleSeverityFilter')?.value; if(sv) params.severity=sv;
    const en=document.getElementById('ruleEnabledFilter')?.value; if(en!==''&&en!=null) params.enabled=en;
    const ca=document.getElementById('ruleCategoryFilter')?.value; if(ca) params.category=ca;
    const d=await API.get('/rules/',params); if(!d) return;
    document.getElementById('rulesTotal').textContent=d.total;
    if(!d.data.length) {
      tb.innerHTML='<tr><td colspan="8" class="text-center text-muted py-5">No rules found. Click <strong>Seed Built-ins</strong> to add default rules.</td></tr>';
      return;
    }
    tb.innerHTML=d.data.map(r=>`
      <tr>
        <td><button class="rule-toggle ${r.enabled?'enabled':'disabled'}" onclick="toggleRule('${r._id}',this)">${r.enabled?'Enabled':'Disabled'}</button></td>
        <td>
          <div style="font-weight:500;font-size:.83rem">${escHtml(r.name)}</div>
          <div style="font-size:.72rem;color:var(--wt-muted)">${escHtml((r.description||'').slice(0,90))}${r.description?.length>90?'…':''}</div>
        </td>
        <td>${sevBadge(r.severity)}</td>
        <td><span style="font-size:.75rem;color:var(--wt-muted)">${(r.category||'').replace(/_/g,' ')}</span></td>
        <td>${mitreTags(r.mitre_technique)}</td>
        <td><span style="font-size:.83rem;font-weight:600">${r.hit_count||0}</span></td>
        <td style="font-size:.75rem;color:var(--wt-muted)">${r.last_triggered?relTime(r.last_triggered):'Never'}</td>
        <td style="white-space:nowrap">
          <button class="btn-wt btn-sm" onclick="showEditRule('${r._id}')" title="Edit"><i class="fa-solid fa-pen"></i></button>
          <button class="btn-wt btn-sm btn-danger ms-1" onclick="deleteRule('${r._id}')" title="Delete"><i class="fa-solid fa-trash"></i></button>
        </td>
      </tr>`).join('');
  } catch(e){toast('Failed to load rules: '+e.message,'error');}
}
function filterRulesTable(term) {
  document.querySelectorAll('#rulesTbody tr').forEach(row=>
    row.style.display=row.textContent.toLowerCase().includes(term.toLowerCase())?'':'none');
}
async function toggleRule(id,btn) {
  try {
    const d=await API.patch(`/rules/${id}/toggle`);
    if(d){btn.textContent=d.enabled?'Enabled':'Disabled';btn.className=`rule-toggle ${d.enabled?'enabled':'disabled'}`;toast(`Rule ${d.enabled?'enabled':'disabled'}`,'success');}
  } catch(e){toast('Toggle failed: '+e.message,'error');}
}
async function deleteRule(id) {
  if(!confirm('Delete this rule? This cannot be undone.')) return;
  try { await API.delete(`/rules/${id}`); toast('Rule deleted','success'); fetchRules(); }
  catch(e){toast('Delete failed: '+e.message,'error');}
}
async function seedBuiltinRules() {
  const btn=document.getElementById('seedRulesBtn');
  btn.disabled=true; btn.innerHTML='<span class="spinner-border spinner-border-sm me-1"></span>Seeding…';
  try { const d=await API.post('/rules/seed'); toast(d?.message||'Rules seeded','success'); fetchRules(); }
  catch(e){toast('Seed failed: '+e.message,'error');}
  btn.disabled=false; btn.innerHTML='<i class="fa-solid fa-download me-1"></i>Seed Built-ins';
}

// ── Rule Builder Modal ─────────────────────────────────────────────────────────
function showRuleBuilder(existingRule=null) {
  const modal=document.getElementById('ruleBuilderModal');
  const title=modal.querySelector('.modal-title');
  title.innerHTML=`<i class="fa-solid fa-shield-halved me-2"></i>${existingRule?'Edit Rule':'Create Detection Rule'}`;
  // Reset form
  document.getElementById('rbName').value=existingRule?.name||'';
  document.getElementById('rbDescription').value=existingRule?.description||'';
  document.getElementById('rbCategory').value=existingRule?.category||'authentication';
  document.getElementById('rbSeverity').value=existingRule?.severity||'medium';
  document.getElementById('rbThreshold').value=existingRule?.condition?.threshold||1;
  document.getElementById('rbWindow').value=existingRule?.condition?.window_seconds||300;
  document.getElementById('rbExcludeMachines').checked=existingRule?.condition?.exclude_machine_accounts||false;
  document.getElementById('rbMitreTech').value=(existingRule?.mitre_technique||[]).join(', ');
  document.getElementById('rbMitreTactic').value=(existingRule?.mitre_tactic||[]).join(', ');
  // Event IDs
  _rbEventIds=existingRule?.condition?.event_ids||[];
  renderEventIdTags();
  // Field conditions
  _rbFieldConds=Object.entries(existingRule?.condition?.fields||{}).map(([k,v])=>({field:k,op:typeof v==='object'?Object.keys(v)[0]:'equals',val:typeof v==='object'?Object.values(v)[0]:v}));
  renderFieldConds();
  document.getElementById('rbSaveBtn').onclick=()=>saveRule(existingRule?._id||null);
  showModal('ruleBuilderModal');
}
async function showEditRule(id) {
  try { const r=await API.get(`/rules/${id}`); if(r) showRuleBuilder(r); }
  catch(e){toast('Failed to load rule: '+e.message,'error');}
}

let _rbEventIds=[], _rbFieldConds=[];

function renderEventIdTags() {
  const c=document.getElementById('rbEventIdTags'); if(!c) return;
  c.innerHTML=_rbEventIds.map(id=>`
    <span class="event-id-tag">${id}<button onclick="_rbRemoveEventId(${id})">×</button></span>`).join('')+
    `<input class="event-id-input" id="rbEventIdInput" placeholder="Add ID…" type="number" min="1">`;
  document.getElementById('rbEventIdInput')?.addEventListener('keydown',e=>{
    if((e.key==='Enter'||e.key===','||e.key===' ')&&e.target.value.trim()){
      e.preventDefault();
      const v=parseInt(e.target.value.trim());
      if(v&&!_rbEventIds.includes(v)){_rbEventIds.push(v);renderEventIdTags();}
      else e.target.value='';
    }
  });
}
function _rbRemoveEventId(id){_rbEventIds=_rbEventIds.filter(x=>x!==id);renderEventIdTags();}

function renderFieldConds() {
  const c=document.getElementById('rbFieldConds'); if(!c) return;
  c.innerHTML=_rbFieldConds.map((fc,i)=>`
    <div class="field-cond-row">
      <input class="wt-input" style="width:130px" placeholder="Field name" value="${escHtml(fc.field)}" oninput="_rbFieldConds[${i}].field=this.value">
      <select class="wt-select" onchange="_rbFieldConds[${i}].op=this.value">
        ${['contains','equals','not_equals','regex'].map(o=>`<option value="${o}"${fc.op===o?' selected':''}>${o}</option>`).join('')}
      </select>
      <input class="wt-input" style="flex:1" placeholder="Value" value="${escHtml(fc.val)}" oninput="_rbFieldConds[${i}].val=this.value">
      <button class="remove-cond-btn" onclick="_rbFieldConds.splice(${i},1);renderFieldConds()"><i class="fa-solid fa-xmark"></i></button>
    </div>`).join('');
}

async function saveRule(existingId=null) {
  const name=document.getElementById('rbName').value.trim();
  const description=document.getElementById('rbDescription').value.trim();
  if(!name||!description){toast('Name and description are required','warning');return;}
  if(!_rbEventIds.length){toast('Add at least one Event ID','warning');return;}
  const fields={};
  for(const fc of _rbFieldConds){
    if(fc.field&&fc.val) fields[fc.field]={[fc.op]:fc.val};
  }
  const condition={event_ids:_rbEventIds,threshold:parseInt(document.getElementById('rbThreshold').value)||1,window_seconds:parseInt(document.getElementById('rbWindow').value)||300};
  if(document.getElementById('rbExcludeMachines').checked) condition.exclude_machine_accounts=true;
  if(Object.keys(fields).length) condition.fields=fields;
  const payload={
    name,description,
    category:document.getElementById('rbCategory').value,
    severity:document.getElementById('rbSeverity').value,
    condition,
    mitre_technique:document.getElementById('rbMitreTech').value.split(',').map(s=>s.trim()).filter(Boolean),
    mitre_tactic:document.getElementById('rbMitreTactic').value.split(',').map(s=>s.trim()).filter(Boolean),
    enabled:true,
  };
  const btn=document.getElementById('rbSaveBtn');
  btn.disabled=true; btn.innerHTML='<span class="spinner-border spinner-border-sm me-1"></span>Saving…';
  try {
    if(existingId) { await API.put(`/rules/${existingId}`,payload); toast('Rule updated','success'); }
    else { await API.post('/rules/',payload); toast('Rule created','success'); }
    hideModal('ruleBuilderModal'); fetchRules();
  } catch(e){toast('Save failed: '+e.message,'error');}
  btn.disabled=false; btn.innerHTML='<i class="fa-solid fa-floppy-disk me-1"></i>Save Rule';
}

// ── Test rule preview ─────────────────────────────────────────────────────────
async function testRulePreview() {
  const res=document.getElementById('rbTestResult'); if(!res) return;
  const condition={event_ids:_rbEventIds};
  if(!_rbEventIds.length){res.className='rule-test-result fail';res.innerHTML='<i class="fa-solid fa-xmark me-2"></i>Add at least one Event ID to test';res.style.display='block';return;}
  res.className='rule-test-result';res.innerHTML='<div class="spinner-border spinner-border-sm me-2"></div>Testing…';res.style.display='block';
  try {
    const recent=await API.get('/events/',{per_page:100});
    const matches=(recent?.data||[]).filter(ev=>_rbEventIds.includes(ev.event_id));
    if(matches.length) {
      res.className='rule-test-result pass';
      res.innerHTML=`<i class="fa-solid fa-check me-2"></i><strong>${matches.length} matching events</strong> found in recent data. Sample: ${escHtml(matches[0].hostname)} — Event ${matches[0].event_id}`;
    } else {
      res.className='rule-test-result fail';
      res.innerHTML=`<i class="fa-solid fa-circle-info me-2"></i>No matching events in recent data. Rule will activate when Event ID(s) ${_rbEventIds.join(', ')} are received.`;
    }
  } catch { res.className='rule-test-result fail'; res.innerHTML='<i class="fa-solid fa-xmark me-2"></i>Preview failed'; }
}

// ═══════════════════════════════════════════════════════════════════════════════
// AGENTS PAGE
// ═══════════════════════════════════════════════════════════════════════════════
async function loadAgents() {
  try {
    const d=await API.get('/agents/'); if(!d) return;
    document.getElementById('agentsTotal').textContent=d.total;
    const tb=document.getElementById('agentsTbody');
    if(!d.data.length) {
      tb.innerHTML='<tr><td colspan="8" class="text-center text-muted py-5">No agents registered. Click <strong>Register Agent</strong> to add one.</td></tr>';
    } else {
      tb.innerHTML=d.data.map(a=>`
        <tr>
          <td><div class="agent-status"><div class="agent-dot ${a.status}"></div>${a.status}</div></td>
          <td><code style="font-size:.82rem">${escHtml(a.hostname)}</code><div style="font-size:.7rem;color:var(--wt-muted)">${escHtml(a.last_ip||a.ip_address)}</div></td>
          <td style="font-size:.78rem;color:var(--wt-muted)">${escHtml(a.os_version)}</td>
          <td style="font-size:.78rem">${a.last_seen?relTime(a.last_seen):'<em style="color:var(--wt-muted)">Never</em>'}</td>
          <td style="font-size:.83rem;font-weight:600">${(a.events_received||0).toLocaleString()}</td>
          <td>${a.sysmon_installed?'<span style="color:var(--wt-green)"><i class="fa-solid fa-check-circle"></i> Yes</span>':'<span style="color:var(--wt-muted)"><i class="fa-solid fa-xmark"></i> No</span>'}</td>
          <td style="font-size:.78rem;color:var(--wt-muted)">${a.agent_version}</td>
          <td style="white-space:nowrap">
            <button class="btn-wt btn-sm" onclick="rotateAgentKey('${a._id}','${escHtml(a.hostname)}')" title="Rotate API key"><i class="fa-solid fa-key"></i></button>
            <button class="btn-wt btn-sm btn-danger ms-1" onclick="decommissionAgent('${a._id}','${escHtml(a.hostname)}')" title="Decommission"><i class="fa-solid fa-trash"></i></button>
          </td>
        </tr>`).join('');
    }
    document.getElementById('registerAgentBtn')?.addEventListener('click',()=>{
      document.getElementById('regAgentSuccess').style.display='none';
      document.getElementById('regAgentError').style.display='none';
      showModal('registerAgentModal');
    });
    document.getElementById('confirmRegisterAgent').onclick=registerAgent;
  } catch(e){toast('Failed to load agents: '+e.message,'error');}
}
async function registerAgent() {
  const hostname=document.getElementById('agentHostname')?.value.trim();
  const ip=document.getElementById('agentIP')?.value.trim();
  const os=document.getElementById('agentOS')?.value.trim();
  const sysmon=document.getElementById('agentSysmon')?.checked;
  if(!hostname||!ip||!os){toast('All fields required','warning');return;}
  try {
    const d=await API.post('/agents/register',{hostname,ip_address:ip,os_version:os,sysmon_installed:sysmon});
    document.getElementById('regApiKey').textContent=d.api_key;
    document.getElementById('regAgentSuccess').style.display='';
    toast('Agent registered','success'); loadAgents();
  } catch(e){
    document.getElementById('regAgentError').textContent=e.message;
    document.getElementById('regAgentError').style.display='';
  }
}
async function rotateAgentKey(id,hostname) {
  if(!confirm(`Rotate API key for ${hostname}? Old key stops working immediately.`)) return;
  try {
    const d=await API.post(`/agents/${id}/rotate-key`);
    const key=d.api_key;
    document.getElementById('rotatedKey').textContent=key;
    document.getElementById('rotateKeyHostname').textContent=hostname;
    document.getElementById('copyRotatedKeyBtn').onclick=()=>copyText(key,'API key copied!');
    showModal('rotatedKeyModal');
    toast('API key rotated','success');
  } catch(e){toast('Failed: '+e.message,'error');}
}
async function decommissionAgent(id,hostname) {
  if(!confirm(`Decommission ${hostname}? It will stop receiving events.`)) return;
  try { await API.delete(`/agents/${id}`); toast('Agent decommissioned','success'); loadAgents(); }
  catch(e){toast('Failed: '+e.message,'error');}
}

// ═══════════════════════════════════════════════════════════════════════════════
// USERS PAGE — full management
// ═══════════════════════════════════════════════════════════════════════════════
async function loadUsers() {
  const tpl=document.getElementById('tpl-users');
  document.getElementById('pageContent').innerHTML=tpl?tpl.innerHTML:`
    <div class="fade-in">
      <div class="page-toolbar">
        <div class="toolbar-filters">
          <input class="wt-input" id="userSearch" placeholder="Search users…">
          <select class="wt-select" id="userRoleFilter">
            <option value="">All Roles</option>
            <option value="super_admin">Super Admin</option>
            <option value="admin">Admin</option>
            <option value="analyst">Analyst</option>
            <option value="read_only">Read Only</option>
          </select>
        </div>
        <div class="toolbar-actions">
          <button class="btn-wt btn-primary" id="createUserBtn"><i class="fa-solid fa-plus me-1"></i>New User</button>
        </div>
      </div>
      <div class="data-card">
        <div class="data-card-header">
          <h3>Users <span class="count-badge" id="usersTotal">-</span></h3>
        </div>
        <div class="table-responsive">
          <table class="wt-table">
            <thead><tr><th>Username</th><th>Full Name</th><th>Email</th><th>Role</th><th>MFA</th><th>Status</th><th>Last Login</th><th></th></tr></thead>
            <tbody id="usersTbody"><tr><td colspan="8" class="text-center py-4"><div class="spinner-border spinner-border-sm text-info"></div></td></tr></tbody>
          </table>
        </div>
      </div>
    </div>`;
  await fetchUsers();
  document.getElementById('createUserBtn')?.addEventListener('click',()=>showCreateUserModal());
  document.getElementById('userSearch')?.addEventListener('input',debounce(()=>{
    const t=document.getElementById('userSearch').value.toLowerCase();
    document.querySelectorAll('#usersTbody tr').forEach(r=>r.style.display=r.textContent.toLowerCase().includes(t)?'':'none');
  },200));
}
async function fetchUsers() {
  try {
    const d=await API.get('/users/'); if(!d) return;
    document.getElementById('usersTotal').textContent=d.data.length;
    const tb=document.getElementById('usersTbody');
    tb.innerHTML=d.data.map(u=>`
      <tr>
        <td style="font-weight:600"><i class="fa-solid fa-user me-2" style="color:var(--wt-muted);font-size:.75rem"></i>${escHtml(u.username)}</td>
        <td style="font-size:.83rem">${escHtml(u.full_name||'—')}</td>
        <td style="font-size:.78rem;color:var(--wt-muted)">${escHtml(u.email)}</td>
        <td><span class="user-role-badge role-${u.role}">${(u.role||'').replace(/_/g,' ')}</span></td>
        <td>${u.mfa_enabled?'<span style="color:var(--wt-green)"><i class="fa-solid fa-shield-check"></i> On</span>':'<span style="color:var(--wt-muted)">Off</span>'}</td>
        <td>${u.is_active?'<span style="color:var(--wt-green)">Active</span>':'<span style="color:var(--wt-red)">Inactive</span>'}</td>
        <td style="font-size:.75rem;color:var(--wt-muted)">${u.last_login?relTime(u.last_login):'Never'}</td>
        <td style="white-space:nowrap">
          <button class="btn-wt btn-sm" onclick="showEditUserModal('${u._id}','${escHtml(u.username)}','${escHtml(u.full_name||'')}','${u.role}')"><i class="fa-solid fa-pen"></i></button>
          ${u._id!==currentUser?.id?`<button class="btn-wt btn-sm btn-danger ms-1" onclick="deactivateUser('${u._id}','${escHtml(u.username)}')"><i class="fa-solid fa-ban"></i></button>`:
          '<span style="font-size:.72rem;color:var(--wt-muted);padding:0 8px">You</span>'}
        </td>
      </tr>`).join('');
  } catch(e){toast('Failed to load users: '+e.message,'error');}
}
function showCreateUserModal() {
  document.getElementById('createUserError').style.display='none';
  document.getElementById('createUserForm').reset();
  showModal('createUserModal');
  document.getElementById('confirmCreateUser').onclick=createUser;
}
async function createUser() {
  const username=document.getElementById('cuUsername').value.trim();
  const email=document.getElementById('cuEmail').value.trim();
  const password=document.getElementById('cuPassword').value;
  const full_name=document.getElementById('cuFullName').value.trim();
  const role=document.getElementById('cuRole').value;
  if(!username||!email||!password){toast('Username, email, and password are required','warning');return;}
  const btn=document.getElementById('confirmCreateUser');
  btn.disabled=true; btn.innerHTML='<span class="spinner-border spinner-border-sm me-1"></span>Creating…';
  try {
    await API.post('/auth/register',{username,email,password,full_name,role});
    toast(`User ${username} created`,'success');
    hideModal('createUserModal'); fetchUsers();
  } catch(e){
    const err=document.getElementById('createUserError');
    err.textContent=e.message||'Failed to create user'; err.style.display='block';
  }
  btn.disabled=false; btn.innerHTML='Create User';
}
function showEditUserModal(id,username,full_name,role) {
  document.getElementById('editUserId').value=id;
  document.getElementById('euFullName').value=full_name||'';
  document.getElementById('euRole').value=role||'analyst';
  showModal('editUserModal');
  document.getElementById('confirmEditUser').onclick=()=>editUser(id);
}
async function editUser(id) {
  const full_name=document.getElementById('euFullName').value.trim();
  const role=document.getElementById('euRole').value;
  const btn=document.getElementById('confirmEditUser');
  btn.disabled=true;
  try {
    await API.patch(`/users/${id}`,{full_name,role});
    toast('User updated','success'); hideModal('editUserModal'); fetchUsers();
  } catch(e){toast('Failed: '+e.message,'error');}
  btn.disabled=false;
}
async function deactivateUser(id,username) {
  if(!confirm(`Deactivate user ${username}?`)) return;
  try { await API.delete(`/users/${id}`); toast(`${username} deactivated`,'success'); fetchUsers(); }
  catch(e){toast('Failed: '+e.message,'error');}
}

// ═══════════════════════════════════════════════════════════════════════════════
// THREAT INTEL PAGE
// ═══════════════════════════════════════════════════════════════════════════════
async function loadThreatIntel() {
  const tpl=document.getElementById('tpl-threat-intel');
  document.getElementById('pageContent').innerHTML=tpl?tpl.innerHTML:`
    <div class="fade-in">
      <div class="page-toolbar">
        <div class="toolbar-filters">
          <select class="wt-select" id="iocTypeFilter">
            <option value="">All Types</option>
            <option value="ip">IP Address</option>
            <option value="domain">Domain</option>
            <option value="hash">File Hash</option>
            <option value="url">URL</option>
          </select>
          <input class="wt-input wide" id="iocSearch" placeholder="Search IOCs…">
          <button class="btn-wt btn-primary" id="iocSearchBtn"><i class="fa-solid fa-magnifying-glass me-1"></i>Search</button>
        </div>
        <div class="toolbar-actions">
          <button class="btn-wt btn-success" id="addIocBtn"><i class="fa-solid fa-plus me-1"></i>Add IOC</button>
          <button class="btn-wt" id="importIocBtn"><i class="fa-solid fa-file-import me-1"></i>Import CSV</button>
        </div>
      </div>
      <!-- Stats row -->
      <div class="metrics-grid" id="iocStats" style="grid-template-columns:repeat(4,1fr);margin-bottom:20px">
        <div class="metric-card info"><div class="metric-icon"><i class="fa-solid fa-crosshairs"></i></div><div class="metric-body"><div class="metric-value" id="iocTotal">—</div><div class="metric-label">Total IOCs</div></div></div>
        <div class="metric-card high"><div class="metric-icon"><i class="fa-solid fa-network-wired"></i></div><div class="metric-body"><div class="metric-value" id="iocIpCount">—</div><div class="metric-label">IP Addresses</div></div></div>
        <div class="metric-card critical"><div class="metric-icon"><i class="fa-solid fa-globe"></i></div><div class="metric-body"><div class="metric-value" id="iocDomainCount">—</div><div class="metric-label">Domains</div></div></div>
        <div class="metric-card success"><div class="metric-icon"><i class="fa-solid fa-fingerprint"></i></div><div class="metric-body"><div class="metric-value" id="iocHashCount">—</div><div class="metric-label">File Hashes</div></div></div>
      </div>
      <div class="data-card">
        <div class="data-card-header">
          <h3>IOC Feed <span class="count-badge" id="iocListTotal">-</span></h3>
        </div>
        <div class="table-responsive">
          <table class="wt-table">
            <thead><tr><th>Type</th><th>Value</th><th>Threat Type</th><th>Confidence</th><th>Source</th><th>Expires</th><th></th></tr></thead>
            <tbody id="iocTbody"><tr><td colspan="7" class="text-center py-4"><div class="spinner-border spinner-border-sm text-info me-2"></div>Loading…</td></tr></tbody>
          </table>
        </div>
        <div class="pagination-bar" id="iocPaginationBar"></div>
      </div>
    </div>`;
  await fetchIocs();
  document.getElementById('iocSearchBtn')?.addEventListener('click',()=>{State.iocPage=1;fetchIocs();});
  document.getElementById('iocTypeFilter')?.addEventListener('change',()=>{State.iocPage=1;fetchIocs();});
  document.getElementById('iocSearch')?.addEventListener('keydown',e=>{if(e.key==='Enter'){State.iocPage=1;fetchIocs();}});
  document.getElementById('addIocBtn')?.addEventListener('click',showAddIocModal);
  document.getElementById('importIocBtn')?.addEventListener('click',()=>document.getElementById('iocCsvImport')?.click());
  document.getElementById('iocCsvImport')?.addEventListener('change',importIocCsv);
}
async function fetchIocs() {
  try {
    const params={page:State.iocPage,per_page:50};
    const t=document.getElementById('iocTypeFilter')?.value; if(t) params.ioc_type=t;
    const s=document.getElementById('iocSearch')?.value; if(s) params.search=s;
    const d=await API.get('/compliance/threat-intel',params);
    if(!d) return;
    const stats=d.stats||{};
    document.getElementById('iocTotal').textContent=(d.total||0).toLocaleString();
    document.getElementById('iocIpCount').textContent=(stats.ip||0).toLocaleString();
    document.getElementById('iocDomainCount').textContent=(stats.domain||0).toLocaleString();
    document.getElementById('iocHashCount').textContent=(stats.hash||0).toLocaleString();
    document.getElementById('iocListTotal').textContent=d.total||0;
    const tb=document.getElementById('iocTbody');
    if(!d.data||!d.data.length) {
      tb.innerHTML='<tr><td colspan="7" class="text-center text-muted py-5"><i class="fa-solid fa-shield-check me-2 text-success"></i>No IOCs found. Add IOCs to start threat correlation.</td></tr>'; return;
    }
    tb.innerHTML=d.data.map(ioc=>`
      <tr>
        <td><span class="ioc-type-badge ioc-${ioc.ioc_type}">${ioc.ioc_type}</span></td>
        <td><code style="font-size:.78rem;word-break:break-all">${escHtml(ioc.ioc_value)}</code></td>
        <td style="font-size:.8rem">${escHtml(ioc.threat_type||'—')}</td>
        <td>
          <div style="display:flex;align-items:center;gap:6px">
            <div style="width:50px;height:5px;background:var(--wt-surface2);border-radius:3px;overflow:hidden">
              <div style="width:${ioc.confidence||0}%;height:100%;background:${(ioc.confidence||0)>=70?'var(--wt-green)':(ioc.confidence||0)>=40?'var(--wt-yellow)':'var(--wt-red)'};border-radius:3px"></div>
            </div>
            <span style="font-size:.75rem;color:var(--wt-muted)">${ioc.confidence||0}%</span>
          </div>
        </td>
        <td style="font-size:.78rem;color:var(--wt-muted)">${escHtml(ioc.source||'Manual')}</td>
        <td style="font-size:.75rem;color:var(--wt-muted)">${ioc.expires_at?relTime(ioc.expires_at):'Never'}</td>
        <td><button class="btn-wt btn-sm btn-danger" onclick="deleteIoc('${ioc._id}')"><i class="fa-solid fa-trash"></i></button></td>
      </tr>`).join('');
    buildPagination(document.getElementById('iocPaginationBar'),State.iocPage,Math.ceil(d.total/50)||1,p=>{State.iocPage=p;fetchIocs();});
  } catch(e){
    document.getElementById('iocTbody').innerHTML='<tr><td colspan="7" class="text-center text-muted py-5">Threat intel endpoint not available. Configure in Settings.</td></tr>';
  }
}
function showAddIocModal() {
  document.getElementById('addIocError').style.display='none';
  document.getElementById('addIocForm').reset();
  showModal('addIocModal');
  document.getElementById('confirmAddIoc').onclick=addIoc;
}
async function addIoc() {
  const ioc_value=document.getElementById('iocValue').value.trim();
  const ioc_type=document.getElementById('iocType').value;
  const threat_type=document.getElementById('iocThreatType').value.trim();
  const confidence=parseInt(document.getElementById('iocConfidence').value)||50;
  const source=document.getElementById('iocSource').value.trim()||'Manual';
  if(!ioc_value){toast('IOC value is required','warning');return;}
  const btn=document.getElementById('confirmAddIoc');
  btn.disabled=true; btn.innerHTML='<span class="spinner-border spinner-border-sm me-1"></span>Adding…';
  try {
    await API.post('/compliance/threat-intel',{ioc_value,ioc_type,threat_type,confidence,source});
    toast('IOC added','success'); hideModal('addIocModal'); fetchIocs();
  } catch(e){
    const er=document.getElementById('addIocError');
    er.textContent=e.message; er.style.display='block';
  }
  btn.disabled=false; btn.innerHTML='Add IOC';
}
async function deleteIoc(id) {
  if(!confirm('Delete this IOC?')) return;
  try { await API.delete(`/compliance/threat-intel/${id}`); toast('IOC deleted','success'); fetchIocs(); }
  catch(e){toast('Failed: '+e.message,'error');}
}
async function importIocCsv(e) {
  const file=e.target.files[0]; if(!file) return;
  const reader=new FileReader();
  reader.onload=async ev=>{
    const lines=ev.target.result.split('\n').slice(1);
    let added=0,failed=0;
    for(const line of lines) {
      const [value,type,threat,conf,source]=(line||'').split(',').map(s=>s.trim());
      if(!value||!type) continue;
      try { await API.post('/compliance/threat-intel',{ioc_value:value,ioc_type:type,threat_type:threat||'',confidence:parseInt(conf)||50,source:source||'Import'}); added++; }
      catch { failed++; }
    }
    toast(`Imported ${added} IOCs${failed?`, ${failed} failed`:''}`,added>0?'success':'warning');
    fetchIocs();
  };
  reader.readAsText(file);
  e.target.value='';
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMPLIANCE
// ═══════════════════════════════════════════════════════════════════════════════
function initCompliancePage() {
  // Use onclick= instead of addEventListener to prevent duplicate handlers
  // when the user navigates away and back to the compliance page
  const genBtn = document.getElementById('genReportBtn');
  const postureBtn = document.getElementById('postureBtn');
  if (genBtn) genBtn.onclick = generateComplianceReport;
  if (postureBtn) postureBtn.onclick = loadPostureOverview;
}

async function loadPostureOverview() {
  const area = document.getElementById('complianceReportArea');
  const overview = document.getElementById('postureOverview');
  area.innerHTML = '<div class="text-center py-5"><div class="spinner-border text-info"></div><p class="text-muted mt-3">Loading posture…</p></div>';
  try {
    const r = await API.get('/compliance/posture', {days: document.getElementById('compPeriod')?.value || 30});
    if (!r) return;
    const fwHtml = Object.entries(r.frameworks || {}).map(([id, fw]) => {
      const col = fw.overall_score >= 80 ? 'var(--wt-green)' : fw.overall_score >= 50 ? '#ffc107' : 'var(--wt-red)';
      return `<div class="compliance-stat-card" style="cursor:pointer" onclick="selectFrameworkAndGenerate('${id}')">
        <div class="compliance-stat-val" style="color:${col}">${Math.round(fw.overall_score)}%</div>
        <div class="compliance-stat-label">${escHtml(fw.name)}</div>
        <div style="font-size:.7rem;margin-top:4px;color:${col};font-weight:700">${fw.status.replace(/_/g,' ').toUpperCase()}</div>
        <div style="font-size:.68rem;color:var(--wt-muted);margin-top:2px">${fw.compliant_controls}/${fw.total_controls} controls</div>
      </div>`;
    }).join('');
    area.innerHTML = `<div class="data-card fade-in">
      <div class="data-card-header"><h3><i class="fa-solid fa-gauge-high me-2" style="color:var(--wt-accent)"></i>Overall Compliance Posture</h3>
        <div style="font-size:.75rem;color:var(--wt-muted)">Last ${r.period_days} days &middot; Click a framework for a detailed report</div>
      </div>
      <div style="padding:20px"><div class="compliance-summary-grid" style="grid-template-columns:repeat(auto-fit,minmax(160px,1fr))">${fwHtml}</div></div>
    </div>`;
  } catch(e) { area.innerHTML = `<div class="alert alert-danger">Failed to load posture: ${escHtml(e.message)}</div>`; }
}

function selectFrameworkAndGenerate(fwId) {
  const sel = document.getElementById('compFramework');
  if (sel) sel.value = fwId;
  generateComplianceReport();
}
async function generateComplianceReport() {
  const fw    = document.getElementById('compFramework')?.value;
  const days  = document.getElementById('compPeriod')?.value || '30';
  const area  = document.getElementById('complianceReportArea');
  if (!fw) { toast('Select a framework first', 'warning'); return; }

  area.innerHTML = '<div class="text-center py-5"><div class="spinner-border text-info"></div><p class="text-muted mt-3">Generating report…</p></div>';

  let r;
  try {
    r = await API.get(`/compliance/report/${fw}`, {days});
  } catch(e) {
    area.innerHTML = `<div class="alert alert-danger"><i class="fa-solid fa-triangle-exclamation me-2"></i><strong>Report failed:</strong> ${escHtml(e.message)}</div>`;
    return;
  }
  if (!r) {
    area.innerHTML = '<div class="alert alert-warning">No data returned. Make sure agents are running and events are being collected.</div>';
    return;
  }

  // ── Scores and status ─────────────────────────────────────────────────────
  const overallScore  = r.overall_score ?? 0;
  const overallStatus = r.overall_status ?? (overallScore >= 80 ? 'compliant' : overallScore >= 50 ? 'partial' : 'at_risk');
  const scoreCol      = overallScore >= 80 ? 'var(--wt-green)' : overallScore >= 50 ? 'var(--wt-yellow)' : 'var(--wt-red)';
  const statusLabel   = overallStatus.replace(/_/g, ' ');
  const summary       = r.summary || {};

  // ── Summary stat cards ────────────────────────────────────────────────────
  const stats = [
    ['Events Monitored',   (summary.total_events_monitored ?? 0).toLocaleString()],
    ['Total Incidents',    (summary.total_incidents ?? 0).toLocaleString()],
    ['Resolution Rate',    summary.resolution_rate_pct != null ? summary.resolution_rate_pct.toFixed(1) + '%' : '—'],
    ['Active Agents',      (summary.active_agents ?? '—').toLocaleString?.() ?? summary.active_agents ?? '—'],
    ['Controls Compliant', `${summary.compliant_controls ?? 0} / ${summary.total_controls ?? 0}`],
    ['Coverage Gaps',      (summary.gap_controls ?? 0).toString()],
  ];
  const summaryHtml = stats.map(([l, v]) =>
    `<div class="compliance-stat-card">
      <div class="compliance-stat-val">${escHtml(String(v))}</div>
      <div class="compliance-stat-label">${l}</div>
    </div>`
  ).join('');

  // ── Recommendations ───────────────────────────────────────────────────────
  const recs = r.recommendations || [];
  const recsHtml = recs.length
    ? `<h4 class="section-heading">
         <i class="fa-solid fa-lightbulb me-2" style="color:var(--wt-yellow)"></i>Top Recommendations
       </h4>
       ${recs.map((rec, i) =>
         `<div class="recommendation-item">
           <span class="rec-num">${i + 1}</span>
           <span>${escHtml(rec)}</span>
         </div>`
       ).join('')}`
    : '';

  // ── Controls list ─────────────────────────────────────────────────────────
  const controls = r.controls || [];
  const controlsHtml = controls.length
    ? controls.map(c => {
        const status = c.status || 'needs_review';
        const score  = c.score != null ? c.score : null;
        // Build evidence tooltip
        const evParts = [];
        if (c.evidence) {
          Object.entries(c.evidence).forEach(([k, v]) => {
            if (typeof v === 'number' && v > 0) evParts.push(`${k.replace(/_/g,' ')}: ${v.toLocaleString()}`);
          });
        }
        const tooltip = evParts.length ? `title="${escHtml(evParts.join(' | '))}"` : '';
        return `
          <div class="control-item" ${tooltip}>
            <div class="control-id">${escHtml(c.id || '')}</div>
            <div class="control-info">
              <div class="control-name">${escHtml(c.name || '')}</div>
              <div class="control-count">${escHtml((c.description || '').slice(0, 90))}${(c.description||'').length > 90 ? '…' : ''}</div>
            </div>
            ${score != null ? `<div class="control-score">${score}%</div>` : ''}
            <div class="control-status ${escHtml(status)}">${escHtml(status.replace(/_/g,' '))}</div>
          </div>`;
      }).join('')
    : '<div class="text-muted py-3" style="font-size:.82rem">No controls data available.</div>';

  // ── MITRE coverage ────────────────────────────────────────────────────────
  const mitreCoverage = r.mitre_coverage || [];
  const coveredItems   = mitreCoverage.filter(t => t.status === 'covered');
  const uncoveredItems = mitreCoverage.filter(t => t.status === 'no_coverage');

  const mitreHtml = mitreCoverage.length
    ? `<h4 class="section-heading">
         <i class="fa-brands fa-fort-awesome me-2" style="color:var(--wt-accent2)"></i>
         MITRE ATT&CK Detection Coverage
       </h4>
       <div class="mitre-coverage-summary">
         <span style="color:var(--wt-green)">
           <i class="fa-solid fa-shield-check me-1"></i>${coveredItems.length} covered
         </span>
         <span style="color:${uncoveredItems.length ? 'var(--wt-red)' : 'var(--wt-muted)'}">
           <i class="fa-solid fa-circle-xmark me-1"></i>${uncoveredItems.length} gap${uncoveredItems.length !== 1 ? 's' : ''}
         </span>
       </div>
       ${uncoveredItems.length
         ? uncoveredItems.map(t => `
             <div class="mitre-gap-row">
               <code class="mitre-gap-code">${escHtml(t.technique)}</code>
               <span class="mitre-gap-rec">${escHtml(t.recommendation || 'No detection rule exists for this technique')}</span>
               <button class="btn-wt btn-sm" onclick="navigateToNewRule('${escHtml(t.technique)}')" style="font-size:.68rem;flex-shrink:0">
                 <i class="fa-solid fa-plus me-1"></i>Add Rule
               </button>
             </div>`).join('')
         : '<div class="all-covered"><i class="fa-solid fa-shield-check me-2"></i>All required techniques are covered.</div>'}`
    : '';

  // ── Action buttons ────────────────────────────────────────────────────────
  const actionsHtml = `
    <div class="report-actions">
      <button class="btn-wt btn-primary" onclick="downloadEvidencePackage('${escHtml(fw)}','${escHtml(days)}')">
        <i class="fa-solid fa-file-arrow-down me-1"></i>Download Evidence Package
      </button>
      <button class="btn-wt" onclick="generateComplianceReport()">
        <i class="fa-solid fa-arrows-rotate me-1"></i>Regenerate
      </button>
    </div>`;

  // ── Assemble full report ──────────────────────────────────────────────────
  area.innerHTML = `
    <div class="compliance-report fade-in">
      <div class="data-card">

        <!-- Header -->
        <div class="data-card-header">
          <div>
            <h3>
              <i class="fa-solid fa-file-certificate me-2" style="color:var(--wt-accent)"></i>
              ${escHtml(r.framework || fw)}
              <span style="font-size:.72rem;color:var(--wt-muted);font-weight:400;margin-left:8px">v${escHtml(r.version || '')}</span>
            </h3>
            <div style="font-size:.75rem;color:var(--wt-muted);margin-top:3px">
              Generated ${fmtDate(r.generated_at)}
              &middot; Last ${r.period_days} days
              &middot; ${escHtml(r.org_name || '')}
              &middot; By ${escHtml(r.generated_by || '')}
            </div>
          </div>
          <div class="overall-score-badge">
            <div class="score-value" style="color:${scoreCol}">${Math.round(overallScore)}%</div>
            <div class="score-label" style="color:${scoreCol}">${escHtml(statusLabel.toUpperCase())}</div>
          </div>
        </div>

        <div style="padding:0 20px 20px">

          <!-- Summary stats -->
          <div class="compliance-summary-grid">${summaryHtml}</div>

          <!-- Recommendations -->
          ${recsHtml}

          <!-- Controls -->
          <h4 class="section-heading">
            <i class="fa-solid fa-list-check me-2" style="color:var(--wt-accent)"></i>Controls Assessment
          </h4>
          ${controlsHtml}

          <!-- MITRE -->
          ${mitreHtml}

          <!-- Actions -->
          ${actionsHtml}
        </div>
      </div>
    </div>`;
}


async function downloadEvidencePackage(fw, days) {
  try {
    toast('Preparing evidence package…', 'info');
    const data = await API.get(`/compliance/evidence-package/${fw}`, {days});
    if (!data) return;
    const blob = new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `watchtower_evidence_${fw}_${new Date().toISOString().slice(0,10)}.json`;
    a.click(); URL.revokeObjectURL(url);
    toast('Evidence package downloaded', 'success');
  } catch(e) { toast('Failed to download: ' + e.message, 'error'); }
}


function navigateToNewRule(mitreTechnique) {
  // Navigate to rules page, then open rule builder pre-filled with the MITRE technique
  loadPage('rules');
  setTimeout(() => {
    document.getElementById('createRuleBtn')?.click();
    setTimeout(() => {
      const el = document.getElementById('rbMitreTech');
      if (el) { el.value = mitreTechnique; el.focus(); }
      toast(`Pre-filled MITRE technique: ${mitreTechnique}`, 'info');
    }, 350);
  }, 450);
}


// ═══════════════════════════════════════════════════════════════════════════════
// AUDIT LOG
// ═══════════════════════════════════════════════════════════════════════════════
async function loadAuditLog() {
  async function fetchPage(page=1) {
    const tb=document.getElementById('auditTbody'); if(!tb) return;
    tb.innerHTML='<tr><td colspan="6" class="text-center py-3"><div class="spinner-border spinner-border-sm text-info"></div></td></tr>';
    try {
      const d=await API.get('/users/audit-log',{page,per_page:50}); if(!d) return;
      document.getElementById('auditTotal').textContent=d.pagination.total.toLocaleString();
      tb.innerHTML=d.data.map(l=>`
        <tr>
          <td style="font-size:.75rem;white-space:nowrap">${fmtDateShort(l.timestamp)}</td>
          <td style="font-weight:500;font-size:.82rem">${escHtml(l.username)}</td>
          <td><code style="font-size:.75rem;color:var(--wt-accent)">${escHtml(l.action)}</code></td>
          <td style="font-size:.78rem;color:var(--wt-muted)">${escHtml(l.resource_type)} <span style="color:var(--wt-border2)">#${escHtml((l.resource_id||'').slice(-8))}</span></td>
          <td style="font-size:.75rem;color:var(--wt-muted);font-family:monospace">${escHtml(l.ip_address||'—')}</td>
          <td style="font-size:.72rem;color:var(--wt-muted);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(JSON.stringify(l.details))}">${escHtml(JSON.stringify(l.details||{}).slice(0,100))}</td>
        </tr>`).join('');
      buildPagination(document.getElementById('auditPaginationBar'),d.pagination.page,d.pagination.pages,fetchPage);
    } catch(e){toast('Failed to load audit log: '+e.message,'error');}
  }
  fetchPage();
}

// ═══════════════════════════════════════════════════════════════════════════════
// SETTINGS
// ═══════════════════════════════════════════════════════════════════════════════
async function loadSettings() {
  try {
    const d=await API.get('/settings/'); if(!d) return;
    if(d.retention_raw_events_days) document.getElementById('s-raw-events').value=d.retention_raw_events_days;
    if(d.retention_incidents_days) document.getElementById('s-incidents').value=d.retention_incidents_days;
    if(d.retention_audit_log_days) document.getElementById('s-audit-log').value=d.retention_audit_log_days;
    if(d.email_alerts_enabled!==undefined) document.getElementById('s-email-enabled').checked=d.email_alerts_enabled;
    if(d.slack_alerts_enabled!==undefined) document.getElementById('s-slack-enabled').checked=d.slack_alerts_enabled;
    if(d.alert_min_severity) document.getElementById('s-min-severity').value=d.alert_min_severity;
    if(d.org_name) document.getElementById('s-org-name').value=d.org_name;
    if(d.org_contact_email) document.getElementById('s-contact-email').value=d.org_contact_email;
    if(d.auto_close_fp_days) document.getElementById('s-auto-close-fp').value=d.auto_close_fp_days;
  } catch {}
  document.getElementById('saveSettingsBtn')?.addEventListener('click',saveSettings);
}
async function saveSettings() {
  const payload={
    retention_raw_events_days:parseInt(document.getElementById('s-raw-events')?.value),
    retention_incidents_days:parseInt(document.getElementById('s-incidents')?.value),
    retention_audit_log_days:parseInt(document.getElementById('s-audit-log')?.value),
    email_alerts_enabled:document.getElementById('s-email-enabled')?.checked,
    slack_alerts_enabled:document.getElementById('s-slack-enabled')?.checked,
    alert_min_severity:document.getElementById('s-min-severity')?.value,
    org_name:document.getElementById('s-org-name')?.value,
    org_contact_email:document.getElementById('s-contact-email')?.value,
    auto_close_fp_days:parseInt(document.getElementById('s-auto-close-fp')?.value)||7,
  };
  try { await API.put('/settings/',payload); toast('Settings saved','success'); }
  catch(e){toast('Failed: '+e.message,'error');}
}
