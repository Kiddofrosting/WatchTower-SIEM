"""
WatchTower SIEM - PDF Export Service
Generates professional PDF reports for incidents, events, and compliance summaries.
Uses reportlab (pure Python — no system dependencies needed in Docker).
"""

import io
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    BaseDocTemplate, Frame, HRFlowable, Image, PageBreak,
    PageTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
)
from reportlab.platypus.flowables import HRFlowable

# ── Color palette ─────────────────────────────────────────────────────────────
DARK       = colors.HexColor('#0A0E1A')
NAVY       = colors.HexColor('#0C1A35')
NAVY2      = colors.HexColor('#1A2E4A')
ACCENT     = colors.HexColor('#0080B3')
ACCENT_LT  = colors.HexColor('#E8F4FA')
TEXT       = colors.HexColor('#1A1A2E')
MUTED      = colors.HexColor('#5A6A7A')
BORDER     = colors.HexColor('#C5D5E5')
WHITE      = colors.white

SEV_COLORS = {
    'critical': (colors.HexColor('#FF1744'), colors.HexColor('#FFF0F0')),
    'high':     (colors.HexColor('#FF6D00'), colors.HexColor('#FFF3E0')),
    'medium':   (colors.HexColor('#F9A825'), colors.HexColor('#FFFDE7')),
    'low':      (colors.HexColor('#0097A7'), colors.HexColor('#E0F7FA')),
    'info':     (colors.HexColor('#5A6A7A'), colors.HexColor('#F5F7FA')),
}

STATUS_COLORS = {
    'open':           colors.HexColor('#FF1744'),
    'investigating':  colors.HexColor('#F9A825'),
    'contained':      colors.HexColor('#FF6D00'),
    'resolved':       colors.HexColor('#2E7D32'),
    'false_positive': colors.HexColor('#5A6A7A'),
    'closed':         colors.HexColor('#5A6A7A'),
}

# ── Styles ────────────────────────────────────────────────────────────────────
def make_styles():
    s = getSampleStyleSheet()
    base = dict(fontName='Helvetica', fontSize=10, leading=14, textColor=TEXT)

    styles = {
        'cover_title': ParagraphStyle('cover_title',
            fontName='Helvetica-Bold', fontSize=28, leading=34,
            textColor=WHITE, alignment=TA_LEFT),
        'cover_sub': ParagraphStyle('cover_sub',
            fontName='Helvetica', fontSize=13, leading=18,
            textColor=colors.HexColor('#A0BFDF'), alignment=TA_LEFT),
        'cover_meta': ParagraphStyle('cover_meta',
            fontName='Helvetica', fontSize=10, leading=14,
            textColor=colors.HexColor('#7A9ABF'), alignment=TA_LEFT),
        'section': ParagraphStyle('section',
            fontName='Helvetica-Bold', fontSize=14, leading=20,
            textColor=DARK, spaceBefore=16, spaceAfter=8,
            borderPad=4),
        'subsection': ParagraphStyle('subsection',
            fontName='Helvetica-Bold', fontSize=11, leading=15,
            textColor=NAVY, spaceBefore=10, spaceAfter=4),
        'body': ParagraphStyle('body', **base, spaceAfter=6),
        'body_muted': ParagraphStyle('body_muted', **{**base, 'textColor': MUTED}, spaceAfter=4),
        'label': ParagraphStyle('label',
            fontName='Helvetica-Bold', fontSize=8.5, leading=12,
            textColor=MUTED, spaceAfter=2),
        'value': ParagraphStyle('value',
            fontName='Helvetica', fontSize=10, leading=13,
            textColor=TEXT, spaceAfter=4),
        'code': ParagraphStyle('code',
            fontName='Courier', fontSize=8.5, leading=12,
            textColor=colors.HexColor('#1A1A8C'),
            backColor=colors.HexColor('#F0F2FF'),
            leftIndent=6, rightIndent=6,
            borderPad=4, spaceAfter=4),
        'mitre': ParagraphStyle('mitre',
            fontName='Helvetica-Bold', fontSize=8, leading=10,
            textColor=colors.HexColor('#5B21B6'),
            backColor=colors.HexColor('#EDE9FE'),
            borderPad=3),
        'note_author': ParagraphStyle('note_author',
            fontName='Helvetica-Bold', fontSize=9, leading=12,
            textColor=ACCENT),
        'note_time': ParagraphStyle('note_time',
            fontName='Helvetica', fontSize=8, leading=10,
            textColor=MUTED),
        'note_text': ParagraphStyle('note_text',
            fontName='Helvetica', fontSize=9.5, leading=13,
            textColor=TEXT, spaceAfter=2),
        'tl_action': ParagraphStyle('tl_action',
            fontName='Helvetica-Bold', fontSize=9.5, leading=12, textColor=TEXT),
        'tl_detail': ParagraphStyle('tl_detail',
            fontName='Helvetica', fontSize=9, leading=12, textColor=MUTED),
        'tl_meta': ParagraphStyle('tl_meta',
            fontName='Helvetica', fontSize=8, leading=10, textColor=MUTED),
        'footer': ParagraphStyle('footer',
            fontName='Helvetica', fontSize=8, leading=10,
            textColor=MUTED, alignment=TA_CENTER),
        'page_num': ParagraphStyle('page_num',
            fontName='Helvetica', fontSize=8, leading=10,
            textColor=ACCENT, alignment=TA_RIGHT),
        'ai_body': ParagraphStyle('ai_body',
            fontName='Helvetica', fontSize=9.5, leading=13,
            textColor=TEXT, spaceAfter=4),
        'ai_heading': ParagraphStyle('ai_heading',
            fontName='Helvetica-Bold', fontSize=10.5, leading=14,
            textColor=colors.HexColor('#5B21B6'), spaceBefore=8, spaceAfter=4),
    }
    return styles

# ── Utility builders ──────────────────────────────────────────────────────────
def sp(n=6): return Spacer(1, n)
def hr(color=BORDER, thickness=0.5): return HRFlowable(width='100%', thickness=thickness, color=color, spaceAfter=6, spaceBefore=4)

def sev_badge_table(severity, styles):
    sev = (severity or 'info').lower()
    col, bg = SEV_COLORS.get(sev, SEV_COLORS['info'])
    icon = {'critical':'★','high':'▲','medium':'◆','low':'●','info':'○'}.get(sev,'●')
    t = Table([[f' {icon}  {sev.upper()} ']], colWidths=[3*cm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), bg),
        ('TEXTCOLOR',  (0,0), (-1,-1), col),
        ('FONTNAME',   (0,0), (-1,-1), 'Helvetica-Bold'),
        ('FONTSIZE',   (0,0), (-1,-1), 9),
        ('ALIGN',      (0,0), (-1,-1), 'CENTER'),
        ('VALIGN',     (0,0), (-1,-1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0,0), (-1,-1), [bg]),
        ('BOX',        (0,0), (-1,-1), 0.5, col),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING',(0,0),(-1,-1), 4),
    ]))
    return t

def status_badge_table(status, styles):
    col = STATUS_COLORS.get((status or '').lower(), MUTED)
    t = Table([[f' {(status or "unknown").replace("_"," ").upper()} ']], colWidths=[3.5*cm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F5F7FA')),
        ('TEXTCOLOR',  (0,0), (-1,-1), col),
        ('FONTNAME',   (0,0), (-1,-1), 'Helvetica-Bold'),
        ('FONTSIZE',   (0,0), (-1,-1), 9),
        ('ALIGN',      (0,0), (-1,-1), 'CENTER'),
        ('BOX',        (0,0), (-1,-1), 0.8, col),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING',(0,0),(-1,-1), 4),
    ]))
    return t

def kv_table(rows, col_widths=None, styles_dict=None):
    """Two-column key-value table."""
    if col_widths is None:
        col_widths = [4.5*cm, 12*cm]
    data = []
    for k, v in rows:
        data.append([
            Paragraph(str(k), styles_dict['label']),
            Paragraph(str(v) if v else '—', styles_dict['value'])
        ])
    t = Table(data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ('VALIGN',      (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING',  (0,0), (-1,-1), 5),
        ('BOTTOMPADDING',(0,0),(-1,-1), 5),
        ('LEFTPADDING', (0,0), (-1,-1), 0),
        ('RIGHTPADDING',(0,0), (-1,-1), 6),
        ('LINEBELOW',   (0,0), (-1,-1), 0.3, BORDER),
    ]))
    return t

def section_header(title, styles_dict):
    return [
        Paragraph(title, styles_dict['section']),
        HRFlowable(width='100%', thickness=1.5, color=ACCENT, spaceAfter=8, spaceBefore=0),
    ]

def fmt_dt(iso_str):
    if not iso_str: return '—'
    try:
        dt = datetime.fromisoformat(iso_str.replace('Z','+00:00'))
        return dt.strftime('%d %b %Y  %H:%M:%S UTC')
    except Exception:
        return str(iso_str)

# ── Cover page ────────────────────────────────────────────────────────────────
def build_cover(incident, styles_dict, org_name='WatchTower SIEM'):
    sev = (incident.get('severity') or 'info').lower()
    sev_col, sev_bg = SEV_COLORS.get(sev, SEV_COLORS['info'])

    # Dark header block
    cover_table = Table([
        [Paragraph('SECURITY INCIDENT REPORT', styles_dict['cover_meta'])],
        [Paragraph(incident.get('title', 'Untitled Incident'), styles_dict['cover_title'])],
        [Spacer(1, 8)],
        [Paragraph(f"Incident ID: {incident.get('_id','—')[:24]}…", styles_dict['cover_meta'])],
        [Paragraph(f"Generated: {fmt_dt(datetime.now(timezone.utc).isoformat())}", styles_dict['cover_meta'])],
        [Paragraph(f"Organization: {org_name}", styles_dict['cover_meta'])],
    ], colWidths=[17*cm])

    cover_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), DARK),
        ('TOPPADDING',    (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('LEFTPADDING',   (0,0), (-1,-1), 20),
        ('RIGHTPADDING',  (0,0), (-1,-1), 20),
    ]))

    # Severity strip under cover
    sev_label = f"  {'★' if sev=='critical' else '▲' if sev=='high' else '◆' if sev=='medium' else '●'}  SEVERITY: {sev.upper()}  "
    sev_strip = Table([[sev_label]], colWidths=[17*cm])
    sev_strip.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,-1), sev_col),
        ('TEXTCOLOR',     (0,0), (-1,-1), WHITE),
        ('FONTNAME',      (0,0), (-1,-1), 'Helvetica-Bold'),
        ('FONTSIZE',      (0,0), (-1,-1), 11),
        ('ALIGN',         (0,0), (-1,-1), 'LEFT'),
        ('TOPPADDING',    (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('LEFTPADDING',   (0,0), (-1,-1), 20),
    ]))

    # Quick-facts grid
    status = incident.get('status','—')
    stat_col = STATUS_COLORS.get(status, MUTED)
    facts = [
        ['HOSTNAME',       'STATUS',      'RULE',           'EVENTS'],
        [
            incident.get('hostname','—'),
            status.replace('_',' ').upper(),
            incident.get('rule_name','—')[:30],
            str(incident.get('event_count', 0))
        ],
        ['CATEGORY', 'ASSIGNED TO', 'CREATED', 'RESOLVED'],
        [
            (incident.get('category') or '—').replace('_',' '),
            incident.get('assigned_to') or 'Unassigned',
            fmt_dt(incident.get('created_at')),
            fmt_dt(incident.get('resolved_at')) if incident.get('resolved_at') else '—'
        ],
    ]
    facts_table = Table(facts, colWidths=[4.25*cm]*4)
    facts_table.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,-1), colors.HexColor('#F5F7FA')),
        ('BACKGROUND',    (0,0), (-1,0), NAVY),
        ('BACKGROUND',    (0,2), (-1,2), NAVY),
        ('TEXTCOLOR',     (0,0), (-1,0), WHITE),
        ('TEXTCOLOR',     (0,2), (-1,2), WHITE),
        ('TEXTCOLOR',     (0,1), (-1,1), TEXT),
        ('TEXTCOLOR',     (0,3), (-1,3), TEXT),
        ('FONTNAME',      (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTNAME',      (0,2), (-1,2), 'Helvetica-Bold'),
        ('FONTNAME',      (0,1), (-1,1), 'Helvetica'),
        ('FONTNAME',      (0,3), (-1,3), 'Helvetica'),
        ('FONTSIZE',      (0,0), (-1,-1), 8.5),
        ('ALIGN',         (0,0), (-1,-1), 'LEFT'),
        ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING',    (0,0), (-1,-1), 7),
        ('BOTTOMPADDING', (0,0), (-1,-1), 7),
        ('LEFTPADDING',   (0,0), (-1,-1), 8),
        ('GRID',          (0,0), (-1,-1), 0.4, BORDER),
    ]))

    return [cover_table, sev_strip, sp(16), facts_table, sp(12)]

# ── MITRE tags row ────────────────────────────────────────────────────────────
def build_mitre_section(incident, styles_dict):
    techniques = incident.get('mitre_technique', [])
    tactics = incident.get('mitre_tactic', [])
    if not techniques and not tactics:
        return []

    items = []
    for t in techniques:
        items.append(Paragraph(f' {t} ', styles_dict['mitre']))
    for t in tactics:
        tac_style = ParagraphStyle('tac', parent=styles_dict['mitre'],
            textColor=colors.HexColor('#0369A1'),
            backColor=colors.HexColor('#E0F2FE'))
        items.append(Paragraph(f' {t} ', tac_style))

    # Arrange in a wrapping row table
    cols = min(len(items), 5)
    if cols == 0: return []
    rows = [items[i:i+cols] for i in range(0, len(items), cols)]
    for row in rows:
        while len(row) < cols:
            row.append(Paragraph('', styles_dict['body']))

    t = Table(rows, colWidths=[3.4*cm]*cols)
    t.setStyle(TableStyle([
        ('TOPPADDING',    (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ('LEFTPADDING',   (0,0), (-1,-1), 2),
        ('RIGHTPADDING',  (0,0), (-1,-1), 8),
        ('VALIGN',        (0,0), (-1,-1), 'MIDDLE'),
    ]))
    return [t, sp(8)]

# ── Notes section ─────────────────────────────────────────────────────────────
def build_notes(notes, styles_dict):
    if not notes:
        return [Paragraph('No analyst notes recorded.', styles_dict['body_muted'])]

    items = []
    for note in notes:
        author = note.get('author', 'Unknown')
        created = fmt_dt(note.get('created_at', ''))
        text = note.get('text', '')

        note_block = Table([
            [
                Paragraph(f'👤 {author}', styles_dict['note_author']),
                Paragraph(created, styles_dict['note_time'])
            ],
            [Paragraph(text, styles_dict['note_text']), ''],
        ], colWidths=[8.5*cm, 8.5*cm])
        note_block.setStyle(TableStyle([
            ('BACKGROUND',    (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
            ('BACKGROUND',    (0,0), (-1,0), colors.HexColor('#EFF6FF')),
            ('BOX',           (0,0), (-1,-1), 0.5, BORDER),
            ('LINEBELOW',     (0,0), (-1,0), 0.5, BORDER),
            ('TOPPADDING',    (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('LEFTPADDING',   (0,0), (-1,-1), 8),
            ('SPAN',          (0,1), (-1,1)),
            ('VALIGN',        (0,0), (-1,-1), 'TOP'),
        ]))
        items.append(KeepTogether([note_block, sp(6)]))

    return items

# ── Timeline ──────────────────────────────────────────────────────────────────
def build_timeline(timeline, styles_dict):
    if not timeline:
        return [Paragraph('No timeline entries recorded.', styles_dict['body_muted'])]

    rows = [['Time', 'Action', 'Actor', 'Detail']]
    for entry in reversed(timeline):
        rows.append([
            Paragraph(fmt_dt(entry.get('timestamp','')), styles_dict['tl_meta']),
            Paragraph((entry.get('action','') or '').replace('_',' '), styles_dict['tl_action']),
            Paragraph(entry.get('actor','—'), styles_dict['tl_detail']),
            Paragraph(entry.get('detail','') or '', styles_dict['tl_detail']),
        ])

    t = Table(rows, colWidths=[3.5*cm, 3.5*cm, 3*cm, 7*cm])
    style = [
        ('BACKGROUND',    (0,0), (-1,0), NAVY),
        ('TEXTCOLOR',     (0,0), (-1,0), WHITE),
        ('FONTNAME',      (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE',      (0,0), (-1,-1), 8.5),
        ('GRID',          (0,0), (-1,-1), 0.3, BORDER),
        ('ROWBACKGROUNDS',(0,1), (-1,-1), [WHITE, colors.HexColor('#F8FAFC')]),
        ('TOPPADDING',    (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING',   (0,0), (-1,-1), 6),
        ('VALIGN',        (0,0), (-1,-1), 'TOP'),
    ]
    t.setStyle(TableStyle(style))
    return [t]

# ── AI Remediation ────────────────────────────────────────────────────────────
def build_ai_remediation(ai_text, styles_dict):
    if not ai_text:
        return [Paragraph('AI remediation has not been generated for this incident.', styles_dict['body_muted'])]

    # Simple markdown-to-paragraphs conversion
    items = []
    for line in ai_text.split('\n'):
        line = line.strip()
        if not line:
            items.append(sp(4))
        elif line.startswith('## ') or line.startswith('# '):
            items.append(Paragraph(line.lstrip('#').strip(), styles_dict['ai_heading']))
        elif line.startswith('- ') or line.startswith('* '):
            items.append(Paragraph(f'• {line[2:]}', styles_dict['ai_body']))
        elif line.startswith('```'):
            pass  # skip code fences
        else:
            # Bold handling: **text**
            text = line.replace('**', '<b>', 1)
            while '**' in text:
                text = text.replace('**', '</b>', 1)
            items.append(Paragraph(text, styles_dict['ai_body']))

    return items

# ── Events table ──────────────────────────────────────────────────────────────
def build_events_table(events, styles_dict):
    if not events:
        return [Paragraph('No triggering events available.', styles_dict['body_muted'])]

    rows = [['Timestamp', 'Event ID', 'Category', 'Severity', 'User', 'Process / Source']]
    for e in events[:50]:  # cap at 50 events in PDF
        sev = (e.get('severity') or 'info').lower()
        sev_col, _ = SEV_COLORS.get(sev, SEV_COLORS['info'])
        rows.append([
            Paragraph(fmt_dt(e.get('timestamp','')), styles_dict['tl_meta']),
            Paragraph(str(e.get('event_id','')), styles_dict['value']),
            Paragraph((e.get('category') or '').replace('_',' '), styles_dict['body_muted']),
            Paragraph(sev.upper(), ParagraphStyle('sv', fontName='Helvetica-Bold', fontSize=8, textColor=sev_col)),
            Paragraph(str(e.get('subject_username') or e.get('target_username') or '—'), styles_dict['body_muted']),
            Paragraph(str(e.get('process_name') or e.get('source_ip') or '—')[:40], styles_dict['body_muted']),
        ])

    t = Table(rows, colWidths=[3.2*cm, 1.8*cm, 3*cm, 1.8*cm, 3*cm, 4.2*cm])
    t.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,0), NAVY),
        ('TEXTCOLOR',     (0,0), (-1,0), WHITE),
        ('FONTNAME',      (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE',      (0,0), (-1,-1), 8),
        ('GRID',          (0,0), (-1,-1), 0.3, BORDER),
        ('ROWBACKGROUNDS',(0,1), (-1,-1), [WHITE, colors.HexColor('#F8FAFC')]),
        ('TOPPADDING',    (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING',   (0,0), (-1,-1), 5),
        ('VALIGN',        (0,0), (-1,-1), 'TOP'),
    ]))
    return [t]

# ── Page template with header/footer ─────────────────────────────────────────
class WatchTowerDocTemplate(BaseDocTemplate):
    def __init__(self, filename, incident_id='', org_name='WatchTower SIEM', **kw):
        super().__init__(filename, **kw)
        self.incident_id = incident_id
        self.org_name = org_name
        self.styles_dict = make_styles()
        frame = Frame(
            self.leftMargin, self.bottomMargin,
            self.width, self.height,
            id='normal', showBoundary=0
        )
        template = PageTemplate(id='watchtower', frames=[frame],
                                onPage=self._on_page)
        self.addPageTemplates([template])

    def _on_page(self, canvas, doc):
        canvas.saveState()
        w, h = A4

        # Header bar
        canvas.setFillColor(DARK)
        canvas.rect(0, h - 1.2*cm, w, 1.2*cm, fill=1, stroke=0)
        canvas.setFillColor(ACCENT)
        canvas.rect(0, h - 1.2*cm, 0.4*cm, 1.2*cm, fill=1, stroke=0)
        canvas.setFont('Helvetica-Bold', 8.5)
        canvas.setFillColor(WHITE)
        canvas.drawString(1.2*cm, h - 0.78*cm, '🗼 WatchTower SIEM — Incident Report')
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(colors.HexColor('#7A9ABF'))
        canvas.drawRightString(w - 1.5*cm, h - 0.78*cm, f'ID: {self.incident_id[:16]}…  |  {self.org_name}')

        # Footer bar
        canvas.setFillColor(colors.HexColor('#F5F7FA'))
        canvas.rect(0, 0, w, 0.9*cm, fill=1, stroke=0)
        canvas.setStrokeColor(BORDER)
        canvas.setLineWidth(0.5)
        canvas.line(0, 0.9*cm, w, 0.9*cm)
        canvas.setFont('Helvetica', 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(1.5*cm, 0.32*cm, f'CONFIDENTIAL — Generated {datetime.now().strftime("%d %b %Y %H:%M UTC")} — WatchTower SIEM')
        canvas.setFillColor(ACCENT)
        canvas.drawRightString(w - 1.5*cm, 0.32*cm, f'Page {doc.page}')

        canvas.restoreState()


# ── Main export function ───────────────────────────────────────────────────────
def generate_incident_pdf(incident: dict, events: list = None,
                          org_name: str = 'WatchTower SIEM') -> bytes:
    """
    Generate a professional PDF report for a single incident.
    Returns raw PDF bytes.
    """
    buf = io.BytesIO()
    doc = WatchTowerDocTemplate(
        buf,
        incident_id=str(incident.get('_id', '')),
        org_name=org_name,
        pagesize=A4,
        topMargin=1.8*cm,
        bottomMargin=1.5*cm,
        leftMargin=1.5*cm,
        rightMargin=1.5*cm,
    )
    styles = doc.styles_dict
    story = []

    # ── Cover ──────────────────────────────────────────────────────────────
    story.extend(build_cover(incident, styles, org_name))
    story.append(hr(ACCENT, 1.5))
    story.append(sp(8))

    # ── Description ────────────────────────────────────────────────────────
    story.extend(section_header('Incident Description', styles))
    story.append(Paragraph(incident.get('description', 'No description provided.'), styles['body']))
    story.append(sp(8))

    # ── MITRE ATT&CK ───────────────────────────────────────────────────────
    mitre = build_mitre_section(incident, styles)
    if mitre:
        story.extend(section_header('MITRE ATT&CK Mapping', styles))
        story.extend(mitre)

    # ── Full Incident Metadata ─────────────────────────────────────────────
    story.extend(section_header('Incident Metadata', styles))
    story.append(kv_table([
        ('Incident ID',    incident.get('_id', '—')),
        ('Title',          incident.get('title', '—')),
        ('Detection Rule', incident.get('rule_name', '—')),
        ('Severity',       (incident.get('severity') or '—').upper()),
        ('Category',       (incident.get('category') or '—').replace('_', ' ').title()),
        ('Status',         (incident.get('status') or '—').replace('_', ' ').upper()),
        ('Hostname',       incident.get('hostname', '—')),
        ('Assigned To',    incident.get('assigned_to') or 'Unassigned'),
        ('Event Count',    str(incident.get('event_count', 0))),
        ('Created At',     fmt_dt(incident.get('created_at'))),
        ('Updated At',     fmt_dt(incident.get('updated_at'))),
        ('Resolved At',    fmt_dt(incident.get('resolved_at')) if incident.get('resolved_at') else '—'),
        ('False Positive', incident.get('false_positive_reason') or '—'),
        ('Resolution Notes', incident.get('resolution_notes') or '—'),
    ], col_widths=[4.5*cm, 12*cm], styles_dict=styles))
    story.append(sp(10))

    # ── AI Remediation ─────────────────────────────────────────────────────
    story.append(PageBreak())
    story.extend(section_header('AI-Powered Remediation Guidance', styles))
    story.extend(build_ai_remediation(incident.get('ai_remediation'), styles))
    story.append(sp(10))

    # ── Analyst Notes ──────────────────────────────────────────────────────
    story.extend(section_header('Analyst Notes', styles))
    story.extend(build_notes(incident.get('analyst_notes', []), styles))
    story.append(sp(10))

    # ── Timeline ───────────────────────────────────────────────────────────
    story.extend(section_header('Incident Timeline', styles))
    story.extend(build_timeline(incident.get('timeline', []), styles))
    story.append(sp(10))

    # ── Triggering Events ──────────────────────────────────────────────────
    if events:
        story.append(PageBreak())
        story.extend(section_header(f'Triggering Events ({len(events)} shown)', styles))
        story.extend(build_events_table(events, styles))

    doc.build(story)
    return buf.getvalue()
