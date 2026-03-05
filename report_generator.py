import html
import io
import datetime
import json
import textwrap
from reportlab.lib.pagesizes import letter, landscape
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

def generate_incident_pdf(log_data):
    """Generates a highly professional PDF Incident Report with deep forensics."""
    buffer = io.BytesIO()
    # Use Platypus for auto-formatting and wrapping
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    elements = []
    styles = getSampleStyleSheet()

    # Custom Text Styles
    title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=20, textColor=colors.darkblue, spaceAfter=5)
    sub_title_style = ParagraphStyle('SubTitleStyle', parent=styles['Heading2'], fontSize=14, textColor=colors.firebrick, spaceAfter=20)
    section_header = ParagraphStyle('SectionHeader', parent=styles['Heading3'], fontSize=12, textColor=colors.black, spaceBefore=15, spaceAfter=5)
    code_style = ParagraphStyle('CodeStyle', parent=styles['Normal'], fontName='Courier', fontSize=9, textColor=colors.black, leading=12)
    payload_style = ParagraphStyle('PayloadStyle', parent=code_style, textColor=colors.darkred)

    # 1. Header Section
    elements.append(Paragraph("<b>SentinelShield SOC</b>", title_style))
    elements.append(Paragraph("SECURITY INCIDENT REPORT", sub_title_style))

    # 2. Incident Overview Table
    elements.append(Paragraph("<b>Incident Overview</b>", section_header))
    overview_data = [
        ["Timestamp:", str(log_data.get('timestamp', 'N/A')), "Event ID:", f"#{log_data.get('id', 'N/A')}"],
        ["Source IP:", f"{log_data.get('ip_address', 'N/A')} ({log_data.get('country', 'Unknown')})", "Action:", str(log_data.get('action', 'N/A'))],
        ["Risk Score:", f"{log_data.get('risk_score', 'N/A')} / 100", "", ""]
    ]
    t_overview = Table(overview_data, colWidths=[80, 180, 80, 180])
    t_overview.setStyle(TableStyle([
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (2, 0), (2, -1), 'Helvetica-Bold'),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(t_overview)

    # 3. Threat Classification & Request Details
    elements.append(Paragraph("<b>Threat & Request Details</b>", section_header))
    
    # Safely escape URL so XML parser doesn't break on <script> tags
    safe_url = html.escape(str(log_data.get('url', 'N/A')))
    request_data = [
        ["Primary Vector:", Paragraph(f"<font color='red'><b>{log_data.get('attack_type', 'N/A')}</b></font>", styles['Normal'])],
        ["HTTP Method:", str(log_data.get('method', 'N/A'))],
        ["Target URL:", Paragraph(safe_url, styles['Normal'])]
    ]
    t_req = Table(request_data, colWidths=[90, 430])
    t_req.setStyle(TableStyle([
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(t_req)

    # 4. Captured HTTP Headers (Shaded Box)
    elements.append(Paragraph("<b>Captured HTTP Headers Extracts</b>", section_header))
    headers_raw = log_data.get('headers', '{}')
    header_lines = []
    try:
        if isinstance(headers_raw, str):
            headers_dict = json.loads(headers_raw)
        else:
            headers_dict = headers_raw
            
        for k, v in headers_dict.items():
            if k.lower() in ['cookie', 'authorization'] and len(str(v)) > 80:
                header_lines.append(f"<b>{k}:</b> [REDACTED FOR PDF LENGTH]")
            else:
                header_lines.append(f"<b>{k}:</b> {html.escape(str(v))}")
        if not header_lines:
            header_lines = ["No headers captured."]
    except:
        header_lines = [f"Raw Data: {html.escape(str(headers_raw)[:200])}..."]

    header_text = "<br/>".join(header_lines[:15])
    if len(header_lines) > 15:
        header_text += "<br/>... [Headers Truncated]"
        
    t_headers = Table([[Paragraph(header_text, code_style)]], colWidths=[520])
    t_headers.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.aliceblue), # Light blue box
        ('BOX', (0, 0), (-1, -1), 1, colors.lightblue),
        ('TOPPADDING', (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
    ]))
    elements.append(t_headers)

    # 5. Detected Payload (Shaded Box)
    elements.append(Paragraph("<b>Detected Payload Extract</b>", section_header))
    payload_raw = log_data.get('payload', 'None')
    if not payload_raw or payload_raw == 'None' or str(payload_raw).strip() == '':
        payload_text = "[ No body payload detected. Threat vector identified in URL parameters or HTTP Headers. ]"
    else:
        payload_text = html.escape(str(payload_raw)[:1500]) # Escape <script> tags
        if len(str(payload_raw)) > 1500:
            payload_text += " <br/>... [Payload Truncated]"

    t_payload = Table([[Paragraph(payload_text, payload_style)]], colWidths=[520])
    t_payload.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.mistyrose), # Light red box
        ('BOX', (0, 0), (-1, -1), 1, colors.lightcoral),
        ('TOPPADDING', (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
    ]))
    elements.append(t_payload)

    # Footer
    elements.append(Spacer(1, 30))
    elements.append(Paragraph("<i>Generated automatically by SentinelShield Advanced Web Application Firewall.</i>", ParagraphStyle('Footer', fontSize=8, textColor=colors.gray)))

    # Build the PDF Document
    doc.build(elements)
    buffer.seek(0)
    return buffer
def generate_global_pdf(stats, logs_data):
    """Generates a multi-page Global SOC summary PDF with a full ledger."""
    buffer = io.BytesIO()
    # Use Platypus landscape for wide tables spanning multiple pages
    doc = SimpleDocTemplate(buffer, pagesize=landscape(letter), rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
    elements = []
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=18, textColor=colors.darkblue, spaceAfter=12)
    elements.append(Paragraph("SentinelShield SOC - GLOBAL SECURITY POSTURE REPORT", title_style))
    
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    elements.append(Paragraph(f"<b>Report Generated:</b> {now}", styles['Normal']))
    elements.append(Spacer(1, 15))

    # Top Level Stats
    stats_html = f"""
    <b>Total Traffic Analysed:</b> {stats['total']} requests<br/>
    <b>Blocked Malicious Payloads:</b> {stats['blocked']} threats<br/>
    <b>Currently Active Detentions:</b> {stats['bans']} IPs
    """
    elements.append(Paragraph(stats_html, styles['Normal']))
    elements.append(Spacer(1, 20))
    
    elements.append(Paragraph("<b>Complete Incident Ledger:</b>", styles['Heading3']))
    elements.append(Spacer(1, 10))

    # Build Table Data
    table_data = [["ID", "TIMESTAMP", "SOURCE IP", "METHOD", "TARGET URL", "ATTACK VECTOR", "RISK"]]
    
    for r in logs_data:
        # Truncate URLs for the table so it doesn't break PDF width
        url = r['url']
        if len(url) > 45: url = url[:42] + "..."
        
        table_data.append([
            str(r['id']), 
            str(r['time']), 
            str(r['ip']), 
            str(r['method']), 
            url, 
            str(r['attack']), 
            str(r['score'])
        ])

    # Create Dynamic Table
    t = Table(table_data, colWidths=[40, 110, 100, 50, 240, 150, 40])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 1, colors.lightgrey),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.whitesmoke, colors.white])
    ]))
    
    elements.append(t)
    
    # Build the PDF (Automatically handles multi-page wrapping!)
    doc.build(elements)
    buffer.seek(0)
    return buffer