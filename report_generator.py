# report_generator.py
import io
import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors

def generate_incident_pdf(log_data):
    """Generates a PDF Incident Report for a specific attack."""
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    # Header
    c.setFont("Helvetica-Bold", 24)
    c.setFillColor(colors.darkblue)
    c.drawString(50, height - 60, "SentinelShield SOC")
    
    c.setFont("Helvetica", 14)
    c.setFillColor(colors.red)
    c.drawString(50, height - 85, "SECURITY INCIDENT REPORT")

    c.setStrokeColor(colors.black)
    c.line(50, height - 95, width - 50, height - 95)

    # Incident Summary
    c.setFont("Helvetica-Bold", 12)
    c.setFillColor(colors.black)
    c.drawString(50, height - 130, "Incident Details")
    
    c.setFont("Helvetica", 10)
    y_pos = height - 150
    details = [
        f"Timestamp: {log_data.get('timestamp')}",
        f"Event ID: #{log_data.get('id')}",
        f"Source IP: {log_data.get('ip_address')} ({log_data.get('country', 'Unknown')})",
        f"Action Taken: {log_data.get('action')}",
        f"Risk Score: {log_data.get('risk_score')} / 100"
    ]
    for detail in details:
        c.drawString(60, y_pos, detail)
        y_pos -= 20

    # Threat Vector
    y_pos -= 10
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y_pos, "Threat Classification")
    y_pos -= 20
    
    c.setFont("Helvetica", 10)
    c.setFillColor(colors.darkred)
    c.drawString(60, y_pos, f"Primary Vector: {log_data.get('attack_type')}")
    y_pos -= 30

    # Request Forensics
    c.setFont("Helvetica-Bold", 12)
    c.setFillColor(colors.black)
    c.drawString(50, y_pos, "HTTP Request Details")
    y_pos -= 20
    
    c.setFont("Helvetica", 10)
    c.drawString(60, y_pos, f"Method: {log_data.get('method')}")
    y_pos -= 20
    c.drawString(60, y_pos, f"Target URL: {log_data.get('url')}")
    y_pos -= 30

    # Payload Evidence
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y_pos, "Detected Payload Extract")
    y_pos -= 20
    
    c.setFont("Courier", 9)
    c.setFillColor(colors.darkblue)
    
    payload_raw = log_data.get('payload', 'None')
    if not payload_raw or payload_raw == 'None':
        payload_raw = "No body payload detected. Threat was likely in headers or URL."
        
    import textwrap
    wrapped_payload = textwrap.wrap(payload_raw, width=80)
    for line in wrapped_payload[:10]:
        c.drawString(60, y_pos, line)
        y_pos -= 15
        
    if len(wrapped_payload) > 10:
        c.drawString(60, y_pos, "... [Payload Truncated for PDF]")

    # Footer
    c.setFont("Helvetica-Oblique", 8)
    c.setFillColor(colors.gray)
    c.drawString(50, 40, "Generated automatically by SentinelShield Advanced Web Application Firewall.")

    c.showPage()
    c.save()
    buffer.seek(0)
    return buffer


def generate_global_pdf(stats):
    """Generates a Global SOC summary PDF instead of a CSV."""
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    c.setFont("Helvetica-Bold", 24)
    c.setFillColor(colors.darkblue)
    c.drawString(50, height - 60, "SentinelShield SOC")
    
    c.setFont("Helvetica", 14)
    c.setFillColor(colors.black)
    c.drawString(50, height - 85, "GLOBAL SECURITY POSTURE REPORT")

    c.setStrokeColor(colors.black)
    c.line(50, height - 95, width - 50, height - 95)
    
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.setFont("Helvetica", 10)
    c.drawString(50, height - 110, f"Report Generated: {now}")

    # Top Level Stats
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, height - 140, "Network Metrics Overview")
    
    c.setFont("Helvetica", 11)
    c.drawString(60, height - 160, f"Total Traffic Analysed: {stats['total']} requests")
    c.drawString(60, height - 180, f"Blocked Malicious Payloads: {stats['blocked']} threats")
    c.drawString(60, height - 200, f"Currently Active Detentions: {stats['bans']} IPs")

    # Attack Distribution
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, height - 240, "Threat Classification Distribution")
    y_pos = height - 260
    c.setFont("Helvetica", 10)
    
    if stats['attacks']:
        for attack, count in stats['attacks'].items():
            c.drawString(60, y_pos, f"- {attack}: {count} incidents")
            y_pos -= 15
    else:
        c.drawString(60, y_pos, "No attacks recorded in the current timeframe.")
        y_pos -= 15

    # Footer
    c.setFont("Helvetica-Oblique", 8)
    c.setFillColor(colors.gray)
    c.drawString(50, 40, "Generated automatically by SentinelShield Advanced Web Application Firewall.")

    c.showPage()
    c.save()
    buffer.seek(0)
    return buffer