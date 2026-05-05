import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# =============================
# EMAIL CONFIG
# =============================
EMAIL_ADDRESS = "22i14.briston@sjec.ac.in"
EMAIL_PASSWORD = "uwfgfipstdfvgwjg"  # App Password (no spaces)

# =============================
# SEND EMAIL FUNCTION
# =============================
def send_email_alert(subject, message):
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = EMAIL_ADDRESS
        msg['Subject'] = subject

        # Email body
        body = f"""
🚨 CYBER SECURITY ALERT 🚨

{message}

--- System Notification ---
"""
        msg.attach(MIMEText(body, 'plain'))

        # SMTP Setup
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()

        # Login
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)

        # Send Email
        server.sendmail(
            EMAIL_ADDRESS,
            EMAIL_ADDRESS,
            msg.as_string()
        )

        server.quit()

        print("✅ Email Alert Sent Successfully")

    except Exception as e:
        print("❌ Email Error:", e)