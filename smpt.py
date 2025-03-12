import smtplib

EMAIL_HOST = "mail.integral.co.ke"  # Replace with your SMTP server
EMAIL_PORT = 465                # Replace with your SMTP port
EMAIL_USER = "jeff@integral.co.ke"
EMAIL_PASSWORD = "Treadstone@4545"

try:
    server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
    server.starttls()
    server.login(EMAIL_USER, EMAIL_PASSWORD)
    print("SMTP connection successful!")
    server.quit()
except Exception as e:
    print(f"SMTP connection failed: {e}")