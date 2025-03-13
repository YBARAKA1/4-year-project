import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

EMAIL_HOST = "mail.integral.co.ke"
EMAIL_PORT = 465
EMAIL_USER = "jeff@integral.co.ke"
EMAIL_PASSWORD = "Treadstone@4545"

def send_test_email():
    msg = MIMEMultipart()
    msg['From'] = EMAIL_USER
    msg['To'] = "jeffbarakag@gmail.com"
    msg['Subject'] = "Test Email"
    msg.attach(MIMEText("This is a test email.", 'plain'))

    try:
        server = smtplib.SMTP_SSL(EMAIL_HOST, EMAIL_PORT)  # Use SMTP_SSL for port 465
        server.login(EMAIL_USER, EMAIL_PASSWORD)
        server.sendmail(EMAIL_USER, "jeffbarakag@gmail.com", msg.as_string())
        server.quit()
        print("Email sent successfully!")
    except Exception as e:
        print(f"Failed to send email: {e}")

send_test_email()