# The following Python code could be utilized for sending emails for your automation results
# You could also attach your HTML, excel, text etc.. attachments 

def send_email(sender_mail, receiver_mail, mailSubject,attachment,smtpServer,smtpPort):

    import logging
    import os
    import json
    import sys
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from email.mime.base import MIMEBase
    from email import encoders


    parent_directory = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))


    # try:
    #     # Get configuration data from the config file
    #     with open(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.getcwd()))), 'conf', 'Config', 'config.json'), 'r') as config_reader:
    #         config_data = json.load(config_reader)
    # except Exception as error:
    #     print(f'(ERROR) - {str(error)}')


    try:
        # Create MIMEMultipart object
        msg = MIMEMultipart()
        msg['From'] = sender_mail
        msg['To'] = receiver_mail
        msg['Subject'] = mailSubject

        # Read HTML content from file and attach it
        # output_file_path = os.path.join(os.path.dirname(os.path.dirname(os.getcwd())), 'output', config_data['outputFileName'])
        with open(attachment, 'r') as html_reader:
            html_content = html_reader.read()

        msg.attach(MIMEText(html_content, 'html'))

        # Attach HTML content as a file
        # attach_file_path = os.path.join(os.path.dirname(os.path.dirname(os.getcwd())), 'output', config_data['outputFileName'])
        attach_payload = MIMEBase('application', 'octet-stream', Name=attachment)
        attach_payload['Content-Disposition'] = f'attachment; filename="{os.path.basename(attachment)}"'
        attach_payload.set_payload(html_content)
        encoders.encode_base64(attach_payload)
        msg.attach(attach_payload)
    except Exception as error:
        print(f'(ERROR) - {str(error)}')
        write_log(f'(ERROR) - {str(error)}')
        return

    try:
        # Connect to SMTP server and send email
        with smtplib.SMTP(smtpServer,smtpPort)as server:
            text = msg.as_string()
            server.sendmail(sender_mail, receiver_mail,text)
        print('Mail Sent Successfully')
        write_log(f'SUCCESS-Mail Sent Successfully')
    except Exception as error:
        print(f'(ERROR) - {str(error)}')
