import os
import logging
from datetime import datetime
import paramiko
import sys
import win32
import json

from Scripts.Microbots.logBot import write_log

today_date = datetime.now().strftime("%d-%m-%Y")

parent_directory = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))


try:
    conf_path = os.path.join(parent_directory, "Conf", "config", "config.json")
    with open(conf_path, 'r') as config_reader:
        data = json.load(config_reader)
except Exception as error:
    print(f'(ERROR) - {str(error)}')
    write_log(status="ERROR", message=f"An error occurred: {str(error)}")

script_path = os.path.join(parent_directory, "Scripts")
sys.path.append(script_path)
logFilePath = os.path.join(parent_directory, "log")
output_folder_path = os.path.join(parent_directory, "Output")
sys.path.append(output_folder_path)
os.makedirs(output_folder_path, exist_ok=True)
server_list_file = os.path.join(parent_directory, 'Input', 'servers.txt')

from Scripts.Microbots.cred import get_cred
from Scripts.Microbots.license import license_validation
from Scripts.Microbots.email_bot import send_email


# Function to execute a command on the remote server
def execute_command(ssh, command):
    stdin, stdout, stderr = ssh.exec_command(command)
    if stdout:
        write_log(status="SUCCESS", message=f"executing the {command}-{stdout}")
    else:
        write_log(status="ERROR", message=f"An error occurred: {command}-{stderr}")
    return stdout.read().decode("utf-8")


def read_servers_from_file(file_path):
    servers = []
    try:
        with open(file_path, 'r') as file:
            servers = file.read().splitlines()
    except FileNotFoundError:
        write_log(status="ERROR", message=f"File not found: {file_path}")
        print(f"File not found: {file_path}")
    except Exception as e:
        write_log(status="ERROR", message=f"File not found: {e}")
        print(f"An error occurred: {e}")

    return servers


# Specify the commands to be executed
commands = [
    "hostname",
    "uptime",
    "sar 1 5",
    "vmstat",
    "df",
    "iostat -d 1 5"
]

# Create an empty list to store results
results = []

# Loop through each server
try:
    if license_validation():
        print(f"license is valid")
        write_log(status="SUCCESS", message=f"license is valid")
        server_list = read_servers_from_file(server_list_file)
        for server in server_list:
            print(f"Connecting to {server}...")
            write_log(status="SUCCESS", message=f"Connecting to {server}...")
            # Create an SSH client
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            try:
                # Assuming credentials are stored in the servers.txt file
                linux_username, linux_password = get_cred(server)

                # Connect to the server
                ssh.connect(server, username=linux_username, password=linux_password)

                # Execute each command and store the output
                server_results = {'Server': server, 'Results': []}
                for command in commands:
                    output = execute_command(ssh, command)
                    server_results['Results'].append({'Command': command, 'Output': output.strip()})

                results.append(server_results)

            except Exception as e:
                print(f"Error connecting to {server}: {str(e)}")
                write_log(status="ERROR", message=f"Error connecting to {server}: {str(e)}")
            finally:
                # Close the SSH connection
                ssh.close()

except Exception as e:
    print(f"An error occurred: {e}")
    write_log(status="ERROR", message=f"An error occurred: {e}")

# Generate HTML content
html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AIX Capacity Report </title>
    <style>
        body {
            background-color: #AED6F1;
            background: rgb(255, 218, 253);
            background: linear-gradient(90deg, rgba(255, 218, 253, 1) 0%, rgba(217, 217, 255, 1) 52%, rgba(195, 241, 251, 1) 100%);
        }

        h1 {
            color: #000;
            text-shadow: 0 0 3px #fff, 0 0 5px #000;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        h2 {
            color: #000;
            text-shadow: 0 0 5px #fff, 0 0 3px #000;
        }

        table {
            border: 2px solid #000;
            width: 100%;
            margin-bottom: 20px;
        }

        th, td {
            border: 1px solid #000;
            padding: 8px;
            text-align: left;
        }

        th {
            background-color:#85C1E9 ;
            text-align: center;
        }

        .server-th {
            background-color:rgba(52, 152, 219, 0.5); /* Change to the desired color */
            text-align: left;
            width: 17%;
            color:#000;
            text-shadow: 0 0 1px #000, 0 0 1px #000;

        }
    </style>
</head>
<body>
    <h1>AIX Capacity Report</h1>
    
"""
html_content += f"<h2>Report Date: {today_date}</h2>"
# Add tables for each server's SSH connection output
for result in results:
    html_content += f"<table>"
    html_content += f"<tr><h2 class='server-th' colspan='3'>Server: {result['Server']}</h2></tr>"
    html_content += f"<tr><th>Command</th><th>Output</th></tr>"
    for entry in result['Results']:
        html_content += "<tr>"
        html_content += f"<td>{entry['Command']}</td>"

        # Format output as a table
        formatted_output = "<table border='1'>"
        lines = entry['Output'].splitlines()
        for line in lines:
            columns = line.split()
            formatted_output += "<tr>"
            for column in columns:
                formatted_output += f"<td>{column}</td>"
            formatted_output += "</tr>"
        formatted_output += "</table>"

        html_content += f"<td>{formatted_output}</td>"
        html_content += "</tr>"
    html_content += "</table>"

html_content += """
</body>
</html>
"""

# Write content to an HTML file
output_file_path = os.path.join(output_folder_path, "AIX_Capacity_Result.html")
with open(output_file_path, 'w') as html_file:
    try:
        html_file.write(html_content)
        print(f"AIX_Capacity_Result.html has been generated.")
        write_log(status="SUCCESS", message="AIX_Capacity_Result.html has been generated.")
        attachment_file = output_file_path
        sender_mail = data['sender_email']
        receiver_mail = data['receiver_email']
        mailSubject = data['subject']
        smtpServer = data['smtp_server']
        smtpPort = data['smtp_port']
        send_email(sender_mail, receiver_mail, mailSubject, attachment_file, smtpServer, smtpPort)
    except Exception as error:
        print(f"Error occurred: {error}")
        write_log(status="ERROR", message=f"Error occurred: {error}")
