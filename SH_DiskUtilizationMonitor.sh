# The following code is responsible to capture the Disk utilization on various list of linux servers and creating a HTML file.
# The list of servers needs to be provided in /var/autoheal/housekeeping/servers.txt


#!/bin/bash

 
output_file="/var/autoheal/housekeeping/disk_util.html"
#private_key="/home/ec2-user/linux_vv.pem"  # Replace with the actual path to your private key file
input_file="/var/autoheal/housekeeping/servers.txt"
recipient_email=""


# Function to check server status and generate HTML
function check_server {
    hostname=$1
    #status=$(timeout 30s ssh -i "$private_key" -q -o BatchMode=yes -o ConnectTimeout=5 "$hostname" exit && echo "OK" || echo "Failed")
    status=$(ssh -q -o BatchMode=yes -o ConnectTimeout=5 "$hostname" exit && echo "OK" || echo "Failed")
    if [ "$status" == "OK" ]; then
        echo "<tr>
                 <td style='height: 40px; background-color:lavender;'>
                 <strong>$hostname</strong>
                 </td>
                 <td style='color:black; background-color:lightgreen; height: 40px;'>
                 <strong>$status</strong>
                 </td>
              </tr>" >> "$output_file"
        ##checking the disk utlization %
        #utilization_before=$(df -h / | awk 'NR==2{print $5}' | tr -d '%')
        #utilization_before=$(ssh -i "$private_key" "$hostname" "df -h / | awk 'NR==2{print \$5}' | tr -d '%'")
        utilization_before=$(ssh "$hostname" "df -h / | awk 'NR==2{print \$5}' | tr -d '%'")

        echo "Disk Utilization Before on $hostname: $utilization_before%"
 
        # Check if utilization is greater than 85%
        if [ "$utilization_before" -gt 85 ]; then
           #removing log files that were last modified more than 7 days ago
           echo "<td style='background-color:lightcoral; height: 40px;'>$utilization_before%</td>" >> "$output_file"
           ssh "$hostname" "find /var/log -type f -name '*.log' -mtime +7 -exec rm {} \;"
           #ssh -i "$private_key" "$hostname" "sudo find /var/log -type f -name '*.py' -mtime 0 -exec rm {} \;"
        else
           echo "<td style='background-color:lightgreen; height: 40px;'>$utilization_before%</td>" >> "$output_file"
        fi

        #checking the disk utlization % after removing logs
        #utilization_after=$(df -h / | awk 'NR==2{print $5}' | tr -d '%')
        #utilization_after=$(ssh -i "$private_key" "$hostname" "df -h / | awk 'NR==2{print \$5}' | tr -d '%'")
        utilization_after=$(ssh "$hostname" "df -h / | awk 'NR==2{print \$5}' | tr -d '%'")

        echo "Disk Utilization After on $hostname: $utilization_after%"
        echo "<td style='background-color:lightgreen; height: 40px;'>$utilization_after%</td></tr>" >> "$output_file"
    else
         echo"<tr style='background-color:lightcoral;'>
            <td style='height: 40px; background-color:lavender;'><strong>$hostname</strong></td>
            <td style='color:black; background-color:lightcoral; height: 40px;'><strong>$status</strong></td>
            <td style='background-color:lightcoral; height: 40px;'>N/A</td>
            <td style='background-color:lightcoral; height: 40px;'>N/A</td>
          </tr>" >> "$output_file"

    fi
}
 

mkdir -p /var/autoheal/housekeeping
 
# Add a header to the HTML file
echo "<html><head><title>Server Status Report</title></head><body>" > "$output_file"
echo "<h1>FileSystem HouseKeeping Report</h1>" >> "$output_file"
echo "<table border='1' style='border-collapse: collapse;'>
<tr>
  <th style='color:black; background-color:yellow; width: 100px; height: 40px;'> &nbsp; IP Address &nbsp; </th>
  <th style='color:black; background-color:yellow; width: 70px; height: 40px;'> &nbsp; Status &nbsp; </th>
  <th style='color:black; background-color:yellow; width: 70px; height: 40px;'> &nbsp; Disk Utilization Before &nbsp; </th>
  <th style='color:black; background-color:yellow; width: 70px; height: 40px;'> &nbsp; Disk Utilization After &nbsp; </th>
</tr>" >> "$output_file"

 

for ip_address in $(cat "$input_file"); do
    check_server "$ip_address"
done

echo "</table></body></html>" >> "$output_file"
echo "Filesystem Housekeeping report generated at: $output_file"

# Email the report
mail_subject="Filesystem Housekeeping report"
uuencode "$output_file" "disk_util.html" | mail -v -s "$mail_subject" "$recipient_email"
echo "Filesystem Housekeeping report generated and emailed to: $recipient_email"
