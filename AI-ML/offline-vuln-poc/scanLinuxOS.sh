#scanLinuxOS.sh

#!/bin/bash

# Linux System Security Scanner

# Run as root for complete information
 
OUTPUT_FILE="linux_system_scan_$(date +%Y%m%d_%H%M%S).csv"
 
echo "Starting Linux system scan..."

echo "Hostname,Category,Item,Version,Status,Port,Process,Risk_Level" > $OUTPUT_FILE
 
HOSTNAME=$(hostname)
 
# Installed Packages (RPM-based)

if command -v rpm &> /dev/null; then

    rpm -qa --queryformat '%{NAME},%{VERSION},%{VENDOR}\n' | while IFS=',' read -r name version vendor; do

        echo "$HOSTNAME,Package,$name,$version,Installed,,$name,Medium" >> $OUTPUT_FILE

    done

fi
 
# Installed Packages (DEB-based)

if command -v dpkg &> /dev/null; then

    dpkg-query -W -f='${Package},${Version},${Maintainer}\n' | while IFS=',' read -r name version maintainer; do

        echo "$HOSTNAME,Package,$name,$version,Installed,,$name,Medium" >> $OUTPUT_FILE

    done

fi
 
# Running Services

systemctl list-units --type=service --state=active --no-pager --plain | grep -v UNIT | while read -r line; do

    service=$(echo $line | awk '{print $1}')

    status=$(echo $line | awk '{print $2}')

    echo "$HOSTNAME,Service,$service,$status,Running,,$service,Low" >> $OUTPUT_FILE

done
 
# Open Ports

ss -tuln | grep LISTEN | while read -r line; do

    port=$(echo $line | awk '{print $5}' | sed 's/.*://')

    protocol=$(echo $line | awk '{print $1}')

    risk="Low"

    if [[ "$port" == "22" ]] || [[ "$port" == "80" ]] || [[ "$port" == "443" ]]; then

        risk="Medium"

    fi

    echo "$HOSTNAME,Port,$protocol,$port,Open,$port,,${risk}" >> $OUTPUT_FILE

done
 
# Running Processes

ps aux --no-headers | while read -r line; do

    process=$(echo $line | awk '{print $11}')

    pid=$(echo $line | awk '{print $2}')

    echo "$HOSTNAME,Process,$process,$pid,Running,,$process,Low" >> $OUTPUT_FILE

done
 
# Check for zombie processes

zombies=$(ps aux | grep -c '<defunct>')

if [ $zombies -gt 0 ]; then

    echo "$HOSTNAME,ZombieProcess,Found,$zombies,Active,,,High" >> $OUTPUT_FILE

fi
 
echo "Scan complete. Output saved to: $OUTPUT_FILE"

echo "Please upload this CSV file to the vulnerability analyzer."
 