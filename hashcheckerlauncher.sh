#!/bin/bash

# Enter full path to hashscan.py in both instances below
# Save and run this with cron (sudo crontab -e) e.g. @reboot /home/<your-user-name>/<this-file.sh>

python /PATH/TO/hashscan.py
while [ $? -ne 0 ]; do
    python /PATH/TO/hashscan.py
done
