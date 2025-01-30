# Linux Fundamentals

## 1. Systemd

Is a service used to start processes and scripts at a specific time.

Not just at a specific time, but with **Systemd** we can also specify specific events and trigger for a specific task.

Steps to do this:
1. Create a time 
2. Create a service
3. Activate the timer

### 1.1 Create a Timer

First we need to create a directory for the timer script:

```bash
sudo mkdir /etc/systemd/system/mytimer.timer.d
sudo vim /etc/systemd/system/mytimer.mytimer
```

The script that configures the timer must contain the following options: 
- [Unit]: specifies a description for the timer.
- [Timer]: specifies when to start and when to activate the timer.
- [Install]: where to install the timer.

```txt
# Mytimer.mytimer

[Unit]
Description=My Timer

[Timer]
OnBootSec=3min
OnUnitActiveSec=1hour

[Install]
WantedBy=timers.target
```

After we decide on how we want to run our script, for example: once after boot **OnBootSec** or regularly **OnUnitActiveSec**, next we need to create the **service**.

### 1.2 Create a Service

```bash
sudo vim /etc/systemd/system/mytimer.service
```

This is quite similar to the timer, we need a [Unit], [Service], [Install]

```text
[Unit]
Description=My Service

[Service]
ExecStart=/full/path/to/my/script.sh

[Install]
WantedBy=multi-user.target
```

The **multi-user.target** - the unit system activated when starting a normal multi-user mode. Defines the services that should be started on a normal system startup.

### 1.3 Reload Systemd

We have to let **systemd** include the changes.

```bash
sudo systemct daemon-reload
```

Then the service can be started manually or enable the autostart:

```bash
sudo systemctl start mytimer.timer
sudo systemctl enable mytimer.timer
```

## 2. Cron

Another tool to to schedule and automate processes, execute tasks at a specific time or intervals. 

We just need to create a script and tell the **cron daemon** to call it a specific time.

To do this we need to store the taks in **crontab** and tell the daemon when to run the tasks.

Structure:
[minutes] [hours] [day of the month] [month] [day of the week]

Example of a crontab:
```txt
# System update
0 */6 * * * /path/tp/update_software.sh

# Execute scripts
0 0 1 * * /path/to/scripts/run_scripts.sh

# Cleanup DB
0 0 * * 0 /path/to/scrpipts/clean_db.sh

# Backups
0 0 * * 7 /path/to/scripts/backup.sh
```

By 0 */6 in the hour column, it means that the update will be executed every six hours.

The task executed every 1st of the month, etc.

## 3. Systemd vs. Cron

Configuration is the key difference, as with Systemd you create a timer and services script that tells the OS when to run the task, and with Cron, you create a crontab file that tells the cron daemon when to run tasks.

