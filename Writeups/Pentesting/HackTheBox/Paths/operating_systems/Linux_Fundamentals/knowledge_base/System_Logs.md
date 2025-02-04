# System Logs

There are different types of system logs on Linux:
- Kernel logs
- System
- Authentication
- Application
- Security

**Kernel logs**
Contain information about hardware drivers, system calls, and kernel events.

They are stored in `/var/log/kern.log/`.

Can provide information about systemcrashes, resource limitations, and can help identify suspicious system calls and other activities to indicate the presence of a malware.

**System logs**
Informations about service starts and stops, login attempts, system reboots, etc. Stored in `/var/log/syslog/`.

**Authentication logs**
Information about user authentication attempts, successful and failed.

Stored in `/var/log/auth.log`.

**Application logs**
Have information about activities of apps runing in the system.

They are stored in their own files, such as `/var/log/apache2/error.log`. Access logs are of importance here.

**Security logs**
Are recorded in a variety of log files, depending on the app.
For example `fail2ban` stores them on `/var/log/fail2ban.log`.

Otehr more general logs can be stored in `/var/log/syslog/` or `/var/log/auth.log`.


