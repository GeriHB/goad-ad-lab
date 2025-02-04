# Challenge

What is the Type of the service of the "dconf.service"?

# Solution

First we need to find all files related to this service.

We do this by using the `find` command:

```bash
find / -name "dconf.service" -type f 2>/dev/null
```

This commands searches in the `root` directory and all of its subdirectories for files containing `dconf.service`, and every `error` sends to the `null` device, meaning will not show us.

The result is:

`/usr/lib/systemd/user/dconf.service`

We open it via `cat`: 

```bash
cat /usr/lib/systemd/user/dconf.service
```

The content of the file is:

```bash
[Unit]
Description=User preferences database
Documentation=man:dconf-service(1)

[Service]
ExecStart=/usr/libexec/dconf-service
Type=dbus
BusName=ca.desrt.dconf
```
So now we see the type, which is `dbus` we provide that as answer and the lab is solved.