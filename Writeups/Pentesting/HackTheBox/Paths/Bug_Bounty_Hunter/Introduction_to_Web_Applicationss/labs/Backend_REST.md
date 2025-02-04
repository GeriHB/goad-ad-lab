# Development Frameworks & API

## Challenge

Use GET request '/index.php?id=0' to search for the name of the user with id number 1?

## Solution

For this I will use `Burp Suite`, and I will first send a request to the page provided by the lab.

I send the request to the repeater, where I modify the `GET` request to the request that was given in the lab:  `GET request '/index.php?id=0`.

When I send the request for the `id=0` I got a response saying `User does not exist`.

And when I put `id=1`, I see `superadmin`, and I provide that, which is the solution to the lab.

