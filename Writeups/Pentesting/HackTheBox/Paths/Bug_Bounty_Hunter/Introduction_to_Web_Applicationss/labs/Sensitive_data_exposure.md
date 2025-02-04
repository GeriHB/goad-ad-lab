# Sensitive Data Exposure

## Challenge

Check the above login form for exposed passwords. Submit the password as the answer.

## Solution

By going the the webpage, there is a login form.

If we view the page source, we see a comment from the devs:

```html
        <!-- TODO: remove test credentials admin:HiddenInPlainSight -->
```

So here we see the credentials, give the password as the answer, and the lab is solved.