# Cross-Site Scripting

## Challenge
Try to use XSS to get the cookie value in the above page

## Solution
When we go to the website, there is a button "Click to enter your name", and after clicking there we are prompted for our name.

Since this input is not sanitized, we can put there javascript code, and I put a snippet of JS which searches for an image that doesn't exist, and this throws an error, so on an error, I ask to give me the cookie:

```js
<img src=/ onerror=alert(document.cookie)>
```

And the result is:
`cookie=XSSisFun`

So the result to the lab is `XSSisFun`.

