# HTML Injection

## Challenge

What text would be displayed on the page if we use the following payload as our input: `<a href="http://www.hackthebox.com">Click Me</a>`

## Solution

When I visit the page, it is a button "Click to enter your name", and it doesn't valdiate the input.

So, here I can provide html code as input, and the goal was to provide the code above.

After giving that, the results was:

`Your name is Click Me` and by clicking on `Click Me` it goes to https://www.hackthebox.com

So, the answer is: `Your name is Click Me`.

