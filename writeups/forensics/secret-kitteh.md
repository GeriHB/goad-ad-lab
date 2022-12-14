Challenge Description

![image](https://user-images.githubusercontent.com/93059165/207590365-e1bfcbd7-91d8-49a1-ba65-90a212bc1552.png)










Kitteh forensic challenge from TUCTF is just an image of a cat, and the flag is hidden somewhere.
From the first look we see nothing else, just the picture. 
Also metadata didn’t give much info about the flag.
exiftool  secret_kitteh_.jpg






















So we dig deeper by looking at image at hex level.
For this we used a GUI hex editor, GHEX. 
ghex secret_kitteh_.jpg





Here we see the “FFD8” which is a starting tag for jpg files. Now we search for “FFD9”, the end tag for jpg files.
We see here that the FFD9 tag is not at the end of the file, as it should be. 
So we have additional data in the file, which can or can’t be a picture.

“37 7A BC AF 27 1C” is the starting tag of a 7z archive file, so we can suppose we have a 7z archive inside this picture, and thus we need to extract it.

So, we copy the hex values from “37 7A BC” until the end, and we paste to an empty file, which I called f.hex

Then the “xxd” tool is used to convert this file into a binary file.

xxd -r -p f.hex output

We now see the file, output, which is a 7z archive.







But there is another protective measure applied, this 7z archive is password protected, so we can’t by the first try access the flag file inside it.

So, in order to crack the password of the zip file, first we must extract the hash of the file.
This is done with the tool “7z2john”:
7z2john output.7z > hashed.7z > hashed.hash
This creates a file called hashed.hash which contains the hash of the 7z file.

Now we need to crack it, and hopefully get a password.
A way to do this is by bruteforcing. So we need a list of passwords that could be used to extract the content of the 7z archive.
I copied a list of common passwords “wordlist_passwords.txt” in the working directory, and used “John The Ripper” to bruteforce it.
John –wordlisst=wordlist_password.txt –format=7z hashed.hash
We don’t see a password here, so we will use another option of john “--show”.
Now, we see that the password was not so hard to guess, it is “password”, and we try it.
The password worked, and we got the flag.
