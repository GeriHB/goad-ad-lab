# Challenge Description

Kitteh forensic challenge from TUCTF is just an image of a cat, and the flag is hidden somewhere.

![image](https://user-images.githubusercontent.com/93059165/207590365-e1bfcbd7-91d8-49a1-ba65-90a212bc1552.png)

From the first look we see nothing else, just the picture. 

Also metadata didn’t give much info about the flag.
``` sh
exiftool  secret_kitteh_.jpg
```

![image](https://user-images.githubusercontent.com/93059165/207590731-f00db596-e536-4b20-a1bd-acf6e2326b85.png)

So we dig deeper by looking at image at hex level.
  
For this we used a GUI hex editor, GHEX. 
``` sh
ghex secret_kitteh_.jpg
``` 

![image](https://user-images.githubusercontent.com/93059165/207590849-7f034ea3-9c45-4743-a1f7-4b5b8026c3bf.png)

Here we see the “FFD8” which is a starting tag for jpg files. Now we search for “FFD9”, the end tag for jpg files.

![image](https://user-images.githubusercontent.com/93059165/207590907-0a396084-3023-4273-b12d-2b9eb899045a.png)

We see here that the FFD9 tag is not at the end of the file, as it should be. 

So we have additional data in the file, which can or can’t be a picture.

“37 7A BC AF 27 1C” is the starting tag of a 7z archive file, so we can suppose we have a 7z archive inside this picture, and thus we need to extract it.

So, we copy the hex values from “37 7A BC” until the end, and we paste to an empty file, which I called f.hex

Then the “xxd” tool is used to convert this file into a binary file.
``` sh
xxd -r -p f.hex output
``` 

We now see the file, output, which is a 7z archive.

![image](https://user-images.githubusercontent.com/93059165/207590957-077bda3d-fd51-4cb4-82ed-af119502885f.png)

But there is another protective measure applied, this 7z archive is password protected, so we can’t by the first try access the flag file inside it.

![image](https://user-images.githubusercontent.com/93059165/207590990-1b39daa5-242d-4482-874e-4e8fbf42b699.png)

So, in order to crack the password of the zip file, first we must extract the hash of the file.

This is done with the tool “7z2john”:

``` sh
7z2john output.7z > hashed.7z > hashed.hash
```

This creates a file called hashed.hash which contains the hash of the 7z file.

![image](https://user-images.githubusercontent.com/93059165/207591020-e0370cdc-e397-48e6-a802-04f0eac2cdd1.png)

Now we need to crack it, and hopefully get a password.

A way to do this is by bruteforcing. So we need a list of passwords that could be used to extract the content of the 7z archive.

I copied a list of common passwords “wordlist_passwords.txt” in the working directory, and used “John The Ripper” to bruteforce it.

``` sh
john –wordlisst=wordlist_password.txt –format=7z hashed.hash
``` 

![image](https://user-images.githubusercontent.com/93059165/207591054-b1e42b27-d91f-4ef9-9460-e1a90f057808.png)

We don’t see a password here, so we will use another option of john “--show”.

``` sh
john --show hashed.hash

``` 

![image](https://user-images.githubusercontent.com/93059165/207591094-d6170dba-914b-4d13-b35f-3232faaf5bcb.png)

Now, we see that the password was not so hard to guess, it is “password”, and we try it.

![image](https://user-images.githubusercontent.com/93059165/207591159-48e4b9b4-9763-4288-b417-0e64a6ff6856.png)

**The password worked, and we got the flag.**
