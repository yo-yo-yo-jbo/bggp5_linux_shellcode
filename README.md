# Linux shellcoding ideas
It is June 2024, and [Binary Golf](https://binary.golf/) season is upon us!  
For the uninitiated - the idea of Binary Golf is to create the shortest program\script\whatever that does *some task*, where the task changes each time.  
This is [year 5](https://binary.golf/5/), and the goal is:

```
Create the smallest file that downloads [this](https://binary.golf/5/5) text file and displays its contents.
```

There are some interesting clarifying questions that were kind of answered:
- It's okay to rely on external dependencies of the OS.
- Environment variables or commandline arguments are okay, although they might be in different categories.

## Preliminary thoughts
Some ideas that come to mind:
1. The URL is `https`, and implementing your own TLS library (or borrowing one) would increase solution size drastically. Therefore, relying on external binaries or libraries makes sense.
2. The `curl` binary exists in every primary modern OS (Windows, Linux, macOS).
3. The URL path could be shortened easily (e.g. like using `bit.ly`).
4. We could send the URL in a commandline argument (or environment variable), or even an entire program!

To test some of those ideas (some of them "game the system" by definition) I submitted [one exterme solution](https://github.com/binarygolf/BGGP/blob/main/2024/entries/jbo/jbo.sh.txt) with only 2 bytes:

```shell
$1
```

To run: `bash jbo.sh "curl https://binary.golf/5/5"`.

In my opinion, this is definitely cheating, but whatever. My real goal is not to rely on scripting but to do some binary work, and so I've decided to go for a shellcode!







