# BPAuthorization
BPAuthorization allows bots to access the API (both Action API and REST API) using an `Authorization` header with a bot password, instead of a complex method like OAuth, or classic Cookie-based login.

## Authentication and Authorization
Set the request header, `Authorization`, to `Bot B64USERNAME:B64APPID:B64PASSWORD`, where `B64USERNAME` is the bot's username (base64ed), `B64APPID` is the bot's app ID (base64ed), and `B64PASSWORD` is the bot password (base64ed).

This authentication/authorization method should only be used on a client (i.e. a bot), not a website. Anyone who can read the header value can access the bot password.

## Example
Here is a Python code to create a page.

```py
from base64 import b64encode
import requests

# The bot's username.
NAME = b64encode(b"ExampleBot").decode("ascii")
# The bot's "bot name"/"app id" on Special:BotPasswords.
APPID = b64encode(b"PageCreationExample").decode("ascii")
# Bot password. Always keep this secret!
PW = b64encode(b"0ok82q312pofknfcfd9ix0p4aqk3wqt4").decode("ascii")

resp = requests.put("https://wiki.example.org/w/rest.php/v1/page/BPAuthorization", headers={
    "Authorization": f"Bot {NAME}:{APPID}:{PW}"
}, json={
    "source": "This page is created using BPAuthorization, a cool extension for authentication.",
    "comment": "Created a page using BPAuthorization"
})

print(resp.json())
```
