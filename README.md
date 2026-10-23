# tellstick-znet-lite-v2-nocloud
This is a new connection method specifically developed for the Tellstick Znet Lite v2, since the lack of current updates makes it nearly impossible to use the device in an air-gapped network. Additionally, the web UI has stopped working in modern browsers and Tellus have ceased support for the device on that front (that annoying /tellduslive/authorize error that has you downloading browsers from 10 years ago to try and bypass).

## TL;DR
Need machine secret, locally generated key to create access token to the device. Tellus helpfully provides a mechanism to obtain this data.


## Background
The API for the Znet Lite v2 is only accessible with a token, that is normally created by Tellus for 30 days at a time. This means there is (was) no way at all to connect to your local device on your local, air-gapped network. Even on a network that has access to the internet, maintaining access is not possible for more than 30 days at a time.


### Inspection
After taking a look at the firmware, device and communication of the Znet v2, we found the following:

- API tokens are JWTs, normally created and signed by Tellus and validated on the local device.
- The secret for this JWT is derived from the machine secret stored on the device along with a salt and device token that is generated locally
- The device token, salt and other configuration is packaged and uploaded to Tellus whenever the configuration changes (e.g. changing the name of the device).
- The /upload/config call towards Tellus is made via HTTP, so it's unencrypted inspectable traffic.
- The uploaded config archive is encrypted by the same machine secret stored on the device above.
- The device is running Dropbear SSH for remote connectivity

This means the road blocks toward being able to use the device fully locally without an internet connection are the following:

1. On-device machine secret
2. The locally generated token

### 1. On-device machine secret
Our first instinct was to target the SSH server to sign in to the device to be able to read the secrets, but root login is disabled by setting an empty password and the dropbear SSH version on the device.

After taking a look at the firmware, we realized we had missed a very helpful undocumented (and completely unauthenticated) UDP API endpoint at port 30303:


```python
import socket, sys

attrs = ['product', 'mac', 'secret', 'firmware', 'uuid']

# Connect to your Znet Lite v2 device via the helpful UDP API at port 30303
address = socket.gethostbyname("10.0.0.33")
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sck:
    sck.settimeout(3.0)
    sck.connect((address, 30303))
    
    # Send the "D" command to request the device configuration
    sck.send(b"D")
    
    # Receive the response containing the device configuration
    response = sck.recv(4096)
    
    # Split the response into lines for easier reading
    response_lines = response.split(b":")
    
    for i, attr in enumerate(attrs):
        if i < len(response_lines):
            print(f"{attr}: {response_lines[i].decode()}")
```

This provides us with the very helpful response of:

```yaml
product: TellstickZnetLiteV2
mac: ACACACACACACAC
secret: ABCDEFGHIJK
firmware: 1.3.2
uuid: 12345678-1234-1234-1234-123456789abc
```

There we go, that's 1/2 road blocks successfully pushed out of the way with the help of some friendly engineer at Tellus.

### 2. The local device token
This one is a bit trickier, since they didn't provide a helpful API for it. However, as it turns out, they helped us a bit along the way.

This is where the part about the helpful configuration backup comes in. If we go ahead and start a packet capture on outbound traffic from the device IP with destination port 80, and then go into the app to change the device name from anything to anything else, we get this very helpful nugget of information among the captured packets (some information obfuscated):

```bash
ethertype IPv4 (0x0800), length 1234: (tos 0x0, ttl 64, id 24112, offset 0, flags [DF], proto TCP (6), length 1234)
    10.0.0.33.56789 > 15.16.17.18.80: Flags [.], cksum 0xf09b (correct), seq 1:1449, ack 1, win 3650, options [nop,nop,TS val 1234567890 ecr 1234567890], length 1024: HTTP, length: 1024
	POST /upload/config HTTP/1.1
	Host: api.telldus.com
	Connection: keep-alive
	Accept-Encoding: gzip, deflate
	Accept: */*
	User-Agent: python-requests/2.12.5
	Content-Length: 1234
	Content-Type: multipart/form-data; boundary=1234567890abcdef1234567890abcdef
	
	--1234567890abcdef1234567890abcdef
	Content-Disposition: form-data; name="mac"
	
	ACCA54013E23
	--1234567890abcdef1234567890abcdef
	Content-Disposition: form-data; name="Telldus.conf.bz2"; filename="Telldus.conf.bz2"
	
	<contents of the Telldus.conf.bz2 file>
	--1234567890abcdef1234567890abcdef--
```

Huzzah! That looks like a configuration file to me. 

We now get a binary blob (which is helpfully encrypted by the device secret that we were provided earlier) with the decrypt_pcap.py script. This will get us a file called Tellus.conf:

```ini
......
[telldus.api]
salt = AbCdeF+GhijkL9mnOpQrast==
pw = $x2x2$$abcdefghijklmnopqrstuvwxyz
tokenKey = AbcdefGhijklmnOpQrStUvw=
```

That gets us the rest of the way there!

### 3. The access token
Now, we just need to generate our own access token for the Tellus API using the information we found. The JWT has the following format:

```json
{
    "typ": "JWT", // The type of token, JWT in this case
    "alg": "HS256", // The signing algorithm
    "aud": "local-audit", // The intended audience (application identity, looks like this is not verified on the Znet)
    "exp": 99999999 // The expiration time (Unix timestamp, not validated for max length so you can create an indefinetly valid token)
}
{
    // Empty JWT payload
}
{
    /// signature bytes here
}
```

Using all of the information combined, we can now mint our very own access token for the Tellus API:

```bash
$ python3 create-jwt.py Decrypted-Telldus.conf --ttl-seconds 99999999 --app local-audit
Device secret:

eyJ0eXAi.........................................................................eyJ9.
```


And now, for the final verification:

```bash
curl -H "Authorization: Bearer eyJ0eXAi.........................................................................eyJ9." http://10.0.0.33/api/devices/list

{
    "device": [
        {
            "id": 1,
            "methods": 0,
            "name": "My Connected Device 1",
            "state": 0,
            "statevalue": "",
            "type": "device
        }
    ]
}
```


And bob's your uncle!




## Disclaimer
This authentication method only targets the purchased hardware that is in your home, and does not in any way, shape or form target the servers or infrastructure of Tellus. This means that under the various right-to-repair laws and interoperability exemptions from DMCA laws, analyzing the software included in a device you purchase/own is not illegal. This method does not read, modify, copy, distribute or alter source or binary code that Tellus holds the intellectual property rights for.
The interoperability exemptions allow for reverse engineering and analysis of software to ensure compatibility with other systems, provided that the analysis is limited to what is necessary for achieving interoperability.

### Section 69e UrhG: decompilation for interoperability
The official text of § 69e UrhG — Decompilation  permits certain acts of code reproduction and translation without the copyright holder's consent when they are indispensable to obtain information necessary for interoperability. The conditions include having the right to use a copy of the program, the information not being readily available, and limiting the analysis to the necessary parts. 

Section 69d(3) UrhG  permits a person entitled to use a copy of a computer program to observe, study or test its functioning to determine the ideas and principles underlying its elements, while performing operations they are entitled to perform.