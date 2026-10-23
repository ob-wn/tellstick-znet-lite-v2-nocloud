import socket

attrs = ['product', 'mac', 'secret', 'firmware', 'uuid']

# Connect to your Znet Live v2 device via the helpfully unauthenticated UDP API at port 30303
address = socket.gethostbyname("10.10.10.8")
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
