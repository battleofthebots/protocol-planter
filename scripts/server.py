import socket
import secrets
import hashlib
import json
import subprocess
import os

import asyncio

async def handleConn(c):
    loop = asyncio.get_event_loop()
    # Receive clientID
    clientMsg = await loop.sock_recv(c, 1024)

    jsonobj = None

    # Always encode our JSON decoding in try/except since competitors will send garbage
    try:
        jsonobj = json.loads(clientMsg) # Don't need to decode utf-8 with json.loads (python3.6+)
    except json.decoder.JSONDecodeError:
        await loop.sock_sendall(c, '{"error":"non-compliant message"}'.encode('utf-8'))
        c.close()   
        return

    clientID = jsonobj.get("clientID")

    # Made separate to aid competitors in determining if it's a json error
    # Bad json (missing/typod fields) or no json = non-compliant message
    if (clientID == None):
        await loop.sock_sendall(c, '{"error":"non-compliant message"}'.encode('utf-8'))
        c.close()   
        return

    if ( (type(clientID) is not int) or (clientID == 12345678) or (clientID < 10000000) ):
        # don't let them copy pcap solution
        # also super lazy but > 10000000 ensures the userid is 8 digits
        await loop.sock_sendall(c, '{"error":"invalid clientID"}'.encode('utf-8'))
        c.close()
        return

    # Send challenge
    challenge = secrets.token_hex(8)
    challengeMsg = '{"challenge":"' + challenge + '"}'
    await loop.sock_sendall(c, challengeMsg.encode('utf-8'))

    # Parse response
    # Always encode our JSON decoding in try/except since competitors will send garbage
    challengeResp = await loop.sock_recv(c, 1024)
    try:
        jsonobj = json.loads(challengeResp) # Don't need to decode utf-8 with json.loads (python3.6+)
    except json.decoder.JSONDecodeError:
        await loop.sock_sendall(c ,'{"error":"non-compliant message"}'.encode('utf-8'))
        c.close()   
        return

    # Does clientID match first packet?
    clientID2 = jsonobj.get("clientID") # clientID2 = clientID in client's packet #2
    
    # Made separate to aid competitors in determining if it's a json error
    # Bad json (missing/typod fields) or no json = non-compliant message
    if (clientID2 == None):
        await loop.sock_sendall(c, '{"error":"non-compliant message"}'.encode('utf-8'))
        c.close()   
        return

    if ( (type(clientID2) is not int) or (clientID2 != clientID) ):
        await loop.sock_sendall(c, '{"error":"invalid clientID"}'.encode('utf-8'))
        c.close()
        return

    # Does challenge match previous packet?
    challengeResp = jsonobj.get("challenge") # challenge response provided by client

    # Made separate to aid competitors in determining if it's a json error
    # Bad json (missing/typod fields) or no json = non-compliant message
    if (challengeResp == None):
        await loop.sock_sendall(c, '{"error":"non-compliant message"}'.encode('utf-8'))
        c.close()   
        return

    if ( (type(challengeResp) is not str) or (challengeResp != challenge) ):
        await loop.sock_sendall(c, '{"error":"challenge response failure"}'.encode('utf-8'))
        c.close()
        return

    # Does client checksum validate?
    # checksum = md5(clientID + challenge + flag)
    providedChecksum = jsonobj.get("checksum")

    # Made separate to aid competitors in determining if it's a json error
    # Bad json (missing/typod fields) or no json = non-compliant message
    if (providedChecksum == None):
        await loop.sock_sendall(c, '{"error":"non-compliant message"}'.encode('utf-8'))
        c.close()   
        return

    expectedChecksum = hashlib.md5((str(jsonobj["clientID"]) + jsonobj["challenge"] + jsonobj["flag"]).encode('utf-8')).hexdigest()
    if ( (type(providedChecksum) is not str) or (providedChecksum != expectedChecksum) ):
        await loop.sock_sendall(c, '{"error":"hash integrity failure"}'.encode('utf-8'))
        c.close()
        return

    # Success, notify client and open shell (loop below runs until client sends "exit")
    await loop.sock_sendall(c, '{"message":"authentication successful"}'.encode('utf-8'))

    while True:
        # Parse response
        # Always encode our JSON decoding in try/except since competitors will send garbage
        commandMsg = await loop.sock_recv(c, 1024)
        try:
            jsonobj = json.loads(commandMsg) # Don't need to decode utf-8 with json.loads (python3.6+)
        except json.decoder.JSONDecodeError:
            await loop.sock_sendall(c, '{"error":"non-compliant message"}'.encode('utf-8'))
            c.close()   
            return

        command = jsonobj.get("command")
        
        # Bad json (missing/typod fields) or no json = non-compliant message
        # Also if the command is not a string
        if ( (command == None) or (type(command) is not str) ):
            await loop.sock_sendall(c, '{"error":"non-compliant message"}'.encode('utf-8'))
            c.close()
            return

        # Check for exit
        if(command == "exit"):
            c.close()
            return

        # Otherwise run command
        try:
            process = subprocess.run(command, encoding='utf-8', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, executable='/bin/bash', timeout=320)
            await loop.sock_sendall(c, ('{"stdout":"' + (process.stdout) + '", "stderr":"' + (process.stderr) + '"}').encode('utf-8'))
        except subprocess.TimeoutExpired:
            c.close()
            return
            # process.kill() automatically done with .run versus .Popen


async def run_server():
    s = socket.socket()
    host = "0.0.0.0"
    port = 13942
    s.bind((host, port))
    s.listen(5)
    s.setblocking(False)

    loop = asyncio.get_event_loop()

    while True:
        c, _ = await loop.sock_accept(s)
        loop.create_task(handleConn(c))


def main():
    asyncio.run(run_server())
    

if __name__ == '__main__':
    main()
