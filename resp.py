#!/usr/bin/python
import socket
import sys
import binascii
import pyperclip

HOST = input("Enter IP address: ") # server ip hosting legit service

while True:
    try:
        PORT = int(input("Enter port number: ")) # service port number
        break
    except ValueError:
        print("Invalid port")
        continue

conn = socket.socket()

try:
    conn.connect((HOST,PORT))
except TimeoutError:
    print("Port is closed. Make scan first.")
    input()
    sys.exit()

resp = conn.recv(10000)
bin = binascii.b2a_hex(resp)
print("Your banner:")
print(bin)
cpy = str(bin).lstrip("b'").rstrip("'")
pyperclip.copy(cpy)
print("Copied to clipboard")
conn.close()
input()
sys.exit()