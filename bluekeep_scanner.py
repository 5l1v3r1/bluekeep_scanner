import os
import datetime
import pytz


def generate_rf():
    """
    TODO: Create msf_0708.
    :return:success
    """
    success = True
    try:
        # Get ip from IP.txt
        IP_list = open("IP.txt", "r").readlines()
        # Generate msf resource file
        msf_0708  = open("msf_0708", "w")
        # Write necesary info
        msf_0708.write("use auxiliary/scanner/rdp/cve_2019_0708_bluekeep\n")
        # Add IP
        for ip in IP_list:
            Added_info = "set RHOST " + ip + "run\n"
            msf_0708.write(Added_info)
        # Exit at end of scan
        msf_0708.write("exit")
    except:
        success = False
    return success


def run():
    """
    TODO: Run msf_0708 and record operate information.
    :return:log_name
    """
    log_name = datetime.datetime.now(pytz.timezone('PRC')).strftime("%Y-%m-%d_%H-%M-%S")
    print("[*] Scanning......")
    os.system("msfconsole -r msf_0708 -q | grep -E '[+]'| tee {}".format(log_name))
    count = len(open(log_name, "r").readlines())
    return log_name, count


if __name__ == "__main__":
    if generate_rf():
        print(":) Generate msf_0708 successfully!")
    else:
        print("[!] Failed to generate msf_0708")
        exit()
    log_location,count = run()
    print(":) Scan is over.{} target(s) is vulnerable.".format(count))
    print(":) The location of log file is: {}".format(log_location))