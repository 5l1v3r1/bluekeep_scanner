import os
import datetime
import pytz


def get_target(target_path):
    """
    TODO: Get IP count.
    :return:ip_list,ip_count
    """
    try:
        ip_data = open(target_path, "r").readlines()
    except OSError:
        print("[!] Can not open {}.It exists?".format(target_path))
        exit()
    # Check if each line is end of /n
    ip_list = []
    for line in ip_data:
        if line == "\n":
            continue
        if line[:-1] != "\n":
            line = line[:-1]
        ip_list.append(line)
    ip_count = len(ip_list)
    return ip_list, ip_count


def generate_rf():
    """
    TODO: Generate msf resource file.
    :return:
    """
    ip_list, ip_count = get_target("IP.txt")
    try:
        cve_2019_0708_bluekeep = open("rc/cve_2019_0708_bluekeep.rc", "w")
    except OSError:
        print("[!] Failed to generate cve_2019_0708_bluekeep.rc")
        exit()
    # Write necessary info
    cve_2019_0708_bluekeep.write("use auxiliary/scanner/rdp/cve_2019_0708_bluekeep\nset THREADS 50\n")
    cve_2019_0708_bluekeep.write("echo \":) Scanning......\"\n")

    # Set display frequency(Display per 50 IPs)
    for start in range(1, ip_count + 50, 50):
        added_info = "echo \":) Progress: [{start}/{total}]......\"\nset RHOSTS ".format(start=start, total=ip_count)
        # If the number of cycles exceeds the maximum
        if start > ip_count:
            continue
        # print("Group:{}".format(int(start / 50) + 1))
        if start + 50 > ip_count:
            end = ip_count
        else:
            end = start + 50 - 1
        for ip_order in range(start, end):
            # Add IP
            added_info += "{ip} ".format(ip=ip_list[ip_order])
        added_info += "\nrun\n"
        cve_2019_0708_bluekeep.write(added_info)

    # Exit at end of scan
    cve_2019_0708_bluekeep.write("exit")
    print(":) Generate cve_2019_0708_bluekeep.rc successfully!")


def washing_log(log_path):
    """
    TODO: Remove junk information.
    :param log_path:
    :return:
    """
    try:
        log_data = open(log_path).readlines()
    except OSError:
        print("[!] Can not open {}!".format(log_path))
        exit()
    with open(log_path, "w") as log:
        for line in log_data:
            if "[+]" in line:
                log.write(line)


def run():
    """
    TODO: Run cve_2019_0708_bluekeep and record operate information.
    :return:
    """
    global LOG_PATH
    start_time = datetime.datetime.now()
    log_name = datetime.datetime.now(pytz.timezone('PRC')).strftime("%Y-%m-%d_%H-%M-%S") + ".log"
    LOG_PATH = "log/{}".format(log_name)
    print("[*] Starting msf.....")
    os.system("logsave {log_path} msfconsole -r rc/cve_2019_0708_bluekeep.rc -q | grep -E '[+]|^(:))'".format(log_path=LOG_PATH))
    washing_log(LOG_PATH)
    vulnerability_count = len(open(LOG_PATH, "r").readlines())
    end_time = datetime.datetime.now()
    run_time = end_time - start_time
    print(":) Scan is over.")
    print(":){} target(s) is vulnerable.".format(vulnerability_count))
    print(":) The scan took: {}".format(run_time))
    print(":) The location of log file is: {}".format(LOG_PATH))


def interrupt(signum, frame):
    print(":) Washing log.Please wait a moment....")
    washing_log(LOG_PATH)
    print(":) Washing complete.The location of log file is: {}".format(LOG_PATH))
    exit()


if __name__ == "__main__":
    LOG_PATH = ""
    generate_rf()
    run()
