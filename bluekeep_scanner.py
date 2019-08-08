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
        # Write necessary info
        cve_2019_0708_bluekeep.write("use auxiliary/scanner/rdp/cve_2019_0708_bluekeep\nset THREADS 5\n")
        # Add IP
        order = 0
        for ip in ip_list:
            order += 1
            added_info = "echo \":) [{current}/{total}] Scanning {IP}...\"\nset RHOSTS {IP}\nrun\n".format(current=order, total=ip_count, IP=ip)
            cve_2019_0708_bluekeep.write(added_info)
        # Exit at end of scan
        cve_2019_0708_bluekeep.write("exit")
    except OSError:
        print("[!] Failed to generate cve_2019_0708_bluekeep.rc")
        exit()
    print(":) Generate cve_2019_0708_bluekeep.rc successfully!")


def washing_log(log_path):
    log_data = open(log_path).readlines()
    with open(log_path, "w") as log:
        for line in log_data:
            if "[+]" in line:
                log.write(line)


def run():
    """
    TODO: Run cve_2019_0708_bluekeep and record operate information.
    :return:log_path,vulnerability_count
    """
    log_name = datetime.datetime.now(pytz.timezone('PRC')).strftime("%Y-%m-%d_%H-%M-%S") + ".log"
    log_path = "log/{}".format(log_name)
    os.system("logsave {log_path} msfconsole -r rc/cve_2019_0708_bluekeep.rc -q | grep -E '[+]|^(:))'".format(log_path=log_path))
    washing_log(log_path)
    vulnerability_count = len(open(log_path, "r").readlines())
    return log_path, vulnerability_count


if __name__ == "__main__":
    generate_rf()
    print("[*] Starting msf.....")
    log_location, count = run()
    print(":) Scan is over.{} target(s) is vulnerable.".format(count))
    print(":) The location of log file is: {}".format(log_location))
