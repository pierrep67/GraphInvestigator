import sys
import re
from datetime import datetime
import time
import math

example_log = """
7;255;255;1,44523e+12;1,44523e+12;19/10/2015 7:45:11 am;19/10/2015 7:45:11 am;192.168.139.5;0;192.168.139.5;0;false;false;n/a;0:0:0:0:0:0:0:0;0:0:0:0:0:0:0:0;0;default domain;unknown;unknown;false;1014,1008,1006,1003,1002,1321,1254,1345;false;0;0;0;0;0;0;0;0;n/a;n/a;n/a;n/a;n/a;n/a;0.0.0.0;n/a;n/a;n/a;n/a;false;n/a;n/a;19/10/2015 7:45:31 am;8052;10;ips_impact_alert;0;1565;soc sourcefire dc (estreamer);rgv2awnlvhlwzt1fc3ryzwftzxijrgv2awnlqwrkcmvzcz0xotiumty4ljezos41cun1cnjlbnruaw1lpte0nduymzm1mte3odijcmvjb3jkvhlwzt1jufnfsu1qqunux0fmrvjucxjly29yzexlbmd0ad0ynzejdgltzxn0yw1wpte5ie9jdcaymde1ida3ojq1ojmxcwltcgfjdefszxj0rgf0ys5ldmvudelkptcynjmxcwltcgfjdefszxj0rgf0ys5kzxrly3rpb25fbmdpbmvjzd0ycwltcgfjdefszxj0rgf0ys5ldmvudfnly29uzd0xndq1mjmzntmycwltcgfjdefszxj0rgf0ys5pbxbhy3q9nwlpbxbhy3rbbgvyderhdgeuc291cmnlqwrkcmvzcz0xotiumty4ljezni4xcwltcgfjdefszxj0rgf0ys5kzxn0aw5hdglvbkfkzhjlc3m9mtkylje2oc4xmzyumjajaw1wywn0qwxlcnreyxrhlmrlc2nyaxb0aw9Mar 20 03:34:56upvsxoje0mtc6mtddicjquk9ut0nptc1ttk1qihjlcxvlc3qgdwrwiibbsw1wywn0oibqb3rlbnrpywxsesbwdwxuzxjhymxlxsbgcm9ticixotiumty4ljezos40iibhdcbnb24gt2n0ide5ida1ojq1ojmyidiwmtugvvrdiftdbgfzc2lmawnhdglvbjogqxr0zw1wdgvkieluzm9ybwf0aw9uiexlywtdiftqcmlvcml0etogml0ge3vkch0gmtkylje2oc4xmzyumtoxnjetpje5mi4xnjgumtm2ljiwojuwodi4;44 65 76 69 63 65 54 79 70 65 3d 45 73 74 72 65 61 6d 65 72 09 44 65 76 69 63 65 41 64 64 72 65 73 73 3d 31 39 32 2e 31 36 38 2e 31 33 39 2e 35 09 43 75 72 72 65 6e 74 54 69 6d 65 3d 31 34 34 35 32 33 33 35 31 31 37 38 32 09 72 65 63 6f 72 64 54 79 70 65 3d 49 50 53 5f 49 4d 50 41 43 54 5f 41 4c 45 52 54 09 72 65 63 6f 72 64 4c 65 6e 67 74 68 3d 32 37 31 09 74 69 6d 65 73 74 61 6d 70 3d 31 39 20 4f 63 74 20 32 30 31 35 20 30 37 3a 34 35 3a 33 31 09 69 6d 70 61 63 74 41 6c 65 72 74 44 61 74 61 2e 65 76 65 6e 74 49 64 3d 37 32 36 33 31 09 69 6d 70 61 63 74 41 6c 65 72 74 44 61 74 61 2e 64 65 74 65 63 74 69 6f 6e 45 6e 67 69 6e 65 49 64 3d 32 09 69 6d 70 61 63 74 41 6c 65 72 74 44 61 74 61 2e 65 76 65 6e 74 53 65 63 6f 6e 64 3d 31 34 34 35 32 33 33 35 33 32 09 69 6d 70 61 63 74 41 6c 65 72 74 44 61 74 61 2e 69 6d 70 61 63 74 3d 37 09 69 6d 70 61 63 74 41 6c 65 72 74 44 61 74 61 2e 73 6f 75 72 63 65 41 64 64 72 65 73 73 3d 31 39 32 2e 31 36 38 2e 31 33 36 2e 31 09 69 6d 70 61 63 74 41 6c 65 72 74 44 61 74 61 2e 64 65 73 74 69 6e 61 74 69 6f 6e 41 64 64 72 65 73 73 3d 31 39 32 2e 31 36 38 2e 31 33 36 2e 32 30 09 69 6d 70 61 63 74 41 6c 65 72 74 44 61 74 61 2e 64 65 73 63 72 69 70 74 69 6f 6e 3d 5b 31 3a 31 34 31 37 3a 31 37 5d 20 22 50 52 4f 54 4f 43 4f 4c 2d 53 4e 4d 50 20 72 65 71 75 65 73 74 20 75 64 70 22 20 5b 49 6d 70 61 63 74 3a 20 50 6f 74 65 6e 74 69 61 6c 6c 79 20 56 75 6c 6e 65 72 61 62 6c 65 5d 20 46 72 6f 6d 20 22 31 39 32 2e 31 36 38 2e 31 33 39 2e 34 22 20 61 74 20 4d 6f 6e 20 4f 63 74 20 31 39 20 30 35 3a 34 35 3a 33 32 20 32 30 31 35 20 55 54 43 20 5b 43 6c 61 73 73 69 66 69 63 61 74 69 6f 6e 3a 20 41 74 74 65 6d 70 74 65 64 20 49 6e 66 6f 72 6d 61 74 69 6f 6e 20 4c 65 61 6b 5d 20 5b 50 72 69 6f 72 69 74 79 3a 20 32 5d 20 7b 75 64 70 7d 20 31 39 32 2e 31 36 38 2e 31 33 36 2e 31 3a 31 36 31 2d 3e 31 39 32 2e 31 36 38 2e 31 33 36 2e 32 30 3a 35 30 38 32 38;""devicetype=estreamer	deviceaddress=192.168.139.5	currenttime=1445233511782	recordtype=ips_impact_alert	recordlength=271	timestamp=19 oct 2015 07:45:31	impactalertdata.eventid=72631	impactalertdata.detectionengineid=2	impactalertdata.eventsecond=1445233532	impactalertdata.impact=7	impactalertdata.sourceaddress=192.168.136.1	impactalertdata.destinationaddress=192.168.136.20	impactalertdata.description=[1:1417:17] """"protocol-snmp request udp"""" [impact: potentially vulnerable] from """"192.168.139.4"""" at mon oct 19 05:45:32 2015 utc [classification: attempted information leak] [priority: 2] {udp} 192.168.136.1:161->192.168.136.20:50828"";51250076;2;information;10;-1;no offense;3;1,44523e+12;n/a;ips_impact_alert;1;197;n/a;false;00:00:00:00:00:00;00:00:00:00:00:00;null;null;null";;
"""
#Mar 20 03:34:56
regex_timestamp1a = r'(... \d\d \d\d:\d\d:\d\d)\D'
regex_timestamp1b = r'(... \d \d\d:\d\d:\d\d)\D'
#2016-03-20 03:34:56
regex_timestamp2 = r'(\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)'
#20/Mar/2016:03:34:56
regex_timestamp3a = r'\D(\d\d/.../\d\d\d\d:\d\d:\d\d:\d\d)\D'
regex_timestamp3b = r'\D(\d/.../\d\d\d\d:\d\d:\d\d:\d\d)\D'
#20/03/2016 3:34:56 am
regex_timestamp4a = r'\D(\d\d/\d\d/\d\d\d\d \d\d:\d\d:\d\d ..)\D'
regex_timestamp4b = r'\D(\d/\d\d/\d\d\d\d \d\d:\d\d:\d\d ..)\D'
regex_timestamp4c = r'\D(\d\d/\d\d/\d\d\d\d \d:\d\d:\d\d ..)\D'
regex_timestamp4d = r'\D(\d/\d\d/\d\d\d\d \d:\d\d:\d\d ..)\D'
#20 mar 2016 03:34:56
regex_timestamp5a = r'\D(\d\d ... \d\d\d\d \d\d:\d\d:\d\d)\D'
regex_timestamp5b = r'\D(\d ... \d\d\d\d \d\d:\d\d:\d\d)\D'

def counting_matches_timestamps(raw_log):
    output = {}
    output['t1a'] = len(find_timestamp_regex(raw_log,regex_timestamp1a))
    output['t1b'] = len(find_timestamp_regex(raw_log,regex_timestamp1b))

    output['t2'] = len(find_timestamp_regex(raw_log,regex_timestamp2))

    output['t3a'] = len(find_timestamp_regex(raw_log,regex_timestamp3a))
    output['t3b'] = len(find_timestamp_regex(raw_log,regex_timestamp3b))

    output['t4a'] = len(find_timestamp_regex(raw_log,regex_timestamp4a))
    output['t4b'] = len(find_timestamp_regex(raw_log,regex_timestamp4b))
    output['t4c'] = len(find_timestamp_regex(raw_log,regex_timestamp4c))
    output['t4d'] = len(find_timestamp_regex(raw_log,regex_timestamp4d))

    output['t5a'] = len(find_timestamp_regex(raw_log,regex_timestamp5a))
    output['t5b'] = len(find_timestamp_regex(raw_log,regex_timestamp5b))

    return output

def calculate_single_timestamp(raw_log):
    list_timestamps = find_all_timestamps(raw_log)

    if len(list_timestamps) == 0:
        return 0
    else:
        #return math.floor(sum(list_timestamps)/len(list_timestamps))
        return min(list_timestamps)

def find_all_timestamps(raw_log):

    result_posix = []

    list_timestamp1 = find_timestamp_regex(raw_log,regex_timestamp1a) + find_timestamp_regex(raw_log,regex_timestamp1b)
    for timestamp in list_timestamp1:
        result_posix.append(convert_string_time_1(timestamp,2015))

    list_timestamp2 = find_timestamp_regex(raw_log,regex_timestamp2)
    for timestamp in list_timestamp2:
        result_posix.append(convert_string_time_2(timestamp))

    list_timestamp3 = find_timestamp_regex(raw_log,regex_timestamp3a) + find_timestamp_regex(raw_log,regex_timestamp3b)
    for timestamp in list_timestamp3:
        result_posix.append(convert_string_time_3(timestamp))

    list_timestamp4 = find_timestamp_regex(raw_log,regex_timestamp4a) + find_timestamp_regex(raw_log,regex_timestamp4b) + find_timestamp_regex(raw_log,regex_timestamp4c) + find_timestamp_regex(raw_log,regex_timestamp4d)
    for timestamp in list_timestamp4:
        result_posix.append(convert_string_time_4(timestamp))

    list_timestamp5 = find_timestamp_regex(raw_log,regex_timestamp5a) + find_timestamp_regex(raw_log,regex_timestamp5b)
    for timestamp in list_timestamp5:
        result_posix.append(convert_string_time_5(timestamp))

    return sorted(result_posix)



def find_timestamp_regex(raw_log,regex):
    timestamp = re.findall(regex, raw_log)
    return timestamp

def find_all_IP_addresses(raw_log):
    ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', raw_log )
    ip = remove_double_elements(ip)
    ip = remove_unwanted_ip_addresses(ip)
    ip = remove_not_ip_addresses(ip)
    ip = sorted(ip)
    return ip


def remove_double_elements(input_list):
    return list(set(input_list))

def remove_unwanted_ip_addresses(input_list):
    ip_addresses_to_remove = ["0.0.0.0"]
    for element in ip_addresses_to_remove:
        if element in input_list:
            input_list.remove(element)
    return input_list

def remove_not_ip_addresses(input_list):
    #There are string with the shape of an IP address but that are not IP addresses.
    for element in input_list:
        splitted_ip = element.split(".")
        for ip in splitted_ip:
            if int(ip) > 256:
                input_list.remove(element)
                break

    return input_list

#---------------------------------

#CONVERSION FUNCTIONS
#For format of style: Mar 20 03:34:56
def convert_string_time_1(string_time, wished_year):
    datetime_object = datetime.strptime(string_time, '%b %d %H:%M:%S')
    datetime_object = datetime_object.replace(year=wished_year)
    result = time.mktime(datetime_object.timetuple())
    return result

#For format of style: 2016-03-20 03:34:56
def convert_string_time_2(string_time):
    datetime_object = datetime.strptime(string_time, '%Y-%m-%d %H:%M:%S')
    result = time.mktime(datetime_object.timetuple())
    return result

#For format of style: 20/Mar/2016:03:34:56
def convert_string_time_3(string_time):
    datetime_object = datetime.strptime(string_time, '%d/%b/%Y:%H:%M:%S')
    result = time.mktime(datetime_object.timetuple())
    return result

#20/03/2016 3:34:56 am
def convert_string_time_4(string_time):
    datetime_object = datetime.strptime(string_time, '%d/%m/%Y %H:%M:%S %p')
    result = time.mktime(datetime_object.timetuple())
    return result

#20 mar 2016 03:34:56
def convert_string_time_5(string_time):
    datetime_object = datetime.strptime(string_time, '%d %b %Y %H:%M:%S')
    result = time.mktime(datetime_object.timetuple())
    return result


if __name__ == "__main__":
    print find_all_IP_addresses(example_log)
    print find_all_timestamps(example_log)
