#!/usr/bin/env python3
'''
Title: vturl.py
Author: github.com/chadpierce
Usage:
    vturl.py -s example.com (single url)
    vturl.py -f file.txt (input file, one url per line)
    vturl.py -d file.txt (dry run)

    - virus total api key should be saved in env var 'VT_API_KEY'
    - http proxy, if needed, should be saved in env var 'VT_HTTP_PROXY'

    - output is written to console and logfile
    - full json data for each url is written to urls directory (url id as filename)

Todo:
    - parse and display additional data, if potentialy malicious (categories, etc)
    - clean up output and logging format
    - add option to re-scan scanned urls
    - add option to re-scan all urls
    - filtering (subnets, domains, etc)

'''
from datetime import datetime
import requests
import base64
import sys
import os
import re

proxy_enabled = False
api_key = os.environ.get('VT_API_KEY')
if proxy_enabled:
    http_proxy = os.environ.get('VT_HTTP_PROXY')
else:
    http_proxy = ''
log_file = 'vt_log.txt'

class Color:

    blue = '\033[94m'
    green = '\033[92m'
    yellow = '\033[93m'
    red = '\033[91m'
    purple = '\033[95m'
    magenta = "\033[35m"
    cyan = "\033[36m"
    bgmagenta = "\033[45m"
    bgyellow = "\033[43m"
    bgred = "\033[41m"
    lightred = "\033[91m"
    lightgreen = "\033[92m"
    end = '\033[0m'


def get_verdict(url_tuple, resp):

    data = resp.json()
    rating_harmless = data['data']['attributes']['last_analysis_stats']['harmless']
    rating_mal = data['data']['attributes']['last_analysis_stats']['malicious']
    rating_sus = data['data']['attributes']['last_analysis_stats']['suspicious']
    rating_undetected = data['data']['attributes']['last_analysis_stats']['undetected']
    rating_rep = data['data']['attributes']['reputation']
    if rating_rep < 3 or rating_mal > 3 or rating_sus > 3:
        verdict = 'BAD! harmless: ' + str(rating_harmless) + ', mal: ' + str(rating_mal) + ', sus: ' + str(rating_sus) + ', rep: ' + str(rating_rep)
    elif rating_rep < 0 or rating_mal > 0 or rating_sus > 0:
        # TODO adjust badness levels
        verdict = 'BAD? harmless: ' + str(rating_harmless) + ', mal: ' + str(rating_mal) + ', sus: ' + str(rating_sus) + ', rep: ' + str(rating_rep)
    else:
        verdict = 'OKAY harmless: ' + str(rating_harmless) + ', mal: ' + str(rating_mal) + ', sus: ' + str(rating_sus) + ', rep: ' + str(rating_rep)
    return verdict


def api_successful(url_tuple, resp):

    if not os.path.exists("urls"):
        os.makedirs("urls")
    file_name = 'urls/' + url_tuple[0] + 'urlid'
    with open(file_name ,'w') as fd:
        fd.write(resp.text)
    # TODO improve verdict
    verdict = get_verdict(url_tuple, resp)
    log_write_new_entry(url_tuple, verdict)
    verdict = verdict.split(" ", 1)
    if verdict[0] == 'OKAY':
        print(Color.green + verdict[0] + Color.end + ' ' + url_tuple[2] + ' ' + url_tuple[0] + ' ' + verdict[1])
    elif verdict[0] == 'BAD?':
        print(Color.magenta + verdict[0] + Color.end + ' ' + url_tuple[2] + ' ' + url_tuple[0] + ' ' + verdict[1])
    else:
        print(Color.bgmagenta + verdict[0] + Color.end + ' ' + url_tuple[2] + ' ' + url_tuple[0] + ' ' + verdict[1])


def api_not_found(url_tuple):

    log_write_new_entry(url_tuple, 'NOT_FOUND')
    print(Color.yellow + 'NONE ' + Color.end + url_tuple[2] + ' ' + url_tuple[0])


def api_failed(url_tuple, r):

    print(Color.bgred + 'ERROR: ' + str(r.status_code) + ' - ' + r.text + Color.end)


def log_write_new_entry(url_tuple, verdict):

    timestamp = datetime.now().strftime("%d-%m-%Y_%H:%M:%S")
    with open(log_file ,'a') as f:
        f.write(timestamp + ',' + url_tuple[0] + ',' + url_tuple[2] + ',' + verdict + '\n')    


def log_check_url_id(url_id):

    if not os.path.exists(log_file):
        timestamp = datetime.now().strftime("%d-%m-%Y_%H:%M:%S")
        with open(log_file ,'a') as f:
           f.write(timestamp + ',url_id,url,verdict\n') 
    with open(log_file, 'r') as f:
        for line in f:
            # bookended id with commas so subdomain
            # and domain hashes are exact matches 
            if ',' + url_id + ',' in line:
                return True
                break
            else:
                continue
        return False


def api_call(url_tuple):

    proxies = {
        "http" : http_proxy,
        "https" : http_proxy,
    }
    headers = {
        'x-apikey': api_key,
    }

    if proxy_enabled:
        response = requests.get('https://www.virustotal.com/api/v3/urls/' + url_tuple[0], headers=headers, proxies=proxies)
    else:
        response = requests.get('https://www.virustotal.com/api/v3/urls/' + url_tuple[0], headers=headers)
    if response.status_code == 200:
        api_successful(url_tuple, response)
    elif response.status_code == 404:
        api_not_found(url_tuple)
    else:
        api_failed(url_tuple, response)


def process_url(url_tuple):

    if log_check_url_id(url_tuple[0]):
        print(Color.blue + 'DONE ' + Color.end  + url_tuple[2] + ' ' + url_tuple[0] + ' - already processed (TODO print verdict)')
        # TODO print url and verdict
    else:
        api_call(url_tuple)


def get_url_tuple(url):

    sanitized_url = url.replace('.', '[.]')
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    url_tuple = (url_id, url, sanitized_url)
    return url_tuple


def check_file_exists(filename):
    if not os.path.exists(filename):
        print(Color.red + 'ERROR: input file does not exist' + Color.end)
        sys.exit()


def process_input_file(filename):

    check_file_exists(filename)
    with open(filename) as file:
        # the code below only works with python >3.8
        # `while (line := file.readline().rstrip()):` 
        # it is relanced with the code below for compatibility
        lines = [line.rstrip() for line in file]
        for line in lines:
            url_tuple = get_url_tuple(line)
            process_url(url_tuple)


def dry_run(filename):

    check_file_exists(filename)
    with open(filename) as file:
        # the code below only works with python >3.8
        # `while (line := file.readline().rstrip()):` 
        # it is relanced with the code below for compatibility
        lines = [line.rstrip() for line in file]
        for line in lines:
            url_tuple = get_url_tuple(line)
            #process_url(url_tuple)
            if log_check_url_id(url_tuple[0]):
                print(Color.blue + 'DONE ' + Color.end  + url_tuple[2] + ' ' + url_tuple[0] + ' - already processed (TODO print verdict)')
            else:
                print(Color.yellow + 'UNKN ' + Color.end  + url_tuple[2] + ' ' + url_tuple[0] + ' - NOT PROCESSED (TODO print verdict)')


def main():

    if len(sys.argv) == 3:
        if sys.argv[1] == '-s':
            # single url
            url_tuple = get_url_tuple(sys.argv[2])
            process_url(url_tuple)
        elif sys.argv[1] == '-f':
            # file with url on each line
            process_input_file(sys.argv[2])
        elif sys.argv[1] == '-d':
            # dry run, check if urls have been processed
            dry_run(sys.argv[2])

        else:
            print(Color.red + 'TODO: display usage' + Color.end)  
    else:
        print(Color.red + 'TODO: display usage' + Color.end) 

if __name__ == "__main__":
    main()
