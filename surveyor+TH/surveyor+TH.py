#!/usr/bin/env python
#     _____                                                 _______ _    _ 
#    / ____|                                          _    |__   __| |  | |
#   | (___  _   _ _ ____   _____ _   _  ___  _ __   _| |_     | |  | |__| |
#    \___ \| | | | '__\ \ / / _ \ | | |/ _ \| '__| |_   _|    | |  |  __  |
#    ____) | |_| | |   \ V /  __/ |_| | (_) | |      |_|      | |  | |  | |
#   |_____/ \__,_|_|    \_/ \___|\__, |\___/|_|               |_|  |_|  |_|
#                                 __/ |                                    
#                                |___/                                     
#
# Company: Red Canary
# Tool Written by: Keith McCammon
# Email: keith@redcanary.com
# Website: https://redcanary.com/surveyor/
#
# Modified by David Frank on 05/04/20
#   Modifed to work with VMware Carbon Black Threat Hunter
#   Modified nested_process_search definition section
#   Changed logging to Output folder and added output file of terminal screen
#   Added total count of items found

from cbapi.psc.threathunter import CbThreatHunterAPI, Process

import argparse
import csv
import json
import os
import sys
import time
from datetime import datetime, timedelta

if sys.version_info.major >= 3:
    _python3 = True
else:
    _python3 = False

def err(msg):
    """Format msg as an ERROR and print to stderr.
    """
    msg = 'ERROR: %s\n' % msg
    sys.stderr.write(msg)
    return


def log(msg):
    """Format msg and print to stdout.
    """
    msg = '%s\n' % msg
    sys.stdout.write(msg)
# log terminal screen to text file (log_filename)
    with open(log_filename, "a") as f:
        f.write("{}".format(msg))
    return

def listToString(s):  
# initialize an empty string 
    str1 = " " 
    
# return string   
    return (str1.join(s)) 

def process_search(cb_conn, query, query_base=None):
    """Perform a single Cb Response query and return a unique set of
    results.
    """
    results = set()
    Count = 0
    query += query_base
    log("  Query: %s" % query)

    try:
        processes = cb_conn.select(Process).where(query)
        
        for proc in processes:
                Count += 1
                ProcessCmdLine = (listToString(proc.process_cmdline)) 
                UserName = (listToString(proc.process_username))                
#                print("{} ~ {} ~ {} ~ {} ~ {}".format(proc.process_name, proc.device_name, UserName, ProcessCmdLine, Count))
                results.add((proc.device_name,
                            UserName,
                            proc.process_name,
                            ProcessCmdLine))
    except KeyboardInterrupt:
        log("Caught CTRL-C. Returning what we have . . .\n")

    return results


def nested_process_search(cb_conn, criteria, query_base=None):
    """Perform Cb Response queries for one or more programs and return a 
    unique set of results per program.
    """
    results = set()

    query = ''

    for search_field,terms in criteria.items():
        if 'surveyor_query' in search_field:
            continue

        query += '(' + ' OR '.join('%s:%s' % (search_field, term) for term in terms) + ')'
#        log("   Query:    %s" % query)
        
    if 'surveyor_query' in criteria.keys():
        query_base += ' ' + criteria['surveyor_query'][0]
#        log("  query_base:     %s" % query_base)
        
    query += query_base

    log("       %s" % query)

    try:
        processes = cb_conn.select(Process).where(query)
        
        for proc in processes:
#                print("{} ~ {} ~ {} ~ {} ~ {} ~ {}".format(proc.process_name, proc.device_name, proc.process_username, proc.process_cmdline, proc.process_md5, proc.parent_name))
                ProcessCmdLine = (listToString(proc.process_cmdline)) 
                UserName = (listToString(proc.process_username))                
#                print("{} ~ {} ~ {} ~ {}".format(proc.process_name, proc.device_name, UserName, ProcessCmdLine))
                results.add((proc.device_name,
                            UserName,
                            proc.process_name,
                            ProcessCmdLine))

    except KeyboardInterrupt:
        log("Caught CTRL-C. Returning what we have . . .")

    return results


def main():
    global log_filename

    parser = argparse.ArgumentParser()
    parser.add_argument("--profile",  type=str, action="store", help="profile to connect", default="default")    
    parser.add_argument("--prefix",  type=str, action="store",  help="Output filename prefix.")
   
# Time boundaries for the survey
    parser.add_argument("--days",  type=int, action="store", 
                        help="Number of days to search.")
    parser.add_argument("--minutes",  type=int, action="store", 
                        help="Number of days to search.")

# Survey criteria
    i = parser.add_mutually_exclusive_group(required=True)
    i.add_argument('--deffile', type=str, action="store", 
                        help="Definition file to process (must end in .json).")
    i.add_argument('--defdir', type=str, action="store", 
                        help="Directory containing multiple definition files.")
    i.add_argument('--query', type=str, action="store", 
                        help="A single Cb query to execute.")
    i.add_argument('--iocfile', type=str, action="store", 
                        help="IOC file to process. One IOC per line. REQUIRES --ioctype")
    parser.add_argument('--hostname', type=str, action="store", 
                        help="Target specific host by name.")
    parser.add_argument('--username', type=str, action="store", 
                        help="Target specific username.")

# IOC survey criteria
    parser.add_argument('--ioctype', type=str, action="store", 
                        help="One of: process_hash, netconn_ipv4, netconn_domain")

    args = parser.parse_args()

    if (args.iocfile is not None and args.ioctype is None):
        parser.error('--iocfile requires --ioctype')

# Get current directory and append Output to it
    pathname =  os.path.dirname(os.path.abspath( __file__ ))+'\\output\\'

    if args.prefix:
        output_filename = '{}{}-{}.csv'.format(pathname, args.prefix, time.strftime("%Y.%m.%d-T%H%M%S", time.localtime(time.time())))
        log_filename = '{}{}-{}.txt'.format(pathname, args.prefix, time.strftime("%Y.%m.%d-T%H%M%S", time.localtime(time.time())))
    else:
        output_filename = '{}_surveyor-{}.csv'.format(pathname, time.strftime("%Y.%m.%d-T%H%M%S", time.localtime(time.time())))
        log_filename = '{}_surveyor-{}.txt'.format(pathname, time.strftime("%Y.%m.%d-T%H%M%S", time.localtime(time.time())))

    log('''
 ***************************************************************************
 *   _____                                                 _______ _    _  *
 *  / ____|                                          _    |__   __| |  | | *
 * | (___  _   _ _ ____   _____ _   _  ___  _ __   _| |_     | |  | |__| | *
 *  \___ \| | | | '__\ \ / / _ \ | | |/ _ \| '__| |_   _|    | |  |  __  | *
 *  ____) | |_| | |   \ V /  __/ |_| | (_) | |      |_|      | |  | |  | | *
 * |_____/ \__,_|_|    \_/ \___|\__, |\___/|_|               |_|  |_|  |_| *
 *                               __/ |                                     *
 *                              |___/                                      * 
 *                              Modified on 05/04/20 by David Frank - v1.0 *
 ***************************************************************************
''')

    c = 0
    query_base = ''
    if args.days:
        now = datetime.utcnow().replace(microsecond=0)
        delta = timedelta(days= args.days )

        start_time= (now - delta).strftime("%Y-%m-%dT%H:%M:%S.00Z")
        end_time = now.strftime("%Y-%m-%dT%H:%M:%S.00Z")
        query_base += ' process_start_time:[%s TO %s]' % (start_time, end_time)
    elif args.minutes:
        now = datetime.utcnow().replace(microsecond=0)
        delta = timedelta(minutes = args.minutes )

        start_time= (now - delta).strftime("%Y-%m-%dT%H:%M:%S.00Z")
        end_time = now.strftime("%Y-%m-%dT%H:%M:%S.00Z")
        query_base += ' process_start_time:[%s TO %s]' % (start_time, end_time)        
    if args.hostname:
        if args.query and 'device_name' in args.query:
            parser.error('Cannot use --hostname with "device_name:" (in query)')
        query_base += ' device_name:%s' % args.hostname

    if args.username:
        if args.query and 'process_username' in args.query:
            parser.error('Cannot use --username with "process_username:" (in query)')
        query_base += ' process_username:%s' % args.username

    definition_files = []
    if args.deffile:
        if not os.path.exists(args.deffile):
            err('deffile does not exist')
            sys.exit(1)
        definition_files.append(args.deffile)
    elif args.defdir:
        if not os.path.exists(args.defdir):
            err('defdir does not exist')
            sys.exit(1)
        for root, dirs, files in os.walk(args.defdir):
            for filename in files:
                if filename.endswith('.json'):
                    definition_files.append(os.path.join(root, filename))

    if _python3:
        output_file = open(output_filename, 'w', newline='')
    else:
        output_file = open(output_filename, 'wb')
    writer = csv.writer(output_file)
    writer.writerow(["hostname","username","process_path","cmdline","program","source"])
 
    cb = CbThreatHunterAPI(profile=args.profile)

    if args.query:
        result_set = process_search(cb, args.query, query_base)

        for r in result_set:
            row = [r[0], r[1], r[2], r[3], args.query, 'query']
            if _python3 == False:
                row = [col.encode('utf8') if isinstance(col, unicode) else col for col in row]
            writer.writerow(row)
            c += 1

    elif args.iocfile:
        with open(args.iocfile) as iocfile:
            data = iocfile.readlines()
            for ioc in data:
                ioc = ioc.strip()
                query = '%s:%s' % (args.ioctype, ioc)
                result_set = process_search(cb, query, query_base)

                for r in result_set:
                    row = [r[0], r[1], r[2], r[3], ioc, 'ioc']
                    if _python3 == False:
                        row = [col.encode('utf8') if isinstance(col, unicode) else col for col in row]
                    writer.writerow(row)
                    c += 1
    else:
        for definition_file in definition_files:
            log("Processing definition file: %s" % definition_file)
            basename = os.path.basename(definition_file)
            source = os.path.splitext(basename)[0]

            with open(definition_file, 'r') as fh:
                programs = json.load(fh)

            for program,criteria in programs.items():
                log("--> %s" % program)

                result_set = nested_process_search(cb, criteria, query_base)

                for r in result_set:
                    row = [r[0], r[1], r[2], r[3], program, source]
                    if _python3 == False:
                        row = [col.encode('utf8') if isinstance(col, unicode) else col for col in row]
                    writer.writerow(row)
                    c += 1
    output_file.close()

    if c > 0:
        log('''
************************************************
 Found {} items in VMware Carbon Black TH 
************************************************
'''.format(c,))

    elif c == 0:
        log('''
*********************************************
 No entries found in VMware Carbon Black TH
*********************************************''')
        
if __name__ == '__main__':

    sys.exit(main())
