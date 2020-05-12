# **surveyor+TH**

## **About**
A Python utility that queries Carbon Black ThreatHunter / VMware Carbon Black Enterprise EDR and summarizes results. It has many uses, but is used primarily to understand where certain applications or activities exist within an enterprise, who is using them and how.

This script is based upon the Red Canary surveyor that has the ability to filter data using criteria.
    [https://github.com/redcanaryco/cb-response-surveyor](https://github.com/redcanaryco/cb-response-surveyor)

------------
## **Using**
Create and populate your cbapi credential file per the instructions found here: https://github.com/carbonblack/cbapi-python.

This script is designed to be run on a Windows machine, it will create two files in the output folder.  The 1st is what is displayed in the console when you run the script and the 2nd is the output in csv format with a date/time stamp as part of the filename.

Ex using Hostname as the prefix:
- Hostname-2020.05.04-T123835.txt - The console screen
- Hostname-2020.05.04-T123835.csv - The output of the command

**Note**: Please review the Sample definitions folder to see an example of the json with the criteria. 

Run using one of the test definitions:

./surveyor+TH.py --deffile definitions/Forensics/PowerShell.json
Then open and review the default output file located in the .\Output folder.

You can also run using an entire directory of definition files in one shot:

./surveyor+TH.py --defdir definitions

If you're looking for instances of something specific and a Cb query suits you best, you can do that too:

./surveyor+TH.py --query 'process_name:explorer.exe AND process_username:joebob'

## Script Help:
```
usage: surveyor+TH.py [-h] [--profile PROFILE] [--prefix PREFIX] [--days DAYS]
                      [--minutes MINUTES]
                      (--deffile DEFFILE | --defdir DEFDIR | --query QUERY | --iocfile IOCFILE)
                      [--hostname HOSTNAME] [--username USERNAME] [--ioctype IOCTYPE]

optional arguments:
  -h, --help           show this help message and exit
  --profile PROFILE    profile to connect
  --prefix PREFIX      Output filename prefix.
  --days DAYS          Number of days to search.
  --minutes MINUTES    Number of days to search.
  --deffile DEFFILE    Definition file to process (must end in .json).
  --defdir DEFDIR      Directory containing multiple definition files.
  --query QUERY        A single Cb query to execute.
  --iocfile IOCFILE    IOC file to process. One IOC per line. REQUIRES --ioctype
  --hostname HOSTNAME  Target specific host by name.
  --username USERNAME  Target specific username.
  --ioctype IOCTYPE    One of: process_hash, netconn_ipv4, netconn_domain
```
------------
## Sample output from the console:
```
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

Processing definition file: ./Forensics/PowerShell.json
--> powershell
       (process_name:powershell.exe) process_start_time:[2020-04-29T16:36:32.00Z TO 2020-05-04T16:36:32.00Z]

************************************************
 Found xxxx items in VMware Carbon Black TH 
************************************************

```



