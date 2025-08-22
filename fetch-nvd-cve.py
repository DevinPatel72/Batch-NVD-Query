#!/usr/bin/env python3

import os
import sys
import re
import csv
import argparse
import nvdlib
from requests.exceptions import HTTPError

def progress_bar(iteration, total, prefix='', suffix='', decimals=2, length=50, fill='█', unfill='-', print_end="\r"):
    percent = ("{} / {}").format(iteration, total)
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + unfill * (length - filled_length)
    print(f'\r{prefix} |{bar}| {percent} {suffix}', end=print_end)

    # Print new line on complete
    if iteration >= total:
        print()
        
# Debug function
import json
def dump_CVE_obj(cve):
    def to_serializable(obj):
        if isinstance(obj, list):
            return [to_serializable(i) for i in obj]
        elif hasattr(obj, '__dict__'):
            return {key: to_serializable(value) for key, value in obj.__dict__.items()}
        else:
            return obj

    # Convert the CVE object
    cve_dict = to_serializable(cve)
            
    with open(f"{cve.id}.json", "w") as f:
        json.dump(cve_dict, f, indent=2)

print()
fieldnames = ['Published', 'Last Modified', 'DependencyName', 'CVE', 'CWE', 'CPE', 'Vulnerability', 'CVSS Base', 'Severity', 'CVSS Standard', 'URL']
help_description = """
This script fetches CVE information from NVD using the nvdlib python module.
Information is output in a CSV file using the same headers as OWASP Dependency Check.
This script requires a connection to the internet.

NOTE:
    Due to rate limiting restrictions by NVD, a request will take 6 seconds with no API key.
    Requests with an API key have the ability to define a delay argument.
    The delay argument must be a integer/float greater than or equal to 0.6 (seconds).
"""


# Input parsing
api_key = None
api_delay = None
outfile = 'nvd_cve.csv'
cve_list = []

parser = argparse.ArgumentParser(description=help_description, formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('--cve', type=str, nargs='+', help='A list of CVE IDs to fetch. These will be searched in addition to a --file input.\n    Example: --cve CVE-2022-24810 CVE-2022-24809')
parser.add_argument('-f', '--file', type=str, help='A file of CVE IDs separated by newlines.')
parser.add_argument('-o', '--out', type=str, default='nvd_cve.csv', help='Output file name. Will output to current directory by default.')
parser.add_argument('--api', type=str, help='(optional) Set an NVD api key to speed up CVE searches. Without it, each CVE search will take 6 seconds.')
parser.add_argument('--delay', type=float, help='(optional) Manually set the delay between CVE searches in seconds. Only usable if an NVD api key is passed.')

args = parser.parse_args()

# Validate inputs
if args.cve is None and args.file is None:
    print("[ERROR]  At least one argument must be passed: --cve or --file")
    print("         Use command line argument \'--help\' to see full usage")
    sys.exit(1)

if args.file is not None:
    with open(args.file, 'r') as r:
        cve_list += [l.strip().upper() for l in r.readlines()]

if args.cve is not None:
    cve_list += [l.strip().upper() for l in args.cve]

if args.out is not None:
    outfile = args.out
    if os.path.splitext(outfile)[1] != '.csv':
        outfile += '.csv'

if args.api is not None:
    api_key = args.api
    if args.delay is not None:
        api_delay = args.delay
    else:
        api_delay = 1
    
    # Test api key
    try:
        print("Testing connection...", end='')
        r = nvdlib.searchCVE(cveId='CVE-2002-1570', key=api_key, delay=api_delay)
    except HTTPError as httperr:
        print()
        if httperr.response.status_code == 404:
            print(f"[ERROR]  Invalid API Key")
        else:
            print(f"[ERROR]  Something went wrong")
        sys.exit(2)
    print('\n')
else:
    api_key = None
    api_delay = None

# Error tracking
errors = []

# Open outfile
while True:
    try:
        __fp = open(outfile, 'a')
        break
    except PermissionError:
        input(f"\n[ERROR]  Outfile \"{outfile}\" cannot be opened. To continue, please make sure the file is not already open in another program.\nPress Enter to continue or CTRL+C to quit...")
        print()

with open(outfile, 'w', encoding='utf-8-sig', newline='') as w:
    writer = csv.DictWriter(w, fieldnames=fieldnames)
    writer.writeheader()

    # Search each CVE
    for i, cve_id in enumerate(cve_list, start=1):
        progress_bar(i, len(cve_list), prefix=f'Searching CVEs'.rjust(18), length=len(cve_list), suffix=f":: {cve_id}".ljust(20))
        try:
            r = nvdlib.searchCVE(cveId=cve_id, key=api_key, delay=api_delay)
            if len(r) <= 0:
                errors.append(f"[ERROR]  \'{cve_id}\' could not be found.")
                continue
            else: r = r[0]
        except HTTPError as httperr:
            if httperr.response.status_code == 404:
                errors.append(f"[ERROR]  \'{cve_id}\' returned error 404. The CVE could not be found.")
            else:
                errors.append(f"[ERROR]  \'{cve_id}\' returned error {httperr.code}.")
            continue
        
        # Parse CWE number
        if r.cwe is not None and len(r.cwe) > 0:
            if m := re.match(r"CWE-(\d+)", r.cwe[0].value):
                cwe = m.group(1)
            else: cwe = ''
        else:
            errors.append(f"[WARNING]  \'{cve_id}\' does not have a CWE.")
            cwe = ''
        
        # Parse CPE Information
        affected_cpes = ''
        dependency_names = []
        version = ''
        if r.cpe is not None and len(r.cpe) > 0:
            for cpe in r.cpe:
                attributes = list(cpe)
                t_dependency_name = ''
                t_ver = ''
                t_version1 = ''
                t_version2 = ''
                
                # DependencyName
                if len(cpe.criteria) > 0:
                    # cpe:2.3: part : vendor : product : version : update : edition : language : sw_edition : target_sw : target_hw : other
                    if m := re.match(r"^cpe:\d+\.\d+:[aho]:([^:]*):([^:]*):([^:]*)", cpe.criteria):
                        t_dependency_name = f"{m.group(1)}:{m.group(2)}"
                        t_ver = m.group(3)
                        
                if t_ver == '*':
                    # Start Version
                    if 'versionStartIncluding' in attributes:
                        t_version1 = f"[{cpe.versionStartIncluding}, "
                    elif 'versionStartExcluding' in attributes:
                        t_version1 = f"({cpe.versionStartExcluding}, "
                    # End Version
                    if 'versionEndIncluding' in attributes:
                        t_version2 = f"{cpe.versionEndIncluding}]" if len(t_version1) > 0 else cpe.versionEndIncluding
                    elif 'versionEndExcluding' in attributes:
                        t_version2 = f"{cpe.versionEndExcluding})" if len(t_version1) > 0 else cpe.versionEndExcluding
                    
                    # Final check to avoid empty string
                    if len(t_version1 + t_version2) <= 0:
                        t_version1 = ''
                        t_version2 = t_ver
                elif t_ver == '-':
                    t_version2 = 'UnspecifiedVersion'
                else:
                    t_version2 = t_ver
                
                t_dependency_name = f"{t_dependency_name}:{t_version1 + t_version2}"
                if t_dependency_name not in dependency_names: dependency_names.append(t_dependency_name)
                affected_cpes += cpe.criteria + "\n"
            
            dependency_name = "\n".join(dependency_names).strip()
            affected_cpes = affected_cpes.strip()
        
        # Parse Description
        if r.descriptions is not None and len(r.descriptions) > 0:
            for d in r.descriptions:
                if d.lang == 'en':
                    description = d.value
                    break
                else:
                    description = ''
        else:
            description = ''
        
        cve = {
            "Published": r.published,
            "Last Modified": r.lastModified,
            "DependencyName": dependency_name,
            "CVE": cve_id,
            "CWE": cwe,
            "CPE": affected_cpes,
            "Vulnerability": description,
            "CVSS Base": str(r.score[1]),
            "Severity": r.score[2],
            "CVSS Standard": r.score[0],
            "URL": r.url
        }
        
        writer.writerow(cve)

print(f"\nOutput CVE data to {outfile}")

if len(errors) > 0:
    print(f"\n{len(errors)} errors have been detected:")
    
    for err in errors:
        print('    ' + err)
