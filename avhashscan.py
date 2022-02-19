import time
import glob
import hashlib
import json
import requests
import hashlib
import os
import argparse
from datetime import datetime
import os.path

global max_file
max_file = "max"
global prev_file
prev_file = "prev"
global leaf
global beaf
leaf = 0
beaf = 0

while True:
    time.sleep(0.4)
    folder_path = r'/home/user/Downloads'
    file_type = '/**/*.*'
    files = glob.glob(folder_path + file_type, recursive=True)
    if files:
        max_file = max(files, key=os.path.getctime)
    
        if max_file != prev_file:
            folder_path = r'/home/user/Downloads'
            file_type = '/**/*.*'
            files = glob.glob(folder_path + file_type, recursive=True)
            max_file = max(files, key=os.path.getctime)
            prev_file = max_file

            print (f"Latest file:{max_file}")

            def block_heading(text):
                header_text = text.upper()
                header_length = len(header_text)
                box_width = int(header_length)
                print()
                print(f'{"+":-<{box_width+5}}+')
                print(f'{"|":<3}{header_text:^{box_width}}{"|":>3}')
                print(f'{"+":=<{box_width+5}}+')
                print()

            def format_json(data):
                total_vendors = 0
                total_detections = 0
                if "data" in data:
                    print("\033[1m\033[91m{:<30} {:<30}\033[0m".format(
                                    "Security Vendor", "Detection"))    
                    for k, v in data["data"]["attributes"]["last_analysis_results"].items():
                        total_vendors += 1
                        if str(v["result"]) != "None":
                            total_detections += 1
                            print("\033[91m{:<30} {:<30}\033[0m".format(
                                k, str(v["result"])))
                    print(
                        f'\n\033[1m\033[91mWARNING: {total_detections} of {total_vendors} Security Vendors flagged this file hash value as malicious\033[0m')
                    basicProp = {
                        "First submission date": str(datetime.fromtimestamp(data["data"]["attributes"]["first_submission_date"])),
                        "Last analysis date": str(datetime.fromtimestamp(data["data"]["attributes"]["last_analysis_date"])),
                        "ssdeep": data["data"]["attributes"]["ssdeep"],
                        "sha256": data["data"]["attributes"]["sha256"],
                        "sha1": data["data"]["attributes"]["sha1"],
                         "md5": data["data"]["attributes"]["md5"]
                    }
                    block_heading("Basic Properties")
                    for k, v in basicProp.items():
                        print("{:<30} {:<30}".format(k, str(v)))
                    print('')
                    if total_detections > 0:
                        os.system(f"""sudo -u user rm -r '{filename}'""")
                else:
                    print("")
    


            def vt_lookup(hashValue, apiKey):
                leaf = 0
                beaf = 0
                mell = "test"
                print(f'VirusTotal report details for file hash: {hashValue}\n')
                url = f'https://www.virustotal.com/api/v3/files/{hashValue}'
                headers = {
                    'x-apikey': apiKey,
                    'Accept': 'application/json',
                }

                try:
                    response = requests.get(url, headers=headers)
                    response.raise_for_status()
                    beaf = leaf
                    leaf = leaf + 1
                    return response.json()
                except requests.exceptions.HTTPError as e:
                    if "404" in str(e):
                        print(
                            'No file hash matches have been found in database.\n')
                        return mell
                    else:
                        print(f'API response: {e}')
                    return mell
        

            def main():
                block_heading(f'''My Hash Checker''')

                parser = argparse.ArgumentParser(
                    description='Lookup hash value using Virustotal')
                parser.add_argument("-file", "--filename", help="Hash of filename")
                parser.add_argument("-hash", "--hashvalue", help="Hash value")
                parser.add_argument("-debug", "--debug",
                                    help="Debug using local JSON data file")
                args = parser.parse_args()
                filenames = glob.glob(max_file)
                global filename
                for filename in filenames:
                    print(filename)
                    with open(filename, 'rb') as inputfile:
                        data = inputfile.read()
                        resultant = hashlib.sha256(data).hexdigest()
                        if hashlib.sha256(data).hexdigest():
                            data = vt_lookup(resultant, "Enter your VirusTotal API key here")
                        else:
                            parser.print_help()
                            usage()
                        format_json(data)
    
            if __name__ == "__main__":
                main()
