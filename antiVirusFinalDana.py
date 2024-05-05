import requests
import json
import sys
import colorama
from time import sleep
import os

colorama.init()
def type(words:str):
    for char in words:
        sleep(0.015)
        sys.stdout.write(char)
        sys.stdout.flush()
    print()



def goThroughAllFiles(folder_path):
    
    files = [f for f in os.listdir(folder_path) if os.path.isfile(folder_path+"\\"+f)]
    for f in files:
        file_path=folder_path+'\\'+f
        scan_files(file_path)

def scan_files(file_path):
    url = r'https://www.virustotal.com/vtapi/v2/file/scan'
    api = "here was my api "
    



    params={"apikey":api}

    file_to_upload={"file":open(file_path,"rb")}

    response=requests.post(url,files=file_to_upload,params=params)
    file_url=f"https://www.virustotal.com/api/v3/files/{(response.json())['sha1']}"

    headers={"accept":"application/json","x-apikey":api}
    type(colorama.Fore.RED+" analysing...")
    response=requests.get(file_url,headers=headers)

    report = response.text
    report = json.loads(report)

    name = ((report["data"])["attributes"]).get("meaningful_name", "unable to fetch ")
    descp = ((report["data"])["attributes"])["type_description"]
    size = (((report["data"])["attributes"])["size"]) * 10**-3
    result = ((report["data"])["attributes"])["last_analysis_results"]

    print()
    type((colorama.Fore.WHITE + "Name : ", colorama.Fore.YELLOW + f"{name}"))
    type((colorama.Fore.WHITE + "Size : ", colorama.Fore.YELLOW + f"{size} KB"))
    type((colorama.Fore.WHITE + "Description : ", colorama.Fore.YELLOW + f"{descp}"))

    malicious_count = 0
    print()
    answer=input(colorama.Fore.RED+" Do you want to see the analysis answer yes/no?")
    if(answer=="yes"): 
        for key,values in result.items():
            key = colorama.Fore.WHITE + f'{key}'
            verdict = values['category']
            if verdict == 'undetected':
                verdict = colorama.Fore.GREEN + 'undetected'
            elif verdict == 'type-unsupported':
                verdict = colorama.Fore.RED + 'type-unsupported'

            elif verdict == 'malicious':
                malicious_count += 1
                verdict = colorama.Fore.RED + 'malicious'
            else:
                verdict = colorama.Fore.RED + f'{verdict}'
            str = f'{key}: {verdict}'
            type(str)
    if malicious_count != 0:
        print(colorama.Fore.RED+"antivirus found the given file is malicious watch out")
    elif malicious_count == 0:
        print(colorama.Fore.GREEN+"no virus found" )


folder_path=input(colorama.Fore.MAGENTA+" Enter the path to the folder ")
goThroughAllFiles(folder_path)
print(colorama.Back.WHITE+"completed the check up")