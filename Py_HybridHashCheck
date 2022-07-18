import requests
from requests.structures import CaseInsensitiveDict
import re
from bs4 import BeautifulSoup

url = "https://www.hybrid-analysis.com/sample/"

headers = CaseInsensitiveDict()
headers["user-agent"] = "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1"

def hybridwebreq(url2):
    resp = requests.get(url2, headers=headers)
    soup = BeautifulSoup(resp.content, features="lxml")
    overviewtag = str(soup.find(id='overview-container'))
    overviewtag = overviewtag.replace('\n', '')
    overviewtag = overviewtag.replace(' ', '')
    maldetecttag = str(soup.find(id='basic-malware-detection-info'))
    maldetecttag = str(maldetecttag)
    regex_threatscore = r'>(Threat\sScore.*)<'
    regex_avdetection = r'>(AV\sDetection.*)<'
    regex_filename = r'9word-break-all">([^<]+)'
    r_avdetection = re.compile(regex_avdetection)
    r_threatscore = re.compile(regex_threatscore)
    r_filename = re.compile(regex_filename)
    threatscore = str(re.findall(r_threatscore, maldetecttag))
    avdetection = str(re.findall(r_avdetection, maldetecttag))
    filename = str(re.findall(r_filename, overviewtag))
    print(line + ' ' + filename + ' ' + threatscore + ' ' + avdetection + '' + url2)

with open('hashes.txt') as f:
    lines = f.read().splitlines()
    for line in lines:
        url3 = url + line
        hybridwebreq(url3)
