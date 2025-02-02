from urllib.parse import urlparse, urlencode
import ipaddress

import re #regular expressions
from bs4 import BeautifulSoup #webscraping 
#import whois
import urllib# tools for working with URLs an making network requests
import urllib.request # opening and reading URLs
from datetime import datetime # gets curretn date and time in different formats

#The first thing i want to do is get the domain of the URL, 
# this is important when trying to determine whether or 
# not we are getting phished
def getDomain(url):
    print(f"This is the original: {url}")
    domain = urlparse(url).netloc #this will give everyting after :// until the pathname "www.example.com"
    if re.match(r"^www.", domain):
        domain = domain.replace("www.", "")
    return domain


#boolean function for chcking if the url has an ip address within it
def checkForIP(url): 
    try:
        ipaddress.ip_address(url)
        ip = 1
    except:
        ip = 0
    return ip 
# @ signs are often used in phishing links because everything 
# before it is ignored and then the reall address is on the other 
# side of it
def hasAtSign(url):
    return "@" in url

#another very common thing with phishing URLs is their length, they tend 
# to be super long. the average URL is around 55-60 charactrers, so for the sake of 
# accuracy, we are going to go with 58
def tooLong(url):
    return len(url) > 58

#counts how many / are in the URL to detemrine how far this goes in the site that it is leading to
#good to have a count
def getDepth(url):
    return str(url).count('/')-2

def isRedirection(url):
    return str(url).rfind('//') - 6

def isHTTP(url):
    if(isHTTPS(url)):
        return False
    else:
        return str(url).count("http", 0, 4) 

def isHTTPS(url):
    return str(url).count("https", 0, 5)



#URL shortening is a tactic used to shorten URLs so that requrests
# are not denied and oeprate correctly no matter the legnth,
# these are used by malicious actors to redirect without 
# explicit strategy
#here are different services that shorten URLs and might be malicious
URL_shorteners = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                    r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                    r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                    r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                    r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                    r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                    r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                    r"tr\.im|link\.zip\.net"
#These are stored as raw string objects, so be reviewed in the next function
def checkForShortener(url):
    if(re.search(URL_shorteners, url) == None):
        return False
    return True

def checkForDoubleHyphen(url):
    return '--' in urlparse(url).netloc

def web_traffic(url):
    try:
        url = urllib.parse.quote(url)
        rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url="+url).read(), "xml").find("REACH")["RANK"]
        rank = int(rank)
    except TypeError:
        return 1
    if rank < 100000:
        return 1
    return 0

def testAll(url):
    if(isHTTP(url)):
        print("URL uses HTTP")
    if(isHTTPS(url)):
        print("URL uses HTTPS")
    getDomain(url)
    if(checkForIP(url)):
        print("URL contains an IP address")
    if(hasAtSign(url)):
        print("URL has an @ symbol inside of it")
    if(tooLong(url)):
        print("URL suspiciously long")
    print(f"Depth of URL is {getDepth(url)}")
    if(checkForShortener(url)):
        print("URL has shortener, probs not a great thing")
    if(checkForDoubleHyphen(url)):
        print("URL has double hyphen (2 dashes), suspicious")




if __name__ == '__main__':
    getDomain("http://www.instagram.com")
    testAll("http://git--hub.com/shreyagopal/Phishing-Website-Detection-by-Machine-Learning-Techniques/blob/master/URLFeatureExtraction.py")
    testAll("https://tinyurl.com/live-with-me")
    testAll("http://doiop.com/live-with-me")
