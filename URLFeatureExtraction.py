from urllib.parse import urlparse, urlencode
import ipaddress
import re


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

if __name__ == '__main__':
    getDomain("https://www.instagram.com")
