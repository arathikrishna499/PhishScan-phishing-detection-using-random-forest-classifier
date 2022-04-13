import ipaddress
import re
import socket
import requests
import regex
import ssl
import whois
import time
import tldextract
import favicon
import string
import urllib.request

from googlesearch import search
from bs4 import BeautifulSoup
from datetime import datetime
from datetime import date
from tldextract import extract
from subprocess import *
from requests_html import HTMLSession
from urllib.parse import urljoin
from dateutil.parser import parse as date_parse


def having_ip_address(domain):

    if domain == "" or domain == None:
        return -1
    else:
        split_url = domain.replace(".", "")
        #print(split_url)

        counter_hex = 0
        for i in split_url:
            if i in string.hexdigits:
                counter_hex +=1

        total_len = len(split_url)
        #print(total_len)
        #print(counter_hex)
        having_IP_Address = 1
        if counter_hex >= total_len:
            having_IP_Address = -1
            
        return having_IP_Address



def url_length(url):
    
    if len(url) < 54:
        return 1
    elif len(url) >= 54 and len(url) <= 75:
        return 0
    else:
        return -1


def shortening_service(domain):

    if domain == "" or domain == None:
        return -1

    else:
    
        famous_short_urls = ["bit.ly", "tinyurl.com", "goo.gl","rebrand.ly", "t.co", "youtu.be","ow.ly", "w.wiki", "is.gd",
                                "shorte.st","go2l.ink","x.co","tr.im","cli.gs","yfrog.com","migre.me","ff.im","tiny.cc","url4.eu",
                                "twit.ac","su.pr","twurl.nl","snipurl.com","short.to","BudURL.com","ping.fm","post.ly","Just.as",
                                "bkite.com","snipr.com","fic.kr","loopt.us","doiop.com","short.ie","kl.am","wp.me",
                                "rubyurl.com","om.ly","to.ly","bit.do","t.co","lnkd.in","db.tt","qr.ae","adf.ly","bitly.com",
                                "cur.lv","ity.im","q.gs","po.st","bc.vc","twitthis.com","u.to","j.mp","buzurl.com","cutt.us",
                                "u.bb","yourls.org","prettylinkpro.com","scrnch.me","filoops.info","vzturl.com","qr.net","1url.com",
                                "tweez.me","v.gd","tr.im","link.zip.net"]
        #domain_of_url = url.split("://")[1]
        #domain_of_url = domain_of_url.split("/")[0]
        status=1
        if domain in famous_short_urls:
                status = -1
        return status


def at_in_url(url):
    
    label = 1
    at_symbol = url.find("@")
    #print(at_symbol)
    if at_symbol!=-1:
         label = -1
    return label
    #data['Having_At_Symbol']=label


def double_slash_redirecting(url):
    
    #index = url.find("://")
    #split_url = url[index+3:]
    #x = 1
    #index = split_url.find("//")
    #if index!=-1:
        #x = -1
    #return x
    #data['Double_slash_redirecting']=x
    
    
    list=[x.start(0) for x in re.finditer('//', url)]
    #print (list)
    l=len(list)-1
    #print(list[l])
    if list[l]>6:
        if list[l]>7:
            return -1
        else:
            return 1
    else:
        return 1


def prefix_suffix(domain):

    if domain == "" or domain == None:
        return -1
    
    else:
        y= 1
        index = domain.find("-")
        #print(index)
        if index!=-1:
            y = -1 
        return y
        #data['Prefix_Suffix']=y


def having_sub_domain(domain):

    if domain == "" or domain == None:
        return -1

    else:
    
        index = domain.rfind(".")
        #print(index)
        if index!=-1:
            split_url = domain[:index]
        #print(split_url)
        counter = 0
        for i in split_url:
            if i==".":
                counter+=1

        label = 1
        if counter==2:
            label = 0
        elif counter >=3:
            label = -1

        return label


def ssl_final_state(url):
    
    try:
        #check wheather contains https  
        
        #print(index)
        if re.match(r"^https?", url):
            https=1
        else: 
            https=0
        #print(https)
        
            
        #getting the certificate issuer to later compare with trusted issuer 
        #getting host name
        subDomain, domain, suffix = extract(url)
        host_name = domain + "." + suffix
        context = ssl.create_default_context()
        sct = context.wrap_socket(socket.socket(), server_hostname = host_name)
        sct.connect((host_name, 443))
        certificate = sct.getpeercert()
        #print("certificate : ",certificate)
        issuer = dict(x[0] for x in certificate['issuer'])
        certificate_Auth = str(issuer['organizationName'])
        certificate_Auth = certificate_Auth.split()
        #print(certificate_Auth)
        
        if(certificate_Auth[0] == "Network" or certificate_Auth[0] == "Deutsche" or certificate_Auth[0] == "Entrust"):
            certificate_Auth = certificate_Auth[0] + " " + certificate_Auth[1]
           
        else:
            certificate_Auth = certificate_Auth[0] 
          
            
        trusted_Auth = ['Amazon','Comodo','Cybertrust','Symantec','GoDaddy.com,','GlobalSign','DigiCert','StartCom','Entrust','Verizon','Trustwave','Unizeto','Buypass',
                        'QuoVadis','Deutsche Telekom','Network Solutions','SwissSign','IdenTrust','Secom','TWCA','GeoTrust','Thawte',
                        'Doster','VeriSign','LinkedIn','Let\'s', 'Sectigo','RapidSSLonline', 'SSL.com', 'Entrust Datacard','Google', 'Facebook']        
        
        #getting age of certificate
        start_date = str(certificate['notBefore'])
        end_date = str(certificate['notAfter'])
        start_year = int(start_date.split()[3])
        end_year = int(end_date.split()[3])
        age_of_certificate = end_year-start_year
        #print(age_of_certificate)  
        
        #checking final conditions
        if((https==1) and (certificate_Auth in trusted_Auth) and (age_of_certificate>=1) ):
            return 1 #legitimate
       
        elif((https==1) and (certificate_Auth in trusted_Auth)):
            return 0 #suspicious
        
        else:
            return -1 #phishing
        
    except Exception as e:
        #print("SSL Exception")
        return -1


def domain_registration_length(whois_response):
    
   
    try:
        expiration_date = whois_response.expiration_date
        registration_length = 0
        list_check = isinstance(expiration_date, list)
        if (list_check==True):
            expiration_date = min(expiration_date)
        #print("Expiration date = ", expiration_date)
        today = time.strftime('%Y-%m-%d')
        today = datetime.strptime(today, '%Y-%m-%d')
        registration_length = abs((expiration_date - today).days)

        if registration_length / 365 <= 1:
            return -1
            
        else:
            return 1
            
    except:
        return -1
        

def favicon(url):
    
    try:
        extract_res = tldextract.extract(url)
        url_ref = extract_res.domain

        favs = favicon.get(url)
        #print(favs)
        match = 0
        for favi in favs:
            url2 = favi.url
            extract_res = tldextract.extract(url2)
            url_ref2 = extract_res.domain

            if url_ref in url_ref2:
                  match += 1

        if match >= len(favs)/2:
            #print("Inside if favicon")
            return 1
            #data['Favicon']=1
        else:
            #print("Inside else favicon")
            return -1
            #data['Favicon']=-1
    except:
        #print("Inside except favicon")
        return -1
        #data['Favicon']=-1


def port(domain):

    if domain == "" or domain == None:
        return -1
    
    else:
    
        try:
            port = domain.split(":")[1]
            if port:
                return -1
                #data['Port']=-1
            else:
                return 1
                #data['Port']=1
        except:
            return 1
            #data['Port']=1


def https_token(domain):

    if domain == "" or domain == None:
        return -1
    else:
        index = domain.find('//https')
        if index != -1:
            return -1
            #data['HTTPS_token']=1
        else:
            return 1
            #data['HTTPS_token']=-1 


def request_url(url,domain,soup):
    
    i = 0
    success = 0
    
    try:

        if soup == -999:
            #print("Request URL : Soup -999")
            return -1
            #data['Request_URL']=-1
            
        else:
            for img in soup.find_all('img', src= True):
                dots= [x.start(0) for x in re.finditer('\.', img['src'])]
                if url in img['src'] or domain in img['src'] or len(dots)==1:
                    success = success + 1
                i=i+1

            for audio in soup.find_all('audio', src= True):
                dots = [x.start(0) for x in re.finditer('\.', audio['src'])]
                if url in audio['src'] or domain in audio['src'] or len(dots)==1:
                    success = success + 1
                i=i+1

            for embed in soup.find_all('embed', src= True):
                dots=[x.start(0) for x in re.finditer('\.',embed['src'])]
                if url in embed['src'] or domain in embed['src'] or len(dots)==1:
                    success = success + 1
                i=i+1

            for iframe in soup.find_all('iframe', src= True):
                dots=[x.start(0) for x in re.finditer('\.',iframe['src'])]
                if url in iframe['src'] or domain in iframe['src'] or len(dots)==1:
                    success = success + 1
                i=i+1

            try:
                percentage = success/float(i) * 100
                print("Request URL percentage = ",percentage)
                
                if percentage < 22.0 :
                    return 1
                    #data['Request_URL']=1
                elif((percentage >= 22.0) and (percentage < 61.0)) :
                    return 0
                    #data['Request_URL']=0
                else :
                    return -1
                    #data['Request_URL']=-1
            except:
                return 1
                #data['Request_URL']=1

    except:
        return -1


def url_of_anchor(url,domain,soup):
    
    percentage = 0
    i = 0
    unsafe=0
    
    try:

        if soup == -999:
            return -1
            #data['URL_of_Anchor']=-1
            
        else:
            for a in soup.find_all('a', href=True):
            # 2nd condition was 'JavaScript ::void(0)' but we put JavaScript because the space between javascript and :: might not be
                    # there in the actual a['href']
                if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (url in a['href'] or domain in a['href']):
                    unsafe = unsafe + 1
                i = i + 1


            try:
                percentage = unsafe / float(i) * 100
                print("URL of Anchor percentage = ",percentage)
                
                if percentage < 31.0:
                    return 1
                    #data['URL_of_Anchor']=1
                elif ((percentage >= 31.0) and (percentage <= 67.0)):
                    return 0
                    #data['URL_of_Anchor']=0
                else:
                    return -1
                    #data['URL_of_Anchor']=-1
            except:
                return 1
                #data['URL_of_Anchor']=1
    except:
        return -1


def links_in_tags(url,domain,soup):
    
    i=0
    success =0
    try:

        if soup == -999:
            return -1
            #data['Links_in_tags']=-1
            
        else:
            for link in soup.find_all('link', href= True):
                dots=[x.start(0) for x in re.finditer('\.',link['href'])]
                if url in link['href'] or domain in link['href'] or len(dots)==1:
                    success = success + 1
                i=i+1

            for script in soup.find_all('script', src= True):
                dots=[x.start(0) for x in re.finditer('\.',script['src'])]
                if url in script['src'] or domain in script['src'] or len(dots)==1 :
                    success = success + 1
                i=i+1
            try:
                percentage = success / float(i) * 100
                print("Links in tags percentage = ",percentage)
                
                if percentage < 17.0 :
                    return 1
                    #data['Links_in_tags']=1
                elif((percentage >= 17.0) and (percentage <= 81.0)) :
                    return 0
                    #data['Links_in_tags']=0
                else :
                    return -1
                    #data['Links_in_tags']=-1
            except:
                return 1
                #data['Links_in_tags']=1

    except:
        return -1


def sfh(url):
    
    try:
        programhtml = requests.get(url).text
        s = BeautifulSoup(programhtml,"lxml")
        #print("Inside sfh try")
        f = str(s.form)
        ac = f.find("action")
        if(ac!=-1):
            i1 = f[ac:].find(">")
            u1 = f[ac+8:i1-1]
            if(u1=="" or u1=="about:blank"):
                #print("Inside about blank if")
                return -1
                #data['SFH']=-1
            erl1 = tldextract.extract(url)
            upage = erl1.domain
            erl2 = tldextract.extract(u1)
            usfh = erl2.domain
            if upage in usfh:
                #print("Inside sfh inner if")
                return 1
                #data['SFH']=1
                
            else:
                #print("Inside sfh inner else")
                return 0
                #data['SFH']=0
        else:
            #print("Inside sfh outer else")
            return 1
            #data['SFH']=1
    except:
        #print("Inside sfh except")
        return -1
        #data['SFH']=-1 



def check_submit_to_email(response):

    if response == "":
        return -1

    else:
        html_content = response.text
        soup = BeautifulSoup(html_content, "lxml")
        
        # Check if no form tag
        form_opt = str(soup.form)
        index = form_opt.find("mail()")
        
        if index == -1:
            index = form_opt.find("mailto:")

        if index == -1:
            return 1
        
        return -1


def abnormal_url(url): #host name not included in URL - phishing, otherwise - legitimate
    
    index = url.find("://")
    split_url = url[index+3:]
    #print(split_url)
    index = split_url.find("/")
    if index !=-1:
        split_url = split_url[:index]
    #print(split_url)
    if re.match(r"^www.",split_url):
        split_url = split_url.replace("www.","")
    #print(split_url)
    split_url=split_url.lower()

    try:
    
        whois_response=whois.whois(url)
        #print(whois_response)
        d = whois_response.domain_name
        #print(d)
        
        if d == "" or d == None:
            return -1
        else:
            list_check = isinstance(d, list)
            
            if(list_check==True):
                d=d[1].lower()
                if d==split_url:
                    return 1
                else:
                    return -1
                    
            
            else:
                d=d.lower()
                if d == split_url:
                    return 1
                else:
                    return -1
    except:
        return -1


def web_forwarding(response):
    
    if response=="":
        return -1
    else:
        if len(response.history)<=1:
            return 1
        elif len(response.history)>=2 and len(response.history)<4:
            return 0
        else:
            return -1


def on_mouseover(response):
    
    if response == "" :
        return -1
        #data['On_mouseover']=-1
    else:
        if re.findall("<script>.+onmouseover.+</script>", response.text):
            return -1
            #data['On_mouseover']=-1
        else:
            return 1
            #data['On_mouseover']=1


def right_click(response):
    
    if response == "":
        return 1
    else:
        if re.findall(r"event.button ?== ?2", response.text):
            return 1
        else:
            return -1


def popup_window(response):
    
    if response == "":
        return -1
    else:
        if re.findall(r"alert\(", response.text):
            return -1
        else:
            return 1


def iframe(response):
    
    if response=="":
        return -1
    else:
        soup = BeautifulSoup(response.text, "lxml")
        if str(soup.iframe).lower().find("frameborder") == -1:
            return 1
        return -1


def age_of_domain(whois_response):
    
      
    try:
        creation_date = whois_response.creation_date
        expiration_date = whois_response.expiration_date
        list_check_1 = isinstance(creation_date, list)
        list_check_2 = isinstance(expiration_date, list)
        if (list_check_1==True and list_check_2==True):
            c_date = min(creation_date)
            e_date = min(expiration_date)
    
                 
        if (isinstance(c_date,str) or isinstance(e_date,str)):
                c_date = datetime.strptime(c_date,'%Y-%m-%d')
                e_date = datetime.strptime(e_date,"%Y-%m-%d")
                
        age = abs((e_date - c_date).days)
        age = int(age/30)
        
        if (age >= 6):
            return 1
        else:
            return -1
    
    except:
        print("Age of domain exception")
        return -1


def check_dns_record(url):
    
    extract_res = tldextract.extract(url)
    url_ref = extract_res.domain + "." + extract_res.suffix
    
    try:
        whois_res = whois.whois(url_ref)
        #print(whois_res)
        return 1
    
    except:
        return -1


def website_traffic(url):
    
    try:
        rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
        rank= int(rank)
        #print("Page Rank = ",rank)
        
        if (rank<100000):
            return 1
            #data['Web_Traffic']=1
        else:
            return 0
            #data['Web_Traffic']=0
            
    except TypeError:
        return -1
        #data['Web_Traffic']=-1


def page_rank(domain):

    if domain == "" or domain == None:
        return -1

    else:

        try:
        
            session = HTMLSession()
            res = session.get('https://checkpagerank.net/')
            soup = BeautifulSoup(res.html.html, "html.parser")
            forms=soup.find_all("form")
            new_form=forms[1]
            
            details = {}
            action = new_form.attrs.get("action").lower()
            method = new_form.attrs.get("method", "get").lower()
            
            inputs = []
            for input_tag in new_form.find_all("input"):
                # get type of input form control
                input_type = input_tag.attrs.get("type", "text")
                # get name attribute
                input_name = input_tag.attrs.get("name")
                # get the default value of that input tag
                input_value =input_tag.attrs.get("value", "")
                # add everything to that list
                inputs.append({"type": input_type, "name": input_name, "value": input_value})
                
            # put everything to the resulting dictionary
            details["action"] = action
            details["method"] = method
            details["inputs"] = inputs
            
            data = {}
            data[input_tag["name"]] = domain
            
            load = urljoin('https://checkpagerank.net/', details["action"])
            res = session.post(load, data=data)
            page_rank = re.findall(r"Google PageRank: <span style=\"color:#000099;\">([0-9]+)", res.text)
            #print(global_rank)
            page_rank=int(page_rank[0])
            #print("Google PageRank = ",page_rank)

            if page_rank > 2:
                return 1
            else:
                return -1

        except:
            #print("Google Page Rank Exception")
            return -1


def google_index(url):

    try:
    
        site=search(url, 5)
        print("Site = ",site)
        
        if site:
            return 1
            #data['Google_Index']=1
        else:
            return -1
            #data['Google_Index']=-1

    except:
        return -1


def links_pointing_to_page(response):
    
        if response == "":
            return -1
            #data['Links_pointing_to_page']=-1
            
        else:
            number_of_links = len(re.findall(r"<a href=", response.text))
            if number_of_links == 0:
                return -1
                #data['Links_pointing_to_page']=1
            elif number_of_links > 0 and number_of_links <= 2:
                return 0
                #data['Links_pointing_to_page']=0
            else:
                return 1
                #data['Links_pointing_to_page']=-1


def statistical_report(domain):

    if domain == "" or domain == None:
        return -1
    else: 
    
        url_match=re.search('at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly',domain)
        
        try:
            ip_address=socket.gethostbyname(domain)
            ip_match=re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
                            '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                            '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                            '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
                            '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
                            '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42',ip_address)
            if url_match:
                return -1
                #data['Stastical_Report']=-1
            elif ip_match:
                return -1
                #data['Stastical_Report']=-1
            else:
                return 1
                #data['Stastical_Report']=1
        except:
            #data['Stastical_Report']=-1
            print ('Connection problem. Please check your internet connection!')
            return -1



def generate_data_set(url):
    
    dataset=[0]*30
    
    # Converts the given URL into standard format
    if not re.match(r"^https?", url):
        url = "http://" + url


    # Stores the response of the given URL
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
    except:
        response = ""
        soup = -999
    #print(soup)
    
    try:
        # Requests all the information about the domain
        whois_response = whois.whois(url)
        #print(whois_response)
        domain=whois_response.domain_name
        list_check=isinstance(domain,list)
        if(list_check==True):
            domain=domain[1].lower()
    except:
        whois_response=""
        domain=""

    start=time.time()

    dataset[0]=having_ip_address(domain)
    dataset[1]=url_length(url)
    dataset[2]=shortening_service(domain)
    dataset[3]=at_in_url(url)
    dataset[4]=double_slash_redirecting(url)
    dataset[5]=prefix_suffix(domain)
    dataset[6]=having_sub_domain(domain)
    dataset[7]=ssl_final_state(url)
    dataset[8]=domain_registration_length(whois_response)
    dataset[9]=favicon(url)
    dataset[10]=port(domain)
    dataset[11]=https_token(domain)
    dataset[12]=request_url(url,domain,soup)
    dataset[13]=url_of_anchor(url,domain,soup)
    dataset[14]=links_in_tags(url,domain,soup)
    dataset[15]=sfh(url)
    dataset[16]=check_submit_to_email(response)
    dataset[17]=abnormal_url(url)
    dataset[18]=web_forwarding(response)
    dataset[19]=on_mouseover(response)
    dataset[20]=right_click(response)
    dataset[21]=popup_window(response)
    dataset[22]=iframe(response)
    dataset[23]=age_of_domain(whois_response)
    dataset[24]=check_dns_record(url)
    dataset[25]=website_traffic(url)
    dataset[26]=page_rank(domain)
    dataset[27]=google_index(url)
    dataset[28]=links_pointing_to_page(response)
    dataset[29]=statistical_report(domain)

    end=time.time()
    
    data={}
    data['having_ip_address']=dataset[0]
    data['url_length']=dataset[1]
    data['shortening_service']=dataset[2]
    data['at_in_url']=dataset[3]
    data['double_slash_redirecting']=dataset[4]
    data['prefix_suffix']=dataset[5]
    data['having_sub_domain']=dataset[6]
    data['ssl_final_state']=dataset[7]
    data['domain_registration_length']=dataset[8]
    data['favicon']=dataset[9]
    data['port']=dataset[10]
    data['https_token']=dataset[11]
    data['request_url']=dataset[12]
    data['url_of_anchor']=dataset[13]
    data['links_in_tags']=dataset[14]
    data['sfh']=dataset[15]
    data['check_submit_to_email']=dataset[16]
    data['abnormal_url']=dataset[17]
    data['web_forwarding']=dataset[18]
    data['on_mouseover']=dataset[19]
    data['right_click']=dataset[20]
    data['popup_window']=dataset[21]
    data['iframe']=dataset[22]
    data['age_of_domain']=dataset[23]
    data['check_dns_record']=dataset[24]
    data['website_traffic']=dataset[25]
    data['page_rank']=dataset[26]
    data['google_index']=dataset[27]
    data['links_pointing_to_page']=dataset[28]
    data['statistical_report']=dataset[29]

    count=0
    l=[]
    l.append(dataset)
    l.append(end-start)  

    for i in dataset:
        count+=1       
        
    print("Enter URL : ",url)
    print("\nNumber of features extracted = ", count)
    print("Time taken to generate dataset =%.2f"%l[1]," seconds")
    print("The generated dataset is : ")
    print(dataset)
    print("\n")
    [print (key,':',value) for key,value in data.items()]
    print("\n")        
    return l


#url=input("Enter URL :")
#generate_data_set(url)