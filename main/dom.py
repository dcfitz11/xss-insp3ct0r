import requests
from bs4 import BeautifulSoup
from requests_html import HTMLSession
from colorama import *
init(autoreset=True)

# Variables:
reset = Fore.RESET
red = Fore.RED
yellow = Fore.YELLOW
green = Fore.GREEN
magenta = Fore.MAGENTA
cyan = Fore.LIGHTCYAN_EX


class DOMinspect:
    def __init__(self, url, cookies):
        self.url = url
        self.cookies = cookies
        self.session = HTMLSession()
        self.r = requests.get(self.url, cookies=self.cookies)
        self.page = self.r.text
        self.bs = BeautifulSoup(self.r.text, 'html.parser')
        self.links = []
        self.http_links()

    def http_links(self):
        """Displays all unencrypted links"""
        self.links = []
        for link in self.bs.find_all('a'):
            self.links.append(str(link.get('href')))
        print('\n' + '-' * 80)
        print(yellow + '[+] Suspicious Links on ' + self.url + ':')
        print('-' * 80)
        print(red + '[+] Unencrypted links:')
        unencrypted_links = []
        try:
            for link in self.links:
                if link is None:
                    pass
                elif link.startswith('http:/'):
                    unencrypted_links.append(link)
                    for line in unencrypted_links:
                        print('\t' + line)  # display unencrypted links
        except AttributeError:
            pass
        self.sop_viol()

    def sop_viol(self):
        """Displays all SOP violations"""
        www_link = False
        if '//www.' in self.url:
            www_link = True
            split_www_url = self.url.split('//www.')  # split 'www' from the url
            base_url = split_www_url[1]  # (e.g., 'google.com')
            global www_url
            global dom_url
            www_url = 'https://www.' + base_url  # (e.g., 'https://www.google.com')
            dom_url = 'https://' + base_url  # (e.g., 'https://google.com')
        else:
            pass

        print(red + '\n[+] SOP violations:')
        sop = []
        try:
            for link in self.links:
                if link is None:
                    pass
                elif not link.startswith(self.url):
                    sop.append(link)
        except AttributeError:
            pass

        if www_link is True:
            www_junk = (www_url, dom_url, '#', 'http:', '/', '\\')  # junk that isn't considered SOP violations
            for line in sop[:]:  # for all elements in the sop array
                if line.startswith(www_junk):
                    sop.remove(line)
            for line in sop:
                if line != '':  # removes arbitrary blanks
                    print('\t' + line)

        if www_link is False:
            split_domurl = self.url.split('https://')  # split 'www' from the url
            base_url = split_domurl[1]
            dom_url = 'https://' + base_url
            www_url = 'https://www.' + base_url
            dom_junk = (www_url, dom_url, '#', 'http:', '/', '\\')
            for line in sop[:]:
                if line.startswith(dom_junk):
                    sop.remove(line)
            for line in sop:
                if line != '':
                    print('\t' + line)
        self.disclaim()

    def disclaim(self):
        """Displays disclaimer since the following methods yield a ton of info"""
        print('\n' + '-' * 80)
        print(yellow + '[+] Potential DOM XSS Vulnerabilities on ' + self.url + ':')
        print("{0}{1}DOMinspect searches through the page's source code for certain "
              "{0}{1}keywords that may be indicative of javascript sources and sinks "
              "{0}{1}whereby untrusted data can enter the web application. A source "
              "{0}{1}is a DOM object capable of accepting data whereas a sink is a "
              "{0}{1}DOM API capable of executing a script stored as text. This will "
              "{0}{1}result in some false-positives.".format('\n\t', '\t'))
        ans = input("\nContinue testing for DOM vulnerabilities [y/n]?: ")
        if ans == 'y'.lower():
            self.sources()
        elif ans == 'n'.lower():
            exit()
        else:
            self.disclaim()

    def sources(self):
        print('-' * 80)
        print(yellow + "[+] Possible 'Sources' discovered on " + self.url + ":")
        print("It is possible that XSS vulnerabilities may be introduced into the {0}"
              "web application via the following sources:".format('\n'))
        with open('dom-info/sources.txt', 'r') as f_object:
            for x in f_object:
                x = x.strip('\n')
                for line in self.page.splitlines():
                    js_sources = []
                    if x in line:
                        print('\n[-]Source Keyword Found: ' + magenta + x.replace('=', '') + '\n' + reset + line.replace(x, red + x + reset).strip())
                        js_sources.append(x)
        if js_sources is None:
            print('\n\t{}None Found'.format(green))
        else:
            pass
        self.dir_exec_sinks()

    def dir_exec_sinks(self):
        print(yellow + "\n[+] Possible 'Execution Sinks' discovered on " + self.url + ":")
        print("The following attributes & JavaScript functions are used to parse strings as JavaScript. If {0}"
              "untrusted and unencoded data is placed into these functions, then it is possible {0}"
              "for attackers to execute their own JavaScript.".format('\n'))
        with open('dom-info/direct-exec-sinks.txt', 'r') as f_object:
            for x in f_object:
                x = x.strip('\n')
                for line in self.page.splitlines():
                    execution_sinks = []
                    if x in line:
                        print('\n[-]Sink Keyword Found: ' + magenta + x.replace('=', '') + '\n' + reset + line.replace(x, red + x + reset).strip())
                        execution_sinks.append(x)
        if execution_sinks is None:
            print('\n\t{}None Found'.format(green))
        self.wit_exec_sinks()

    def wit_exec_sinks(self):
        print(yellow + "\n[+] Possible 'Event Handlers' discovered on " + self.url + ":")
        print("The following JavaScript event handlers 'react' to certain events. If untrusted {0}"
              "and unencoded data is placed into these event handlers, then it is possible for {0}"
              "attackers to execute their own javaScript.".format('\n'))
        with open('dom-info/events.txt', 'r') as f_object:
            for x in f_object:
                x = x.strip('\n')
                for line in self.page.splitlines():
                    event_handlers = []
                    if x in line:
                        print('\n[-]Sink Keyword Found: ' + magenta + x.replace('=', '') + '\n' + reset + line.replace(x, red + x + reset).strip())
                        event_handlers.append(x)
        if event_handlers is None:
            print('\n\t{}None Found'.format(green))
        self.html_man_sinks()

    def html_man_sinks(self):
        print(yellow + "\n[+] Possible 'HTML Manipulation sinks' discovered on " + self.url + ":")
        print("The following operations allow for HTML manipulation; therefore, if it may be {0}"
              "possible to control a vulnerable argument, then it may be possible to manipulate {0}"
              "the HTML content and execute javascript.".format('\n'))
        with open('dom-info/html-manipulation-sinks.txt', 'r') as f_object:
            for x in f_object:
                x = x.strip('\n')
                for line in self.page.splitlines():
                    man_sinks = []
                    if x in line:
                        print('\n[-]Sink Keyword Found: ' + magenta + x.replace('=', '') + '\n' + reset + line.replace(x, red + x + reset).strip())
                        man_sinks.append(x)
        if man_sinks is []:
            print('\n\t{}None Found'.format(green))
        self.location_sinks()

    def location_sinks(self):
        print(yellow + "\n[+] Possible 'Location Sinks' discovered on " + self.url + ":")
        print("The following can be considered both sources or sinks; however, this depends {0}"
              "on how they are used. Unvalidated assignment to any of the listed objects could {0}"
              "lead to redirection to malicious web sites.".format('\n'))
        with open('dom-info/location-sinks.txt', 'r') as f_object:
            for x in f_object:
                x = x.strip('\n')
                for line in self.page.splitlines():
                    loc_sinks = []
                    if x in line:
                        print('\n[-]Sink Keyword Found: ' + magenta + x.replace('=', '') + '\n' + reset + line.replace(x, red + x + reset).strip())
                        loc_sinks.append(x)
        if loc_sinks is None:
            print('\n\t{}None Found'.format(green))
        self.jq_sinks()

    def jq_sinks(self):
        print(yellow + "\n[+] Possible 'Jquery Sinks' discovered on " + self.url + ":")
        print("The following jQuery methods can directly update the DOM. If untrusted or {0}"
              "unencoded data is placed into these methods, then it may be possible for {0}"
              "attackers to execute their own JavaScript.".format('\n'))
        with open('dom-info/jq-sinks.txt', 'r') as f_object:
            for x in f_object:
                x = x.strip('\n')
                for line in self.page.splitlines():
                    jquery_sinks = []
                    if x in line:
                        print('\n[-]Sink Keyword Found: ' + magenta + x.replace('(', '') + '\n' + reset + line.replace(x, red + x + reset).strip())
                        jquery_sinks.append(x)
        if jquery_sinks is None:
            print('\n\t{}None Found'.format(green))
        self.disclaimer()

    def disclaimer(self):
        print("\n{0}DISCLAIMER:".format(red))
        print("OWASP: Automated testing has limited success at identifying and {0}"
              "validating DOM-based XSS since many web sites rely on large libraries {0}"
              "of functions, which often stretch into hundreds or thousands of {0}"
              "lines of code. For this reason, manual testing should be undertaken {0}"
              "to examine the areas of code identified above, including which {0}"
              "sources extend to which sinks. For more information, please read {0}"
              "dom-based-xss.md".format('\n'))
        print("{0}\nUse F12 in FireFox to inspect the page's source code and {1}"
              "manually test the sources and sinks identified above for possible {1}"
              "vulnerabilities.".format(green, '\n'))