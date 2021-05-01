import requests
from requests_html import HTMLSession
from bs4 import BeautifulSoup
from colorama import *
init(autoreset=True)

# Variables:
reset = Fore.RESET
red = Fore.RED
yellow = Fore.YELLOW
green = Fore.GREEN
magenta = Fore.MAGENTA


class Crawler:
    """Crawl the DOM for vulnerabilities"""
    def __init__(self, url, cookies):
        self.url = url
        self.cookies = cookies
        self.session = HTMLSession()
        self.r = requests.get(self.url, cookies=self.cookies)
        self.bs = BeautifulSoup(self.r.text, 'html.parser')
        self.forms = []
        self.inputs = []  # May need this list later
        self.find_forms()

    def find_forms(self):
        for form in self.bs.find_all('form'):
            self.forms.append(str(form))
        print('\n' + '-' * 80)
        print(yellow + '[+] Injection Points on ' + self.url + ':')
        print('-' * 80)
        print('\t[-]' + red + self.url + ' contains ' + str(len(self.forms)) + ' form tag(s):')
        self.find_input()

    def find_input(self):
        for form in self.bs.find_all('input'):
            self.inputs.append(str(form))

        print('\n\t[-]' + red + self.url + ' contains ' + str(len(self.inputs)) + ' input tag(s):')
        self.display()

    def display(self):
        if len(self.forms) == 0:
            print("\n No forms were found on " + self.url)
            exit()
        else:
            f_ans = input("\nView forms and input tags? [y/n]: ")
            if f_ans == 'n'.lower():
                exit()
            elif f_ans == 'y'.lower():
                for line in self.forms:
                    print("-" * 80)
                    print("\n" + line.replace("<form", red + "<form" + reset) + line.replace("<input", red + "<input" +
                                                                                             reset))
            else:
                self.display()