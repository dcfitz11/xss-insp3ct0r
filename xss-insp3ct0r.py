from main.validation import ValidateURL
from main.crawler import Crawler
from main.headers import InspectHeaders
from main.dom import DOMinspect
from main.parametercheck import ParamInject
from main.formcheck import FormTest
from main.fuzzer import Fuzz
from selenium import webdriver
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.firefox.service import Service  # Fixes the deprecation warning
from selenium.common.exceptions import WebDriverException
import pyfiglet
from colorama import *
init(autoreset=True)

# Variables:
reset = Fore.RESET
red = Fore.RED
yellow = Fore.YELLOW
green = Fore.GREEN
magenta = Fore.MAGENTA


class Menu:
    def __init__(self):
        self.cookies = None
        self.banner()

    def banner(self):
        ascii_banner = pyfiglet.figlet_format("XSS INSP3CT0R")
        print(red + ascii_banner)
        self.usage()

    def usage(self):
        print("-" * 70)
        print(yellow + "[+] Usage:")
        print("\n\tXSS-Detector provides several options to automate the discovery of {0}"
              "\tCross Site Scripting (XSS) vulnerabilities. If one option fails to {0}"
              "\tproduce positive results, try selecting a different Menu option.\n".format('\n'))
        print("-" * 70)
        print(yellow + "[+] Headless Browsing:")
        print("\n" + "-" * 70)
        self.options()

    def options(self):
        options = ['{0}Crawl and Identify Injection Points'.format(yellow),
                   '{0}Inspect Server Headers for Vulnerabilities'.format(yellow),
                   '{0}Detect DOM Vulnerabilities'.format(yellow),
                   '{0}Test the First Parameter in the URL'.format(yellow),
                   "{0}Test A <form> Tag's Input Fields".format(yellow),
                   '{0}Fuzz A Specific URL Parameter'.format(yellow)]

        print(yellow + "[+] Menu Options:\n")

        for index, item in enumerate(options, start=1):
            print(index, item)

        while True:
            try:
                user_input = int(input("\nSelect an " + yellow + "option "
                                       + reset + "from 1-{}: ".format(len(options))))
            except ValueError:
                print("{0}That's not a valid option.".format(red))
                continue
            if user_input <= 0 or user_input > 9:
                print("{0}That's not a valid option.".format(red))
                continue
            else:
                break

        if user_input == 1:
            self.op_1_usage()
            ValidateURL(self.url)
            Crawler(self.url, self.cookies)
        elif user_input == 2:
            self.op_2_usage()
            ValidateURL(self.url)
            InspectHeaders(self.url, self.cookies)
        elif user_input == 3:
            self.op_3_usage()
            ValidateURL(self.url)
            DOMinspect(self.url, self.cookies)
        elif user_input == 4:
            self.op_4_usage()
            ValidateURL(self.url)
            ParamInject(self.url, self.cookies)
        elif user_input == 5:
            self.op_5_usage()
            ValidateURL(self.url)
            FormTest(self.url, self.cookies)
        elif user_input == 6:
            self.op_6_usage()
            ValidateURL(self.url)
            Fuzz(self.url, self.cookies)

    def op_1_usage(self):
        print("-" * 80)
        print(yellow + "[+] Crawler Usage:")
        print("\n\t[-] Enter a URL to submit to the Crawler:")
        print("\t\tEx: https://www.google.com")
        self.url = input("\nEnter the URL of the page you wish to test: ")
        if len(self.url) == 0:
            print(red + "You didn't enter a URL")
            self.op_1_usage()
        self.cookie_op()
        print("-" * 80)

    def op_2_usage(self):
        print("-" * 80)
        print(yellow + "[+] Inspect Headers Usage:")
        print("\n\t[-]Enter a URL to inspect its headers:")
        print("\t\tEx: https://www.google.com")
        self.url = input("\nEnter the URL of the page you wish to test: ")
        if len(self.url) == 0:
            print(red + "You didn't enter a URL")
            self.op_2_usage()
        self.cookie_op()
        print("-" * 80)

    def op_3_usage(self):
        print("-" * 80)
        print(yellow + "[+] DOMinspect Usage:")
        print("\n\t[-] Enter a URL to inspect its DOM:")
        print("\t\tEx: https://www.google.com")
        self.url = input("\nEnter the URL of the page you wish to test: ")
        if len(self.url) == 0:
            print(red + "You didn't enter a URL")
            self.op_3_usage()
        self.cookie_op()
        print("-" * 80)

    def op_4_usage(self):
        print("-" * 80)
        print(yellow + "[+] ParamInject Usage:")
        print("\n\t[-] Enter a URL that includes a parameter(?), such as:")
        print("\t\tEx: https://xss-game.appspot.com/level1/frame?query=test")
        print("\t\tEx: http://sudo.co.il/xss/level1.php?email=test#")
        print("\n\tNOTE: If a specific parameter must be specified, select option #6 in the menu options instead.")
        self.url = input("\nEnter the URL of the page you wish to test: ")
        if len(self.url) == 0:
            print(red + "You didn't enter a URL")
            self.op_3_usage()
        self.cookie_op()
        print("-" * 80)

    def op_5_usage(self):
        print("-" * 80)
        print(yellow + "[+] FormTest Usage:")
        print("\n\t[-] Enter a URL that contains a <form> tag(s):")
        print("\t\tEx: https://xss-game.appspot.com/level1/frame")
        print("\t\tEx: https://xss-quiz.int21h.jp/")
        self.url = input("\nEnter the URL of the page you wish to test: ")
        if len(self.url) == 0:
            print(red + "You didn't enter a URL")
            self.op_5_usage()
        self.cookie_op()
        print("-" * 80)

    def op_6_usage(self):
        print("-" * 80)
        print(yellow + "[+] Fuzz Usage:")
        print('\n\t[-] Enter a URL and replace the the value in the URL for the parameter you wish to \n\t\t'
              'fuzz with the word, "FUZZ". NOTE: only one parameter can be tested at a time!')
        print("\t\tEx: https://xss-game.appspot.com/level1/frame?query=FUZZ")
        print("\t\tEx: http://sudo.co.il/xss/level1.php?email=FUZZ#")
        self.url = input("\nEnter the URL of the page you wish to test: ")
        if len(self.url) == 0:
            print(red + "You didn't enter a URL")
            self.op_6_usage()
        self.cookie_op()
        print("-" * 80)

    def cookie_op(self):
        ans = input("\nAdd a cookie with the request? (Note: This may be necessary for web sites that \n"
                    "require authentication; Otherwise, skip this option) [y/n]: ")
        if ans.lower() == "n":
            self.cookies = None
        elif ans.lower() == "y":
            print(yellow + '\n[+] Returning cookies for ' + self.url + ': \n')
            try:
                service = Service('/usr/local/bin/geckodriver')  # Fixes the deprecation warning.
                options = FirefoxOptions()
                options.add_argument("--headless")
                driver = webdriver.Firefox(service=service)
            except (IOError, OSError) as e:
                print("\n" + e)
                exit()
            except WebDriverException as e:
                print("\n" + str(e))
                print("Ensure that 'geckodriver' is in the /usr/local/bin directory")
                exit()

            driver.get(self.url)
            print(driver.get_cookies())
            print(green + '\nEx: cookiename:cookievalue:cookiepath')
            self.cookies = input("Enter a cookie string: ")
            if len(self.cookies) == 0:
                print("A cookie was not entered. Try again.")
                self.cookie_op()
            else:
                parse_cookies = self.cookies.split(':')
                self.cookies = {
                    'name': parse_cookies[0],
                    'value': parse_cookies[1],
                    'path': parse_cookies[2]
                }
        else:
            self.cookie_op()


m = Menu()
