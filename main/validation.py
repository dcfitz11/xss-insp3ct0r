import requests
import time
from requests_html import HTMLSession
from colorama import *
init(autoreset=True)

# Variables:
reset = Fore.RESET
red = Fore.RED
yellow = Fore.YELLOW
green = Fore.GREEN
magenta = Fore.MAGENTA
l_blue = Fore.LIGHTBLUE_EX


class ValidateURL:
    """Validate that the URL is reachable"""
    def __init__(self, url):
        self.url = url
        self.session = HTMLSession()
        self.r = requests.get(self.url)
        self.val_url()

    def val_url(self):
        if len(self.url) == 0:
            print("\n{0}No web page was entered.".format(red))

        else:
            try:
                print("\nAttempting to establish connection to " + self.url + "...")
                self.r = self.session.get(self.url)
                if self.r.status_code == 200:
                    print("\tConnection Successful")
                    print("\tConnected to " + self.url + " on " + time.ctime())
                else:
                    print("Connection to " + self.url + " received a status code "
                                                        "of " + red + str(self.r.status_code))
                    exit()
            except (ConnectionError, requests.exceptions.ConnectionError):
                print(self.r.status_code)
                print("\n" + red + "Failed to establish a connection to " + self.url)
                exit()