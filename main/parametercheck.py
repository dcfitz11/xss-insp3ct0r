import urllib
from requests_html import HTMLSession
from urllib.parse import urljoin
from selenium import webdriver
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.common.exceptions import TimeoutException, NoAlertPresentException, \
    UnexpectedAlertPresentException, InvalidSessionIdException, WebDriverException, \
    NoSuchWindowException
from urllib3.exceptions import ProtocolError, MaxRetryError, NewConnectionError
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions
from colorama import *
init(autoreset=True)

# Variables:
reset = Fore.RESET
red = Fore.RED
yellow = Fore.YELLOW
green = Fore.GREEN
magenta = Fore.MAGENTA
l_blue = Fore.LIGHTBLUE_EX


class ParamInject:
    """Test the first parameter in the URL"""
    def __init__(self, url, cookies):
        self.url = url
        self.cookies = cookies
        self.params = {}
        self.session = HTMLSession()
        self.payloads = []
        self.target_urls = []
        self.successful_payloads = []
        self.find_params()

    def find_params(self):
        new_url = urllib.parse.urlparse(self.url)  # scheme, netloc, path, params, query, fragment, etc.
        param_string = new_url.query
        self.params = dict(urllib.parse.parse_qsl(param_string))
        print(yellow + "\n[+] Returning Parameters:")
        for key in self.params:
            print(yellow + '\t[-]' + magenta + key)
        self.xsspayloads()

    def xsspayloads(self):
        with open('payloads/xssvectors.txt', 'r') as payload_file:
            for payload in payload_file.readlines():
                payload = payload.strip('\n')
                self.payloads.append(payload)
        self.injector()

    def injector(self):
        print('\nParamInject will test the first parameter in the URL by \n'
              'injecting harmless XSS payloads. If you wish to test a \n'
              'specific parameter, try menu option 6 - FUZZ')

        # Split base_url from parameters:
        split_url = self.url.split('?')
        base_url = split_url[0]

        # Replace parameter value with encoded payload:
        for param in self.params.keys():
            for payload in self.payloads:
                self.params[param] = payload
                encoded_params = urllib.parse.urlencode(self.params)  # encode the payloads
                target_url = str(base_url) + '?' + str(encoded_params)  # construct the full target url to submit
                self.target_urls.append(target_url)
        self.test(self.target_urls)

    def test(self, urls):
        try:
            options = FirefoxOptions()
            # options.add_argument("--headless")   # Uncomment this line below if you prefer a 'headless' browser.
            driver = webdriver.Firefox(options=options, executable_path='/usr/local/bin/geckodriver')
        except (IOError, OSError) as e:
            print("\n" + e)
            exit()
        except WebDriverException as e:
            print("\n" + str(e))
            print("Ensure that 'geckodriver' is in the /usr/local/bin directory")
            exit()

        print("\n" + "-" * 80)
        print(yellow + "[+] Testing for XSS on: " + self.url + "\n")
        for url in urls:
            try:
                print('Testing ' + url)
                driver.get(url)
                if self.cookies:
                    driver.add_cookie(self.cookies)
                if WebDriverWait(driver, 1).until(expected_conditions.alert_is_present()):
                    driver.switch_to.alert.accept()
                    print(green + '\t[+]XSS FOUND' + '\n')
                    self.successful_payloads.append(url)
            except (TimeoutException, NoAlertPresentException, UnexpectedAlertPresentException,
                    InvalidSessionIdException, NoSuchWindowException):
                pass
            except BrokenPipeError:
                print(red + "\nBrokenPipeError" + reset + ": Broken pipe")
                self.results()
            except ProtocolError:
                print(red + "\nProtocolError" + reset + ": Connection Aborted")
                self.results()
            except ConnectionRefusedError:
                print(red + "\nConnectionRefusedError" + reset + ": Connection Refused")
                self.results()
            except NewConnectionError:
                print(red + "\nNewConnectionError: Failed to establish a new connection" + reset + ": "
                                                                                                   "Connection Refused")
                self.results()
            except MaxRetryError:
                print(red + "\nMaxRetryError: Failed to establish a new connection" + reset + ": Connection "
                                                                                              "Refused")

                self.results()
            except KeyboardInterrupt:
                pass
        driver.close()
        self.results()

    def results(self):
        print("-" * 80)
        print(yellow + '[+] Successful Payloads for ' + self.url + ':')
        if self.successful_payloads:
            for index, item in enumerate(self.successful_payloads, start=1):
                print(index, item)
        else:
            print('\tNo XSS vulnerability detected')
        exit()