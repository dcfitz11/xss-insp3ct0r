import urllib
from urllib.parse import urljoin
from selenium import webdriver
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.common.exceptions import TimeoutException, NoAlertPresentException, \
    UnexpectedAlertPresentException, InvalidSessionIdException, WebDriverException, \
    NoSuchElementException, ElementNotInteractableException, NoSuchWindowException
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


class Fuzz:
    """Fuzz a specific parameter in the URL"""
    def __init__(self, url, cookies):
        self.url = url
        self.cookies = cookies
        self.injected = []
        self.successful_payloads = []
        self.verify()

    def verify(self):
        if 'FUZZ' not in self.url:
            print(red + '\nThey keyword, "FUZZ," was not found in ' + self.url)
            exit()
        else:
            self.injector()

    def injector(self):
        with open('payloads/xssvectors.txt', 'r') as f_object:
            for payload in f_object.readlines():
                payload = payload.strip('\n')
                param = urllib.parse.quote(payload)  # encode payload
                self.injected.append(self.url.replace("FUZZ", param))
        self.inject()

    def inject(self):
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
        for url in self.injected:
            try:
                print('Testing ' + url)
                driver.get(url)
                if self.cookies:
                    driver.add_cookie(self.cookies)
                if WebDriverWait(driver, 1).until(expected_conditions.alert_is_present()):
                    driver.switch_to.alert.accept()
                    print(green + '\t[+]XSS FOUND' + '\n')
                    self.successful_payloads.append(url)
                elif not WebDriverWait(driver, 1).until(expected_conditions.alert_is_present()):
                    driver.close()
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