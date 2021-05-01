import requests
from bs4 import BeautifulSoup
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


class FormTest:
    """Test a form's input fields for XSS vulnerabilities"""
    def __init__(self, url, cookies):
        self.url = url
        self.cookies = cookies
        self.r = requests.get(self.url)
        self.bs = BeautifulSoup(self.r.text, 'html.parser')
        self.successful_payloads = []
        self.forms = []
        self.inputs = []
        self.textarea = []
        self.id = None
        self.name = None
        self.attr = None
        self.find_forms()

    def find_forms(self):
        forms = (self.bs.find_all("form"))
        for form in forms:
            self.forms.append(str(form))

        print(yellow + "\n[+] Detected " + (str(len(self.forms)) + " form(s) on " + self.url + ":"))

        inputs = (self.bs.find_all("input"))
        textarea = (self.bs.find_all("textarea"))
        self.input_details(inputs, textarea)

    def input_details(self, inputs, textarea):
        """Displays filtered input tags for testing"""
        for line in inputs:
            self.inputs.append(str(line))
        for line in textarea:
            self.textarea.append(str(line))
        if not self.inputs and not self.textarea:
            print('\nNo <form> tags or injection points found')
            exit()
        else:
            pass

        # Filters:
        self.inputs = [x for x in self.inputs if "hidden" not in x]
        self.inputs = [x for x in self.inputs if 'id="button"' not in x]
        self.inputs = [x for x in self.inputs if 'type="checkbox"' not in x]
        self.inputs = [x for x in self.inputs if 'type="submit"' not in x]
        self.inputs = [x for x in self.inputs if 'type="number"' not in x]

        print()
        self.id = 'id='
        self.name = 'name='
        print("-" * 80)
        print(yellow + "[+] Displaying injection points on " + self.url + ":")
        for line in self.inputs:
            if self.id in line:
                print("\n\t" + line.replace(self.id, green + self.id + reset).strip())
            if self.name in line:
                print("\n\t" + line.replace(self.name, green + self.name + reset).strip())
        for line in self.textarea:
            if self.id in line:
                print("\n\t" + line.replace(self.id, green + self.id + reset).strip())
            if self.name in line:
                print("\n\t" + line.replace(self.name, green + self.name + reset).strip())
        self.select()

    def select(self):
        """Selenium locates the id or name attribute, submits each payload, and tests for an alert"""
        global id_attr
        global name_attr
        id_attr = False
        name_attr = False
        print("\nNOTE: Some websites dynamically generate identifiers (id's) using server- {0}"
              "side code. If this is the case, Selenium will raise a NoSuchElementException {0}"
              "because the id changes every time the page loads. Selenium cannot know ahead {0}"
              "of time what the id will be when the page loads.".format('\n'))

        self.attr = input("\nType the input tag's '{0}id{1}' or '{0}name{1}' attribute value that you wish to test: "
                          .format(green, reset))
        attr_type = input("\nIs this an '{0}id{1}'[1] attribute or a '{0}name{1}' [2] attribute? (Select '1' or '2'): "
                          .format(yellow, reset))
        if attr_type == str(1):
            id_attr = True
            self.inject()
        elif attr_type == str(2):
            name_attr = True
            self.inject()
        else:
            print(red + "That's not an option")
            self.select()

    def inject(self):
        print("-" * 80)
        print(yellow + "[+] Testing '" + self.attr + "' on " + self.url)

        try:
            options = FirefoxOptions()
            # options.add_argument("--headless")  # Uncomment this line if you prefer a 'headless' browser
            driver = webdriver.Firefox(options=options, executable_path='/usr/local/bin/geckodriver')
        except (IOError, OSError) as e:
            print("\n" + e)
            exit()
        except WebDriverException as e:
            print("\n" + str(e))
            print("Ensure that 'geckodriver' is in the /usr/local/bin directory")
            exit()

        with open('payloads/xssvectors.txt', 'r') as payload_file:
            for payload in payload_file.readlines():
                payload = payload.strip('\n')
                print("\nSubmitting " + magenta + payload + reset)

                try:
                    driver.get(self.url)
                    if self.cookies:
                        driver.add_cookie(self.cookies)
                    if id_attr is True:
                        element = driver.find_element_by_id("x".replace("x", self.attr))
                    elif name_attr is True:
                        element = driver.find_element_by_name("x".replace("x", self.attr))
                    element.send_keys(payload)
                    element.submit()

                    if WebDriverWait(driver, 1).until(expected_conditions.alert_is_present()):
                        driver.switch_to.alert.accept()
                        print(green + '\t[+]XSS FOUND')
                        self.successful_payloads.append(payload)
                    elif not WebDriverWait(driver, 1).until(expected_conditions.alert_is_present()):
                        driver.close()
                except NoSuchElementException as e:
                    print(e)
                    print("\n" + red + "NoSuchElementException" + reset + ": Selenium was unable to locate element '"
                          + self.attr + "'. {0}"
                                        "If you selected an 'id' attribute, make sure you specify that {0}"
                                        "it as an id attribute. Otherwise, if the attribute you selected {0}"
                                        "is a 'name' attribute, make sure you specify it is a name attribute. {0}"
                                        "Additionally, some web sites dynamically generate identifiers (id's) {0}"
                                        "using server-side code. If this is the case, Selenium cannot predict {0}"
                                        "what the id value will be.".format('\n', red, reset))
                    self.results()
                except (TimeoutException, InvalidSessionIdException, NoAlertPresentException,
                        UnexpectedAlertPresentException, NoSuchWindowException):
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
                except ElementNotInteractableException:
                    print("\nElementNotInteractableException: This error may occur when two attributes share {0}"
                          "the same value. Selenium automatically locates the first selected attribute on the {0}"
                          "page and injects the payloads into this input. If this first attribute happens to be {0}"
                          "the non-interactable attribute, it raises an error. If this is a GET parameter, such as {0}"
                          "a 'search' bar, try Option #4 - Test a Parameter in the URL.".format("\n"))
                    self.results()
                except KeyboardInterrupt:
                    pass
        driver.close()
        self.results()

    def results(self):
        print("-" * 80)
        print(yellow + '[+] Successful payloads for "' + self.attr + '":')
        if self.successful_payloads:
            for line in self.successful_payloads:
                print('\t' + green + line)
        else:
            print('\tNo XSS vulnerability detected')
        exit()
