# XSS-INSP3CT0R
A **Kali Linux** program to detect XSS vulnerabilities in web pages.

XSS is the second most prevalent issue in the OWASP Top 10, and is found in around two thirds of all applications. The potential to discover XSS vulnerabilities depends on the security of the web application being tested. Lackluster secure coding principles, such as failing to sanitize user-controlled data, missing encoding of special characters, misconfigured Web Application Firewalls (WAFs), or server misconfigurations, all contribute to XSS vulnerabilities.

# INSTALLATION
## Clone repository:
`git clone https://github.com/dcfitz11/xss-insp3ct0r.git`

## Install requirements:
`pip3 install -r requirements.txt`

# GECKODRIVER INSTRUCTIONS
## xss.detector.py depends on FireFox and geckodriver to perform testing:
### Install:
`sudo apt-get FireFox`
### Download:
> Download geckodriver from the [geckodriver releases page](https://github.com/mozilla/geckodriver/releases) for Linux
### Extract
> Extract the geckodriver tar file
### Copy to /usr/local/bin
`sudo mv geckodriver /usr/local/bin/`

# RUNNING THE PROGRAM
## To run the program:
`python3 XSS-Insp3t0r.py`

# MENU OPTIONS:
## 1. Crawl and Identify Injection Points:
Crawl a web page to identify injection points on the web page.
> Ex: Type https://google.com and press Enter and it will identify Google's "search" form.

## 2. Inspect Server Headers for Vulnerabilities:
Display and analyze server headers in addition to identify missing headers that could result in security issues.
> Ex: Type https://google.com and press Enter to display Google's headers and identify any security issues.

## 3. Detect DOM Vulnerabilities:
Discover unencrypted links and SOP violations on the web page, including possible javascript sources and sinks.
> Ex: Type https://google.com and press Enter and it will identify unencrypted links, SOP violations, and any DOM-based XSS vulnerabilities. See [dom-based-xss.md](https://github.com/dcfitz11/xss-detection/blob/main/dom-based-xss.md) for more information.

## 4. Test the First Parameter in the URL:
When given a URL with a parameter(?), ParamInject identifies all parameters in the URL and tests the first parameter for XSS vulnerabilities.
> Ex: Type https://xss-game.appspot.com/level1/frame?query=something or http://sudo.co.il/xss/level1.php?email=test# and press Enter. ParamInject will find the first parameter (?), which in this case is **query** or **email**, respectively, and begin submitting harmless XSS payloads. Any link you submit must contain one parameter in the URL.

## 5. Test A `<form>` Tag's Input Fields:
If a web page contains form tags, testers can identify an input tag by either its 'id' or 'name' attribute for XSS vulnerability testing.
> Ex: Type https://xss-game.appspot.com/level1/frame or https://xss-quiz.int21h.jp/ and press Enter. FormTest will display all input tags and request that you identify the "id" or "name" attribute to test, which in this case is "query" or "p1." Users must then identify if this is an "id" or "name" attribute so that Selenium can find the exact location on the page to begin injecting harmless XSS payloads. Any link you provide must have a form tag(s).

## 6. Fuzz A Specific URL Parameter:
Replace parameter value to be tested in the URL with the word, "FUZZ" and Fuzz will inject and submit harmless xss payloads.
> Ex: Enter https://xss-game.appspot.com/level1/frame?query=FUZZ or http://sudo.co.il/xss/level1.php?email=FUZZ# and press Enter. Fuzz will immediately begin submitting harmless XSS payloads at the position of "FUZZ." Any link you provide must include the keyword "FUZZ" for the parameter to be tested. 

