import requests
from requests_html import HTMLSession
from colorama import *
init(autoreset=True)

# Variables:
reset = Fore.RESET
red = Fore.RED
yellow = Fore.YELLOW
green = Fore.GREEN
magenta = Fore.MAGENTA


class InspectHeaders:
    """Inspect server headers for vulnerabilities"""
    def __init__(self, url, cookies):
        self.url = url
        self.cookies = cookies
        self.session = HTMLSession()
        self.r = requests.get(self.url, cookies=self.cookies)
        self.headers = []
        self.headers_inspect()

    def headers_inspect(self):
        print('\n{0}[+] Server Headers:'.format(yellow))
        print('-' * 80)
        for header in self.r.headers:
            self.headers.append(header.lower())

        for header in self.r.headers:
            print('\t' + header + ' : ' + self.r.headers[header])
        self.headers_eval()

    def headers_eval(self):
        for header in self.r.headers:
            print('\t' + header + ' : ' + self.r.headers[header])

        print("\n" + "-" * 80)
        print(yellow + "[+] Header results for " + self.url + ":")
        if 'http-only' or 'httponly' not in self.headers:
            print(red + '\nHTTPOnly flag is disabled:')
            print("The 'HttpOnly' flag mitigates the risk of client-side scripts {0}"
                  "from accessing a protected cookie (if the browser supports it). {0}"
                  "If the HttpOnly flag is included in the HTTP response header, {0}"
                  "the cookie cannot be accessed through a client-side script.".format('\n'))
        if 'strict-transport-security' not in self.headers:
            print(red + '\nHTTP Strict-Transport-Security is disabled:')
            print("Abbreviated 'HSTS,' this header instructs the browser that {0}"
                  "it should only be accessed using HTTPS instead of HTTP.".format('\n'))
        if "x-frame-options" not in self.headers:
            print(red + "\nX-Frame-Options is disabled:")
            print("The 'X-Frame-Options' HTTP response header can be used to {0}"
                  "indicate whether or not a browser should be allowed to {0}"
                  "render a page in a <frame>, <iframe>, <embed>, or <object>. {0}"
                  "Sites can use this to avoid 'click-jacking' attacks by {0}"
                  "ensuring that their content is not embedded into other sites.".format('\n'))
        if "x-xss-protection" not in self.headers:
            print(red + "\nX-XSS-Protection is disabled:")
            print("The 'X-XSS-Protection' header prevents some levels of XSS {0}"
                  "attacks and is compatible with IE 8+, Chrome, Opera, Safari, {0}"
                  "and Android. Do not rely on this header alone for XSS protection. {0}"
                  "Presently, this header is becoming unnecessary with increasing {0}"
                  "use of CSP.".format('\n'))
        if "x-content-type-options" not in self.headers:
            print(red + "\nX-Content-Type-Options is disabled:")
            print("The 'X-Content-Type-Options' response header is a marker used {0}"
                  "by the server to indicate that the MIME types advertised in the {0}"
                  "'Content-Type' headers should not be changed and should be followed. {0}"
                  "This is a way to opt out of MIME-type sniffing, or, in other words, {0}"
                  "to say that the MIME types are deliberately configured.".format('\n'))
        if "content-security-policy" not in self.headers:
            print(red + "\nContent-Security-Policy is disabled:")
            print("The 'Content-Security-Policy (CSP)' is a browser security {0}"
                  "mechanism that aims to mitigate XSS attacks. It works by {0}"
                  "restricting resources (e.g., scripts and images) that a web {0}"
                  "page can load and by restricting whether a web page can be {0}"
                  "framed by other web pages.".format('\n'))
        if "set-cookie" not in self.headers:
            print(red + "\nSet-Cookie is disabled:")
            print("If this site is using cookies, the 'set-cookie' can {0}"
                  "be set using the 'secure' attribute to ensure cookies are sent {0}"
                  "to the server only with an encrypted request over the HTTPS {0}"
                  "protocol. This prevents MitM attacks over the unsecured HTTP {0}"
                  "protocol.".format('\n'))
        if "x-powered-by" in self.headers:
            print(red + "X-Powered-By Header is enabled:")
            print("The 'X-Powered-By Header' may expose information unintended {0}"
                  "unintended for public exposure. For example, it is not {0}"
                  "uncommon for this header to reveal the name and version {0}"
                  "of the web server.".format('\n'))
        else:
            print("\nNo security issues were discovered")