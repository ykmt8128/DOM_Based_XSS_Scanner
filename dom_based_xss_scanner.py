import os
import json
import itertools
import datetime

import chromedriver_autoinstaller
from selenium import webdriver
from selenium.common.exceptions import UnexpectedAlertPresentException, TimeoutException, NoAlertPresentException, UnableToSetCookieException
from selenium.webdriver.common.alert import Alert
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions


# Chrome Driverのインストール
chrome_ver = chromedriver_autoinstaller.get_chrome_version().split(".")[0]
current_path = os.path.dirname(os.path.abspath(__file__))
driver_path = os.path.join(current_path, chrome_ver, "chromedriver.exe")
if os.path.exists(driver_path):
    print(f"chrom driver is insatlled: {driver_path}")
else:
    print(f"install the chrome driver(ver: {chrome_ver})")
    chromedriver_autoinstaller.install(True)

# Chrome Driverの設定
options = webdriver.ChromeOptions()
options.add_experimental_option("excludeSwitches", ["enable-logging"])
options.add_argument("--headless")

# 設定ファイルの読み込み
scan_settings_filename = "scan_settings.json"
with open(os.path.join(current_path, scan_settings_filename)) as f:
    xss_dict = json.load(f)
base_url = xss_dict["base_url"]
print(base_url)


# location.hash
def scan_location_hash():
    results = []

    for src in get_injection_strings():
        xss_string ="#" + src
        url = base_url + xss_string
        info = {
            "xss_flag": check_page(url),
            "xss_string": xss_string,
            "type": "location.search" 
        }
        results.append(info)
        print(info)

    return results

# location.search
def scan_location_search():
    results = []

    for keyword in get_injection_keywords():
        for src in get_injection_strings():
            xss_string = "?" + keyword + "=" + src
            url = base_url + xss_string

            info = {
                "xss_flag": check_page(url),
                "xss_string": xss_string,
                "type": "location.search" 
            }
            results.append(info)
            print(info)

    return results

# document.cookie
def scan_document_cookie():
    results = []

    for keyword in get_injection_keywords():
        for xss_string in get_injection_strings():
            cookie = {
                "name": keyword,
                "value": '"' + xss_string + '"',
                "path": "/",
            }
            info = {
                "xss_flag": check_page(base_url, cookie=cookie),
                "xss_string": keyword + "=" + xss_string,
                "type": "document.cookie" 
            }
            results.append(info)
            print(info)
    
    return results

def get_injection_strings(base_only=True):
    with open(os.path.join(current_path, scan_settings_filename)) as f:
        xss_dict = json.load(f)

    if base_only:
        return xss_dict["base_string"]
    else:
        return ["".join(elms) for elms in itertools.product(xss_dict["prefix"], xss_dict["base_string"], xss_dict["suffix"])]

def get_injection_keywords():
    with open(os.path.join(current_path, scan_settings_filename)) as f:
        xss_dict = json.load(f)
    
    return xss_dict["keyword"]


def check_page(url, cookie=None):
    driver = webdriver.Chrome(driver_path, options=options)

    # キーワード引数cookieが渡されている場合Cookieをセット
    if cookie is not None:
        # Cookieのセットには事前にアクセスする必要がある
        driver.get(url)
        try:
            driver.add_cookie(cookie)
        except UnableToSetCookieException:
            print("UnableToSetCookieException")

            driver.close()
            return None

    driver.get(url)

    check_alert_times = 3
    xss_alert_content = "585353"
    wait_time = 0.5
    for _ in range(check_alert_times):
        try:
            wait = WebDriverWait(driver, wait_time)
            wait.until(expected_conditions.alert_is_present())
            # ブロッキングの有無を確認
            driver.execute_script("")

        # 
        except UnexpectedAlertPresentException as e:
            # XSSによるアラートを検知
            print("UnexpectedAlertPresentException")
            if xss_alert_content in e.args[0]:
                print("XSS detected")
                
                # アラートがなくなるまで閉じる(最大10回)
                for _ in range(10):
                    try:        
                        Alert(driver).accept()
                    except NoAlertPresentException:
                        break
                driver.close()
                return True
            # 無関係のアラートを検知
            else:
                print("other alert", e.args[0])

                Alert(driver).accept()
        except TimeoutException as e:
            print("no alert(timeout)")

    driver.close()
    return False
    

def main():
    scan_location_hash_result = scan_location_hash()
    print("###scan_location_hash_result", scan_location_hash_result)
    scan_location_search_result = scan_location_search()
    print("###scan_location_search_result", scan_location_search_result)
    scan_document_cookie_result = scan_document_cookie()
    print("###scan_document_cookie_result", scan_document_cookie_result)

    result = {
        "base_url": base_url,
        "document.cookie": scan_document_cookie_result,
    }
    result_filename = f"scan_result_{datetime.datetime.now().strftime('%Y-%m-%d_%H%M%S')}.json"
    with open(os.path.join(current_path, "scan_results", result_filename), "w") as f:
        json.dump(result, f)

if __name__ == "__main__":
    main()

