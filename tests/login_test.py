from __future__ import print_function
import unittest
from selenium import webdriver
from selenium.webdriver.firefox.firefox_binary import FirefoxBinary
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
import json
import requests

ldap_test_server = "vm28.nubes.stfc.ac.uk"
shib_test_server = "vm181.nubes.stfc.ac.uk"
credentials_file = "/home/mnf98541/Dynafed/credentials.json"
firefox_path = "/home/mnf98541/Downloads/firefox-58.0.2/firefox"
firefox_profile_path = "/home/mnf98541/.mozilla/firefox/u2v7wxvi.default"


class LDAPAuthnTest(unittest.TestCase):
    def setUp(self):
        binary = FirefoxBinary(firefox_path)
        self.driver = webdriver.Firefox(firefox_binary=binary)

        with open(credentials_file, "r") as f:
            f_json = json.load(f)
            self.username = f_json["louise"]["username"]
            self.password = f_json["louise"]["password"]

    def test_login(self):
        driver = self.driver
        driver.get("https://" + ldap_test_server + "/myfed/ldap/")

        # if we get a pop up, then authentication is on
        popup = True
        try:
            WebDriverWait(driver, 5).until(EC.alert_is_present())
        except TimeoutException:
            popup = False

        self.assertTrue(popup)

        # test our credentials work
        alert = driver.switch_to.alert
        alert.send_keys(self.username + Keys.TAB + self.password)
        alert.accept()

        WebDriverWait(driver, 5).until(EC.title_is("/myfed/ldap/"))
        self.assertIn(self.username, driver.page_source)

    def test_login_fail(self):
        driver = self.driver
        driver.get("https://" + "wrong_username" + ":" + "wrong_password" + "@" + ldap_test_server + "/myfed/ldap")

        # if we get a pop up, then our username and password were wrong
        # if we don't get a pop up then it was accepted for some reason
        popup = True
        try:
            WebDriverWait(driver, 5).until(EC.alert_is_present())
        except TimeoutException:
            popup = False

        self.assertTrue(popup)

        # clean up alert
        alert = driver.switch_to.alert
        alert.dismiss()

    def tearDown(self):
        self.driver.close()


class LDAPAuthzTest(unittest.TestCase):
    def setUp(self):
        binary = FirefoxBinary(firefox_path)
        self.driver = webdriver.Firefox(firefox_binary=binary)

        with open(credentials_file, "r") as f:
            f_json = json.load(f)
            self.username = f_json["louise"]["username"]
            self.password = f_json["louise"]["password"]

    def test_access_allowed(self):
        driver = self.driver
        driver.get("https://" + ldap_test_server + "/myfed/ldap/test/authorised")

        WebDriverWait(driver, 5).until(EC.alert_is_present())

        # test our credentials work
        alert = driver.switch_to.alert
        alert.send_keys(self.username + Keys.TAB + self.password)
        alert.accept()

        WebDriverWait(driver, 5).until(EC.title_is("/myfed/ldap/test/authorised/"))
        self.assertIn("Smudge.jpg", driver.page_source)

    def test_access_denied(self):
        driver = self.driver
        driver.get("https://" + ldap_test_server + "/myfed/ldap/test/unauthorised")

        WebDriverWait(driver, 5).until(EC.alert_is_present())

        # test our credentials work
        alert = driver.switch_to.alert
        alert.send_keys(self.username + Keys.TAB + self.password)
        alert.accept()

        WebDriverWait(driver, 5).until(EC.title_is("403 Forbidden"))

        self.assertNotIn("Smudge.jpg", driver.page_source)

    def test_download_access_success(self):
        # use requests here to test we get a 200 response when trying to directly download a file

        r = requests.get("https://" + ldap_test_server + "/myfed/ldap/test/authorised/Smudge.jpg", auth=(self.username, self.password), verify=False)
        self.assertEqual(r.status_code, 200)

    def test_download_access_fail(self):
        # use requests here to test we get a 403 response when trying to directly download a file

        r = requests.get("https://" + ldap_test_server + "/myfed/ldap/test/unauthorised/Smudge.jpg", auth=(self.username, self.password), verify=False)
        self.assertEqual(r.status_code, 403)

    def tearDown(self):
        self.driver.close()


class CertificateAuthSuccessTest(unittest.TestCase):
    def setUp(self):
        binary = FirefoxBinary(firefox_path)
        # need to specify our profile so it can use our certificate
        # see https://stackoverflow.com/questions/17437407/how-to-import-ssl-certificates-for-firefox-with-selenium-in-python
        profile = webdriver.FirefoxProfile(firefox_profile_path)
        self.driver = webdriver.Firefox(profile, firefox_binary=binary)

    def test_login(self):
        driver = self.driver
        driver.get("https://" + ldap_test_server + "/myfed/x509/test/unprotected")

        self.assertIn("/C=UK/O=eScience/OU=CLRC/L=RAL/CN=louise davies", driver.page_source)

    def test_see_all_buckets(self):
        driver = self.driver
        driver.get("https://" + ldap_test_server + "/myfed/x509")

        WebDriverWait(driver, 5).until(EC.title_is("/myfed/x509/"))
        self.assertIn("atlas", driver.page_source)
        self.assertIn("dteam", driver.page_source)
        self.assertIn("enmr", driver.page_source)
        self.assertIn("lhcb", driver.page_source)
        self.assertIn("ligo", driver.page_source)
        self.assertIn("prominence", driver.page_source)
        self.assertIn("ska", driver.page_source)
        self.assertIn("test", driver.page_source)

    def test_access_allowed_simple(self):
        driver = self.driver
        driver.get("https://" + ldap_test_server + "/myfed/x509/test/authorised")

        WebDriverWait(driver, 5).until(EC.title_is("/myfed/x509/test/authorised/"))
        self.assertIn("Smudge.jpg", driver.page_source)

    def test_access_allowed(self):
        driver = self.driver
        driver.get("https://" + ldap_test_server + "/myfed/x509/enmr/ccp4-data")

        WebDriverWait(driver, 5).until(EC.title_is("/myfed/x509/enmr/ccp4-data/"))
        self.assertIn("Powered by LCGDM-DAV", driver.page_source)

    def test_access_denied_simple(self):
        driver = self.driver
        driver.get("https://" + ldap_test_server + "/myfed/x509/test/unauthorised")

        WebDriverWait(driver, 5).until(EC.title_is("403 Forbidden"))

        self.assertNotIn("Smudge.jpg", driver.page_source)

    def test_access_denied(self):
        driver = self.driver
        driver.get("https://" + ldap_test_server + "/myfed/x509/enmr/ccp4-jobs")

        WebDriverWait(driver, 5).until(EC.title_is("403 Forbidden"))

        self.assertNotIn("Powered by LCGDM-DAV", driver.page_source)

    def tearDown(self):
        self.driver.close()


class CertificateAuthFailureTest(unittest.TestCase):
    def setUp(self):
        binary = FirefoxBinary(firefox_path)
        # don't specify profile, so we don't have certificate
        self.driver = webdriver.Firefox(firefox_binary=binary)

    def test_login_fail(self):
        driver = self.driver
        driver.get("https://" + ldap_test_server + "/myfed/x509/test/authorised")

        WebDriverWait(driver, 5).until(EC.title_is("403 Forbidden"))

        self.assertNotIn("/C=UK/O=eScience/OU=CLRC/L=RAL/CN=louise davies", driver.page_source)

    def tearDown(self):
        self.driver.close()


class ShibAuthnTest(unittest.TestCase):
    def setUp(self):
        binary = FirefoxBinary(firefox_path)
        self.driver = webdriver.Firefox(firefox_binary=binary)
        # these are the username and password for TestShib
        self.username = "myself"
        self.password = "myself"

    def test_login(self):
        driver = self.driver
        driver.get("https://" + shib_test_server + "/myfed")

        # if we get a pop up, then authentication is on
        try:
            WebDriverWait(driver, 5).until(EC.title_is("TestShib Identity Provider Login"))

            # test our credentials work
            username_field = driver.find_element_by_name("j_username")
            username_field.send_keys(self.username)
            password_field = driver.find_element_by_name("j_password")
            password_field.send_keys(self.password)
            driver.find_element_by_css_selector("input[value=Login]").click()

            WebDriverWait(driver, 5).until(EC.title_is("/myfed/"))
            self.assertIn(self.username, driver.page_source)
            successful_login = True
        except TimeoutException:
            successful_login = False

        self.assertTrue(successful_login)

    def test_login_fail(self):
        driver = self.driver
        driver.get("https://" + shib_test_server + "/myfed")

        # if we get a pop up, then authentication is on
        login_page = True
        try:
            WebDriverWait(driver, 5).until(EC.title_is("TestShib Identity Provider Login"))

            # test our credentials work
            username_field = driver.find_element_by_name("j_username")
            username_field.send_keys("wrong_username")
            password_field = driver.find_element_by_name("j_password")
            password_field.send_keys("wrong_password")
            driver.find_element_by_css_selector("input[value=Login]").click()

            WebDriverWait(driver, 5).until(EC.presence_of_element_located((By.CSS_SELECTOR, "#main > center > p > font")))
            self.assertIn("Authentication failed", driver.page_source)
        except TimeoutException:
            login_page = False

        self.assertTrue(login_page)

    def tearDown(self):
        self.driver.close()


class ShibAuthzTest(unittest.TestCase):
    def setUp(self):
        binary = FirefoxBinary(firefox_path)
        self.driver = webdriver.Firefox(firefox_binary=binary)
        # these are the username and password for TestShib
        self.username = "myself"
        self.password = "myself"

    def test_access_allowed(self):
        driver = self.driver
        driver.get("https://" + shib_test_server + "/myfed/shib/authorised")

        WebDriverWait(driver, 5).until(EC.title_is("TestShib Identity Provider Login"))

        # test our credentials work
        username_field = driver.find_element_by_name("j_username")
        username_field.send_keys(self.username)
        password_field = driver.find_element_by_name("j_password")
        password_field.send_keys(self.password)
        driver.find_element_by_css_selector("input[value=Login]").click()

        WebDriverWait(driver, 5).until(EC.title_is("/myfed/shib/authorised/"))
        self.assertIn("Smudge.jpg", driver.page_source)

    def test_access_denied(self):
        driver = self.driver
        driver.get("https://" + shib_test_server + "/myfed/shib/unauthorised")

        WebDriverWait(driver, 5).until(EC.title_is("TestShib Identity Provider Login"))

        # test our credentials work
        username_field = driver.find_element_by_name("j_username")
        username_field.send_keys(self.username)
        password_field = driver.find_element_by_name("j_password")
        password_field.send_keys(self.password)
        driver.find_element_by_css_selector("input[value=Login]").click()

        WebDriverWait(driver, 5).until(EC.title_is("403 Forbidden"))

        self.assertNotIn("Smudge.jpg", driver.page_source)

    def test_download_access_success(self):
        # use requests here to test we get a 200 response when trying to directly download a file

        # need to login first...

        driver = self.driver
        driver.get("https://" + shib_test_server + "/myfed/")

        WebDriverWait(driver, 5).until(EC.title_is("TestShib Identity Provider Login"))

        # test our credentials work
        username_field = driver.find_element_by_name("j_username")
        username_field.send_keys(self.username)
        password_field = driver.find_element_by_name("j_password")
        password_field.send_keys(self.password)
        driver.find_element_by_css_selector("input[value=Login]").click()

        WebDriverWait(driver, 5).until(EC.title_is("/myfed/"))

        # use the cookies to see if this allows us to download a file with our credentials
        cookies = {i['name']: i['value'] for i in driver.get_cookies()}

        r = requests.get("https://" + shib_test_server + "/myfed/shib/authorised/Smudge.jpg", cookies=cookies, verify=False)
        self.assertEqual(r.status_code, 200)

    def test_download_access_fail(self):
        # use requests here to test we get a 403 response when trying to directly download a file

        # need to login first...

        driver = self.driver
        driver.get("https://" + shib_test_server + "/myfed/")

        WebDriverWait(driver, 5).until(EC.title_is("TestShib Identity Provider Login"))

        # test our credentials work
        username_field = driver.find_element_by_name("j_username")
        username_field.send_keys(self.username)
        password_field = driver.find_element_by_name("j_password")
        password_field.send_keys(self.password)
        driver.find_element_by_css_selector("input[value=Login]").click()

        WebDriverWait(driver, 5).until(EC.title_is("/myfed/"))

        # use the cookies to see if this allows us to download a file with our credentials
        cookies = {i['name']: i['value'] for i in driver.get_cookies()}

        r = requests.get("https://" + shib_test_server + "/myfed/shib/unauthorised/Smudge.jpg", cookies=cookies, verify=False)
        self.assertEqual(r.status_code, 403)

    def tearDown(self):
        self.driver.close()


if __name__ == "__main__":
    unittest.main()
