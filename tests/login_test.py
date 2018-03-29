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


class LDAPAuthnTest(unittest.TestCase):
    server = "vm28.nubes.stfc.ac.uk"

    def setUp(self):
        binary = FirefoxBinary("/home/mnf98541/Downloads/firefox-58.0.2/firefox")
        self.driver = webdriver.Firefox(firefox_binary=binary)

        with open("../credentials.json", "r") as f:
            f_json = json.load(f)
            self.username = f_json["louise"]["username"]
            self.password = f_json["louise"]["password"]

    def test_login(self):
        driver = self.driver
        driver.get("https://" + self.server + "/myfed")

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

        WebDriverWait(driver, 5).until(EC.title_is("/myfed/"))
        self.assertIn(self.username, driver.page_source)

    def test_login_fail(self):
        driver = self.driver
        driver.get("https://" + "wrong_username" + ":" + "wrong_password" + "@" + self.server + "/myfed")

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
    server = "vm28.nubes.stfc.ac.uk"

    def setUp(self):
        binary = FirefoxBinary("/home/mnf98541/Downloads/firefox-58.0.2/firefox")
        self.driver = webdriver.Firefox(firefox_binary=binary)

        with open("../credentials.json", "r") as f:
            f_json = json.load(f)
            self.username = f_json["louise"]["username"]
            self.password = f_json["louise"]["password"]

    def test_access_allowed(self):
        driver = self.driver
        driver.get("https://" + self.server + "/myfed/ldap/authorised")

        WebDriverWait(driver, 5).until(EC.alert_is_present())

        # test our credentials work
        alert = driver.switch_to.alert
        alert.send_keys(self.username + Keys.TAB + self.password)
        alert.accept()

        WebDriverWait(driver, 5).until(EC.title_is("/myfed/ldap/authorised/"))
        self.assertIn("Smudge.jpg", driver.page_source)

    def test_access_denied(self):
        driver = self.driver
        driver.get("https://" + self.server + "/myfed/ldap/unauthorised")

        WebDriverWait(driver, 5).until(EC.alert_is_present())

        # test our credentials work
        alert = driver.switch_to.alert
        alert.send_keys(self.username + Keys.TAB + self.password)
        alert.accept()

        WebDriverWait(driver, 5).until(EC.title_is("403 Forbidden"))

        self.assertNotIn("Smudge.jpg", driver.page_source)

    def test_download_access_success(self):
        # use requests here to test we get a 200 response when trying to directly download a file

        r = requests.get("https://" + self.server + "/myfed/ldap/authorised/Smudge.jpg", auth=(self.username, self.password), verify="/home/mnf98541/Downloads/UKe-ScienceCombined.crt")
        self.assertEqual(r.status_code, 200)

    def test_download_access_fail(self):
        # use requests here to test we get a 403 response when trying to directly download a file

        r = requests.get("https://" + self.server + "/myfed/ldap/unauthorised/Smudge.jpg", auth=(self.username, self.password), verify="/home/mnf98541/Downloads/UKe-ScienceCombined.crt")
        self.assertEqual(r.status_code, 403)

    def tearDown(self):
        self.driver.close()


class CertificateAuthTest(unittest.TestCase):
    server = "vm28.nubes.stfc.ac.uk"

    def setUp(self):
        binary = FirefoxBinary("/home/mnf98541/Downloads/firefox-58.0.2/firefox")
        # need to specify our profile so it can use our certificate
        profile = webdriver.FirefoxProfile("/home/mnf98541/.mozilla/firefox/u2v7wxvi.default")
        self.driver = webdriver.Firefox(profile, firefox_binary=binary)

    def test_login(self):
        driver = self.driver
        driver.get("https://" + self.server + "/myfed/cert/authorised")

        self.assertIn("CN=louise davies,L=RAL,OU=CLRC,O=eScience,C=UK", driver.page_source)

    def tearDown(self):
        self.driver.close()


class ShibAuthnTest(unittest.TestCase):
    server = "vm181.nubes.stfc.ac.uk"

    def setUp(self):
        binary = FirefoxBinary("/home/mnf98541/Downloads/firefox-58.0.2/firefox")
        self.driver = webdriver.Firefox(firefox_binary=binary)
        self.username = "myself"
        self.password = "myself"

    def test_login(self):
        driver = self.driver
        driver.get("https://" + self.server + "/myfed")

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
        driver.get("https://" + self.server + "/myfed")

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
    server = "vm181.nubes.stfc.ac.uk"

    def setUp(self):
        binary = FirefoxBinary("/home/mnf98541/Downloads/firefox-58.0.2/firefox")
        self.driver = webdriver.Firefox(firefox_binary=binary)
        self.username = "myself"
        self.password = "myself"

    def test_access_allowed(self):
        driver = self.driver
        driver.get("https://" + self.server + "/myfed/shib/authorised")

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
        driver.get("https://" + self.server + "/myfed/shib/unauthorised")

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
        driver.get("https://" + self.server + "/myfed/")

        WebDriverWait(driver, 5).until(EC.title_is("TestShib Identity Provider Login"))

        # test our credentials work
        username_field = driver.find_element_by_name("j_username")
        username_field.send_keys(self.username)
        password_field = driver.find_element_by_name("j_password")
        password_field.send_keys(self.password)
        driver.find_element_by_css_selector("input[value=Login]").click()

        WebDriverWait(driver, 5).until(EC.title_is("/myfed/"))

        cookies = {i['name']: i['value'] for i in driver.get_cookies()}

        r = requests.get("https://" + self.server + "/myfed/shib/authorised/Smudge.jpg", cookies=cookies, verify=False)
        self.assertEqual(r.status_code, 200)

    def test_download_access_fail(self):
        # use requests here to test we get a 403 response when trying to directly download a file

        # need to login first...

        driver = self.driver
        driver.get("https://" + self.server + "/myfed/")

        WebDriverWait(driver, 5).until(EC.title_is("TestShib Identity Provider Login"))

        # test our credentials work
        username_field = driver.find_element_by_name("j_username")
        username_field.send_keys(self.username)
        password_field = driver.find_element_by_name("j_password")
        password_field.send_keys(self.password)
        driver.find_element_by_css_selector("input[value=Login]").click()

        WebDriverWait(driver, 5).until(EC.title_is("/myfed/"))

        cookies = {i['name']: i['value'] for i in driver.get_cookies()}

        r = requests.get("https://" + self.server + "/myfed/shib/unauthorised/Smudge.jpg", cookies=cookies, verify=False)
        self.assertEqual(r.status_code, 403)

    def tearDown(self):
        self.driver.close()


if __name__ == "__main__":
    unittest.main()
