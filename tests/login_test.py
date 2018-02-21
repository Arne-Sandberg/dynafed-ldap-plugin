from __future__ import print_function
import unittest
from selenium import webdriver
from selenium.webdriver.firefox.firefox_binary import FirefoxBinary
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.keys import Keys
import time
import json


class LDAPAuthTest(unittest.TestCase):
    server = "130.246.223.218"

    def setUp(self):
        binary = FirefoxBinary("/home/mnf98541/Downloads/firefox-58.0.2/firefox")
        self.driver = webdriver.Firefox(firefox_binary=binary)

        with open("../credentials.json", "r") as f:
            f_json = json.load(f)
            self.username = f_json["louise"]["username"]
            self.password = f_json["louise"]["password"]

    def test_login(self):
        driver = self.driver
        driver.get("https://" + self.server + "/myfed/authorised")

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
        time.sleep(1)

        self.assertIn(self.username, driver.page_source)
        self.assertIn("Smudge", driver.page_source)

    def test_login_fail(self):
        driver = self.driver
        driver.get("https://" + "wrong_username" + ":" + "wrong_password" + "@" + self.server + "/myfed/authorised")

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


class CertificateAuthTest(unittest.TestCase):
    server = "130.246.223.218"

    def setUp(self):
        binary = FirefoxBinary("/home/mnf98541/Downloads/firefox-58.0.2/firefox")
        # need to specify our profile so it can use our certificate
        profile = webdriver.FirefoxProfile("/home/mnf98541/.mozilla/firefox/u2v7wxvi.default")
        self.driver = webdriver.Firefox(profile, firefox_binary=binary)

    def test_login(self):
        driver = self.driver
        driver.get("https://" + self.server + "/myfed/unprotected")

        self.assertIn("CN=louise davies,L=RAL,OU=CLRC,O=eScience,C=UK", driver.page_source)

    def tearDown(self):
        self.driver.close()


if __name__ == "__main__":
    unittest.main()
