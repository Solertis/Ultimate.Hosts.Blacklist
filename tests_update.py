#!/usr/bin/env python3

"""
This module contain the tests of update.py for the Ultimate Hosts Blacklist

Author:
    - @Funilrys, Nissar Chababy - contactTATATfunilrysTODTODcom

Contributors:
    - @GitHubUsername, First/Last Name - emailTATATserviceTODTODextension
"""
# pylint: disable=protected-access, ungrouped-imports

import sys
import unittest
from io import StringIO
from unittest import TestCase

import requests_mock

from update import Helpers, Initiate, Settings, path


class BaseStdout(TestCase):
    """
    This class is the one we use when we want to catch stdout.
    """

    def setUp(self):
        """
        Setup stdout.
        """

        sys.stdout = StringIO()

    def tearDown(self):
        """
        This method clean stdout.
        """

        sys.stdout.close()
        sys.stdout = sys.__stdout__


class TestInitiate(BaseStdout):
    """
    Test of the update.Initiate()
    """

    def test_whitelist_parser(self):
        """
        This method test update.Initiate()._whitelist_parser()
        """

        # Test the case that we give a domain without `www.`
        domain_to_test = "google.com"

        expected = [r"^google\.com$", r"^www\.google\.com$"]
        Initiate()._whitelist_parser(domain_to_test)

        self.assertEqual(expected, Settings.whitelist)

        # Test the case that we give a domain with `www.`
        domain_to_test = "www.facebook.com"

        expected.extend([r"^www\.facebook\.com$", r"^facebook\.com$"])
        Initiate()._whitelist_parser(domain_to_test)

        self.assertEqual(expected, Settings.whitelist)

        # Test of the case that we give a line which start with `ALL `
        line_to_test = "ALL github.com"

        expected.extend([r"github\.com$"])
        Initiate()._whitelist_parser(line_to_test)

        self.assertEqual(expected, Settings.whitelist)
        Settings.whitelist = []

    @requests_mock.Mocker()
    def test_get_whitelist(self, req_mock):
        """
        This method test update.Initiate().get_whitelist()
        """

        BaseStdout.setUp(self)
        expected = r"^google\.com$|^www\.google\.com$|^github\.com$|^www\.github\.com$"
        Settings.raw_link = "http://hello-funilrys.world/%s"

        text = """google.com
github.com
"""
        link = (Settings.raw_link + "domains.list") % Settings.whitelist_repo_name

        # Test of the case that everything goes right
        req_mock.get(link, text=text)
        Initiate().get_whitelist()
        actual = Settings.regex_whitelist

        self.assertEqual(expected, actual)

        expected_stdout = "Getting whitelist %s\n" % Settings.done
        actual = sys.stdout.getvalue()

        self.assertEqual(expected_stdout, actual)
        Settings.whitelist = []
        Settings.regex_whitelist = ""

        # Test of the case that everything goes wrong
        expected = ""

        req_mock.get(link, status_code=404)
        Initiate().get_whitelist()
        actual = Settings.regex_whitelist

        self.assertEqual(expected, actual)

        expected_stdout += "Getting whitelist %s\n" % Settings.error
        actual = sys.stdout.getvalue()

        self.assertEqual(expected_stdout, actual)
        Settings.whitelist = []
        Settings.regex_whitelist = ""

    def test_data_parser(self):
        """
        This method test update.Initiate()._data_parser
        """

        # Test of the case that we have a commented line
        expected_ips = []
        expected_domains = []

        Initiate()._data_parser("# Hello World")

        self.assertEqual(expected_ips, Settings.ips)
        self.assertEqual(expected_domains, Settings.domains)

        # Test of the case that we have an excluded ip
        ips_to_test = ["192.168.255.255", "10.15.78.45"]  # ,'0.0.0.0']

        for ip_to_test in ips_to_test:
            Initiate()._data_parser(ip_to_test)
            self.assertEqual(expected_ips, Settings.ips)

        # Test of the case that we have a not excluded ip
        ips_to_test = ["85.45.26.36", "78.45.230.14", "45.38.91.75"]

        for ip_to_test in ips_to_test:
            Initiate()._data_parser(ip_to_test)
            expected_ips.append(ip_to_test)
            self.assertEqual(
                expected_ips, Settings.ips, msg=repr(Settings.regex_whitelist)
            )
        Settings.ips = []

        # Test of the case that we have an invalid domain
        domains_to_test = ["-hello-.world", "hello@world"]

        for domain in domains_to_test:
            Initiate()._data_parser(domain)
            self.assertEqual(expected_domains, Settings.domains)

        # Test of the case that we do not have invalid domain
        domains_to_test = [
            "google.com",
            "twitter.com",
            "github.com",
            "facebook.com",
            "hello.world",
            "world.hello",
        ]

        for domain in domains_to_test:
            Initiate()._data_parser(domain)
            expected_domains.append(domain)
            self.assertEqual(expected_domains, Settings.domains)
        Settings.domains = []

    @requests_mock.Mocker()
    def test_data_extractor(self, req_mock):
        """
        This method test update.Initiate.data_extractor()
        """

        BaseStdout.setUp(self)
        Settings.raw_link = "http://google.com/%s/"

        repository = "this-repo-is-a-ghost"
        domains_to_test = [
            "facebook.com",
            "github.com",
            "google.com",
            "hello.world",
            "twitter.com",
            "world.hello",
        ]
        link_clean = (Settings.raw_link + "clean.list") % repository
        link_domains = (Settings.raw_link + "domains.list") % repository
        text_to_get = "\n".join(domains_to_test)
        expected_domains = domains_to_test

        # Test of the case that everything goes right
        req_mock.get(link_clean, text=text_to_get, status_code=200)
        req_mock.get(link_domains)

        Initiate().data_extractor(repository)
        self.assertEqual(expected_domains, Settings.domains)

        expected = "Extracting domains and ips from %s (clean.list) %s\n" % (
            repository, Settings.done
        )
        actual = sys.stdout.getvalue()

        self.assertEqual(expected, actual)

        BaseStdout.tearDown(self)
        BaseStdout.setUp(self)
        Settings.domains = []

        # Test of the case that everything goes wrong
        req_mock.get(link_clean, status_code=404)
        req_mock.get(link_domains, text=text_to_get)

        Initiate().data_extractor(repository)
        self.assertEqual(expected_domains, Settings.domains)

        expected = "Extracting domains and ips from %s (domain.list) %s\n" % (
            repository, Settings.done
        )
        actual = sys.stdout.getvalue()
        self.assertEqual(expected, actual)

        BaseStdout.tearDown(self)
        BaseStdout.setUp(self)
        Settings.domains = []

        # Test of the case that everything goes really wrong
        req_mock.get(link_clean, status_code=404)
        req_mock.get(link_domains, status_code=404)
        expected_domains = []

        Initiate().data_extractor(repository)
        self.assertEqual(expected_domains, Settings.domains)

        expected = "Extracting domains and ips from this-repo-is-a-ghost (ERROR) " + Settings.error + "\n"  # pylint:disable=line-too-long
        actual = sys.stdout.getvalue()
        self.assertEqual(expected, actual)

        BaseStdout.tearDown(self)
        BaseStdout.setUp(self)
        Settings.domains = []


class TestFormatLine(TestInitiate):
    """
    This class will test update.Initiate()._format_line()
    """

    def setUp(self):
        self.domains = [
            "google.com",
            "twitter.com",
            "github.com",
            "facebook.com",
            "hello.world",
            "world.hello",
        ]

    def tests_simple_line(self):
        """
        This method test the case that a simple line is catched.
        """

        for domain in self.domains:
            expected = domain
            actual = Initiate()._format_line(domain)

            self.assertEqual(expected, actual)

    def tests_line_starts_with_comment(self):
        """
        This method test the case that we catch a commented line.
        """

        for domain in self.domains:
            expected = ""

            data = "# %s" % domain
            actual = Initiate()._format_line(data)

            self.assertEqual(expected, actual)

    def tests_line_ends_with_comment(self):
        """
        This method test the case that we catch a line that ends with a comment.
        """

        for domain in self.domains:
            expected = domain

            data = "%s # hello world" % domain
            actual = Initiate()._format_line(data)

            self.assertEqual(expected, actual)

    def tests_line_with_prefix(self):
        """
        This method test the case that we catch a line with a prefix.
        """

        for domain in self.domains:
            expected = domain

            data = "0.0.0.0 %s" % domain
            actual = Initiate()._format_line(data)

            self.assertEqual(expected, actual)

        for domain in self.domains:
            expected = domain

            data = "127.0.0.1 %s" % domain
            actual = Initiate()._format_line(data)

            self.assertEqual(expected, actual)

    def tests_line_multiple_spaces(self):
        """
        This method test the case that we catch a line with multiple space as
        separator.
        """

        for domain in self.domains:
            expected = domain

            data = "0.0.0.0                %s" % domain
            actual = Initiate()._format_line(data)

            self.assertEqual(expected, actual)

        for domain in self.domains:
            expected = domain

            data = "127.0.0.1                %s" % domain
            actual = Initiate()._format_line(data)

            self.assertEqual(expected, actual)

    def tests_line_with_tab(self):
        """
        This method test the case that we catch a line with only one tab as
        separator.
        """

        for domain in self.domains:
            expected = domain

            data = "0.0.0.0\t%s" % domain
            actual = Initiate()._format_line(data)

            self.assertEqual(expected, actual)

        for domain in self.domains:
            expected = domain

            data = "127.0.0.1\t%s" % domain
            actual = Initiate()._format_line(data)

            self.assertEqual(expected, actual)

    def tests_line_multiple_tabs(self):
        """
        This method test the case that we match a line with multiple tabs
        as separator.
        """

        for domain in self.domains:
            expected = domain

            data = "0.0.0.0\t\t\t\t\t\t\t\t\t\t%s" % domain
            actual = Initiate()._format_line(data)

            self.assertEqual(expected, actual)

        for domain in self.domains:
            expected = domain

            data = "127.0.0.1\t\t\t\t\t\t\t\t\t\t\t%s" % domain
            actual = Initiate()._format_line(data)

            self.assertEqual(expected, actual)


class TestHelpers(BaseStdout):
    """
    This class will test update.Generate
    """

    def test_list(self):
        """
        This method test Helpers.List().
        """

        # Test of the case that we pass `None` as `main_list`
        expected = []
        actual = Helpers.List(None).format()
        self.assertEqual(expected, actual)

        # Test of the case that we want to format a list
        expected = ["", "github.com", "google.com", "twitter.com"]
        list_to_format = [
            "google.com", "twitter.com", "twitter.com", "", "google.com", "github.com"
        ]

        actual = Helpers.List(list_to_format).format()
        self.assertEqual(expected, actual)

        # Test of the case that we have a non string in the list
        list_to_format = [
            None,
            1,
            "google.com",
            "twitter.com",
            "twitter.com",
            "",
            "google.com",
            "github.com",
        ]
        expected = list_to_format

        actual = Helpers.List(list_to_format).format()
        self.assertEqual(expected, actual)

    def test_file(self):
        """
        This method test Helpers.File()
        """

        # Test of the case that we want to read a file.
        expected = """requests==2.18.4
requests_mock==1.4.0
colorama==0.3.9
"""

        actual = Helpers.File("requirements.txt").read()
        self.assertEqual(expected, actual)

        # Test of the case that we want to write into a file
        expected = "Hello, World!"
        Helpers.File("hi").write(expected)

        actual = Helpers.File("hi").read()
        self.assertEqual(expected, actual)

        # Test of the case we want to append to a file
        to_write = "This is the Ultimate Hosts Blacklist!"
        expected += to_write
        Helpers.File("hi").write(to_write)

        actual = Helpers.File("hi").read()
        self.assertEqual(expected, actual)

        # Test of the case that we want to overwrite the content of a file
        expected = "Hello Funilrys!"
        Helpers.File("hi").write(expected, overwrite=True)

        actual = Helpers.File("hi").read()
        self.assertEqual(expected, actual)

        # Test if the file is really deleted
        expected = False

        Helpers.File("hi").delete()
        actual = path.isfile("hi")
        self.assertEqual(expected, actual)

        # Coverage of the deletion of a file that does not exist
        Helpers.File("hi").delete()

    def test_regex(self):
        """
        This method test update.Helpers.Regex().
        """

        # Test of a simple match
        expected = True
        actual = Helpers.Regex("Hello, World!", r"llo", return_data=False).match()
        self.assertEqual(expected, actual)

        expected = False
        actual = Helpers.Regex("Hello, World!", r"funilrys", return_data=False).match()
        self.assertEqual(expected, actual)

        expected = "o, World!"
        actual = Helpers.Regex(
            "Hello, World!", r"o.*", return_data=True, group=0
        ).match()
        self.assertEqual(expected, actual)

        # Test of the rematch function
        expected = ["elp, eplo!"]
        actual = Helpers.Regex("Help, eplo!", r"el.*", rematch=True).match()
        self.assertEqual(expected, actual)

        expected = "you"
        actual = Helpers.Regex(
            "Hello how are you ? Who are you!? What are you doing around here!?",
            r"(you)",
            rematch=True,
            group=1,
        ).match()
        self.assertEqual(expected, actual)

        # Test of replace
        expected = "Heuuuuo, Woruud!"
        actual = Helpers.Regex("Hello, World!", r"l", replace_with="uu").replace()
        self.assertEqual(expected, actual)

        expected = "Hello, World!"
        actual = Helpers.Regex("Hello, World!", r"l", replace_with=None).replace()
        self.assertEqual(expected, actual)

    def test_command(self):
        """
        This method test updaet.Helpers.Command().
        """

        # Test of a simple command
        expected = "Hello, World!\n"

        actual = Helpers.Command('echo "Hello, World"!', False).execute()
        self.assertEqual(expected, actual)


if __name__ == "__main__":
    unittest.main()
