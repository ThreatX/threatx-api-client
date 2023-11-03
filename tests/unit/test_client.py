import os
from unittest import TestCase

from threatx_api_client import TXAPIIncorrectEnvironment, Client, TXAPIIncorrectToken, TXAPIIncorrectCommand, \
    TXAPIResponseError


class TestClient(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.api_key_prod = os.environ.get("TX_API_PROD_KEY")
        cls.api_key_pod = os.environ.get("TX_API_POD_KEY")
        cls.api_env = "prod"

    def test_incorrect_env(self):
        with self.assertRaises(TXAPIIncorrectEnvironment):
            Client("", "")

    def test_empty_token(self):
        with self.assertRaises(TXAPIIncorrectToken):
            Client("prod", "")

    def test_incorrect_token(self):
        with self.assertRaises(TXAPIIncorrectToken):
            Client("prod", "a34456456gfd")

    def test_correct_token_and_env(self):
        Client("pod", self.api_key_pod)
        Client("prod", self.api_key_prod)

    def test_sites_incorrect_command(self):
        client = Client(self.api_env, self.api_key_prod)
        with self.assertRaises(TXAPIIncorrectCommand):
            client.sites({
                "command": "AyyLmao",
                "customer_name": "soclab3"
            })

    def test_list_sites_incorrect_customer(self):
        client = Client(self.api_env, self.api_key_prod)
        with self.assertRaises(TXAPIResponseError):
            client.sites({
                "command": "list",
                "customer_name": "fffamogus"
            })

    def test_list_sites(self):
        client = Client(self.api_env, self.api_key_prod)
        response = client.sites({
            "command": "list",
            "customer_name": "soclab3"
        })
        self.assertIsInstance(response, list)

    def test_refresh_auth(self):
        client = Client(self.api_env, self.api_key_prod)
        response = client.auth({
            "command": "refresh"
        })
        self.assertIn("token", response)

    def test_get_customers(self):
        client = Client(self.api_env, self.api_key_prod)
        response = client.customers({
            "command": "get",
            "name": "soclab3"
        })
        self.assertIsInstance(response, dict)

    def test_list_users(self):
        client = Client(self.api_env, self.api_key_prod)
        response = client.users({
            "command": "list",
            "customer_name": "soclab3"
        })
        self.assertIsInstance(response, list)

    def test_get_templates(self):
        client = Client(self.api_env, self.api_key_prod)
        response = client.templates({
            "command": "get",
            "customer_name": "soclab3"
        })
        self.assertIsInstance(response, dict)

    def test_list_sensors(self):
        client = Client(self.api_env, self.api_key_prod)
        response = client.sensors({
            "command": "list",
            "customer_name": "soclab3"
        })
        self.assertIsInstance(response, list)

    def test_list_services(self):
        client = Client(self.api_env, self.api_key_prod)
        response = client.services({
            "command": "list",
            "customer_name": "soclab3"
        })
        self.assertIsInstance(response, list)

    def test_list_entities(self):
        client = Client(self.api_env, self.api_key_prod)
        response = client.entities({
            "command": "list",
            "customer_name": "soclab3"
        })
        self.assertIsInstance(response, list)

    def test_list_subscriptions(self):
        client = Client(self.api_env, self.api_key_prod)
        response = client.subscriptions({
            "command": "list",
            "customer_name": "soclab3"
        })
        self.assertIsInstance(response, list)

    def test_list_blacklist_lists(self):
        client = Client(self.api_env, self.api_key_prod)
        response = client.lists({
            "command": "list_blacklist",
            "customer_name": "soclab3"
        })
        self.assertIsInstance(response, list)

    def test_list_customer_rules(self):
        client = Client(self.api_env, self.api_key_prod)
        response = client.rules({
            "command": "list_customer_rules",
            "customer_name": "soclab3"
        })
        self.assertIsInstance(response, list)
