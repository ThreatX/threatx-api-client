import os
from unittest import TestCase

from threatx_api_client import (
    Client,
    TXAPIIncorrectCommandError,
    TXAPIIncorrectEnvironmentError,
    TXAPIIncorrectTokenError,
    TXAPIResponseError,
)


class TestClient(TestCase):
    """Main API Client test class."""
    @classmethod
    def setUpClass(cls) -> None:
        """Setting up Main API Client class for tests."""
        cls.api_key_prod = os.environ.get("TX_API_PROD_KEY")
        cls.api_key_pod = os.environ.get("TX_API_POD_KEY")
        cls.api_env = "prod"

    def test_incorrect_env(self):
        """Test for incorrect environment provided."""
        with self.assertRaises(TXAPIIncorrectEnvironmentError):
            Client("", "")

    def test_empty_token(self):
        """Test for no API token provided."""
        with self.assertRaises(TXAPIIncorrectTokenError):
            Client("prod", "")

    def test_incorrect_token(self):
        """Test for incorrect API token provided."""
        with self.assertRaises(TXAPIIncorrectTokenError):
            Client("prod", "a34456456gfd")

    def test_correct_token_and_env(self):
        """Test for correct API token and environment provided."""
        Client("pod", self.api_key_pod)
        Client("prod", self.api_key_prod)

    def test_sites_incorrect_command(self):
        """Test for incorrect command in payload provided."""
        client = Client(self.api_env, self.api_key_prod)
        with self.assertRaises(TXAPIIncorrectCommandError):
            client.sites({
                "command": "AyyLmao",
                "customer_name": "soclab3"
            })

    def test_list_sites_incorrect_customer(self):
        """Test for incorrect customer in payload provided."""
        client = Client(self.api_env, self.api_key_prod)
        with self.assertRaises(TXAPIResponseError):
            client.sites({
                "command": "list",
                "customer_name": "fffamogus"
            })

    def test_list_sites(self):
        """Test for 'sites' method 'list' command."""
        client = Client(self.api_env, self.api_key_prod)
        response = client.sites({
            "command": "list",
            "customer_name": "soclab3"
        })
        self.assertIsInstance(response, list)

    # TODO: Remove this?
    # def test_refresh_auth(self):
    #     client = Client(self.api_env, self.api_key_prod)
    #     response = client.auth({
    #         "command": "refresh"
    #     })
    #     self.assertIn("token", response)

    def test_get_customers(self):
        """Test for 'customers' method 'get' command."""
        client = Client(self.api_env, self.api_key_prod)
        response = client.customers({
            "command": "get",
            "name": "soclab3"
        })
        self.assertIsInstance(response, dict)

    def test_list_users(self):
        """Test for 'users' method 'list' command."""
        client = Client(self.api_env, self.api_key_prod)
        response = client.users({
            "command": "list",
            "customer_name": "soclab3"
        })
        self.assertIsInstance(response, list)

    def test_get_templates(self):
        """Test for 'templates' method 'get' command."""
        client = Client(self.api_env, self.api_key_prod)
        response = client.templates({
            "command": "get",
            "customer_name": "soclab3"
        })
        self.assertIsInstance(response, dict)

    def test_list_sensors(self):
        """Test for 'sensors' method 'list' command."""
        client = Client(self.api_env, self.api_key_prod)
        response = client.sensors({
            "command": "list",
            "customer_name": "soclab3"
        })
        self.assertIsInstance(response, list)

    def test_list_services(self):
        """Test for 'services' method 'list' command."""
        client = Client(self.api_env, self.api_key_prod)
        response = client.services({
            "command": "list",
            "customer_name": "soclab3"
        })
        self.assertIsInstance(response, list)

    def test_list_entities(self):
        """Test for 'entities' method 'list' command."""
        client = Client(self.api_env, self.api_key_prod)
        response = client.entities({
            "command": "list",
            "customer_name": "soclab3"
        })
        self.assertIsInstance(response, list)

    def test_list_subscriptions(self):
        """Test for 'subscriptions' method 'list' command."""
        client = Client(self.api_env, self.api_key_prod)
        response = client.subscriptions({
            "command": "list",
            "customer_name": "soclab3"
        })
        self.assertIsInstance(response, list)

    def test_list_blacklist_lists(self):
        """Test for 'lists' method 'list_blacklist' command."""
        client = Client(self.api_env, self.api_key_prod)
        response = client.lists({
            "command": "list_blacklist",
            "customer_name": "soclab3"
        })
        self.assertIsInstance(response, list)

    def test_list_customer_rules(self):
        """Test for 'rules' method 'list_customer_rules' command."""
        client = Client(self.api_env, self.api_key_prod)
        response = client.rules({
            "command": "list_customer_rules",
            "customer_name": "soclab3"
        })
        self.assertIsInstance(response, list)
