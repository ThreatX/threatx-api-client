import requests

from txapiclient.exceptions import TXAPIIncorrectEnvironment, TXAPIIncorrectCommand, TXAPIResponseError, \
    TXAPIIncorrectToken


class Client:
    def __init__(self, api_env, api_key):
        self.api_pod_host = "https://provision-tx-us-east-2a.threatx.io"
        self.api_prod_host = "https://provision.threatx.io"
        self.api_path = "tx_api"

        self.api_env = api_env
        self.api_key = api_key

        self.session_token = self.__login()

    def __get_api_env_host(self, api_env):
        match api_env:
            case "pod":
                return self.api_pod_host
            case "prod":
                return self.api_prod_host
            case _:
                raise TXAPIIncorrectEnvironment("TX API ENV not found!")

    def __generate_api_link(self, api_ver: int):
        return f"{self.__get_api_env_host(self.api_env)}/{self.api_path}/v{api_ver}"

    def __process_response(self, url: str, available_commands: list, payload: dict):
        payload_command = payload.get("command")

        if payload_command not in available_commands:
            raise TXAPIIncorrectCommand(payload_command)

        auth = {"token": self.session_token}
        response: dict = requests.post(url, json={**auth, **payload}).json()

        response_data = response.get("Ok")

        if response_data:
            return response_data
        else:
            raise TXAPIResponseError(response.get("Error"))

    def __login(self):
        url = f"{self.__generate_api_link(1)}/login"

        if not self.api_key:
            raise TXAPIIncorrectToken("Please provide TX API KEY.")

        data = {"command": "login", "api_token": self.api_key}

        response = requests.post(url, json=data).json()["Ok"]["token"]

        if response:
            return response
        else:
            raise TXAPIIncorrectToken("TX API Token is not correct!")

    def auth(self, payload):
        url = f"{self.__generate_api_link(1)}/auth"

        available_commands = ["authorize", "refresh", "issue_password_reset", "redeem_password_reset"]

        return self.__process_response(url, available_commands, payload)

    def auth_v2(self, payload):
        url = f"{self.__generate_api_link(2)}/auth"

        available_commands = ["authorize", "refresh"]

        return self.__process_response(url, available_commands, payload)

    def api_keys(self, payload):
        url = f"{self.__generate_api_link(2)}/apikeys"

        available_commands = ["list", "new", "update", "revoke"]

        return self.__process_response(url, available_commands, payload)

    def api_schemas(self, payload):
        url = f"{self.__generate_api_link(1)}/apischemas"

        available_commands = ["save", "list", "delete"]

        return self.__process_response(url, available_commands, payload)

    def customers(self, payload):
        url = f"{self.__generate_api_link(1)}/customers"

        available_commands = [
            "list",
            "new",
            "get",
            "update",
            "delete",
            "list_api_keys",
            "new_api_key",
            "delete_api_key",
            "get_customer_config",  # TODO: confirm
            "set_customer_config",  # TODO: confirm
        ]

        return self.__process_response(url, available_commands, payload)

    def users(self, payload):
        url = f"{self.__generate_api_link(1)}/users"

        available_commands = [
            "list",
            "new",
            "get",
            "update",
            "delete",
            "get_api_key",  # TODO: confirm
        ]

        return self.__process_response(url, available_commands, payload)

    def sites(self, payload):
        url = f"{self.__generate_api_link(2)}/sites"

        available_commands = ["list", "new", "get", "delete", "update", "unset"]

        return self.__process_response(url, available_commands, payload)

    def site_groups(self, payload):
        url = f"{self.__generate_api_link(1)}/sitegroups"

        available_commands = ["list", "save", "delete"]

        return self.__process_response(url, available_commands, payload)

    def templates(self, payload):
        url = f"{self.__generate_api_link(1)}/templates"

        available_commands = ["set", "get", "delete"]

        return self.__process_response(url, available_commands, payload)

    def sensors(self, payload):
        url = f"{self.__generate_api_link(1)}/sensors"

        available_commands = ["list", "tags"]

        return self.__process_response(url, available_commands, payload)

    def services(self, payload):
        url = f"{self.__generate_api_link(1)}/services"

        available_commands = ["list"]

        return self.__process_response(url, available_commands, payload)

    def entities(self, payload):
        url = f"{self.__generate_api_link(1)}/entities"

        available_commands = [
            "list",
            "show",
            "state_changes",
            "risk_changes",
            "notes",
            "new_note",
            "reset",
            "block_entity",
            "blacklist_entity",
            "whitelist_entity",
            "watch_entity",
            "list_most_risky",
            "count"
        ]

        return self.__process_response(url, available_commands, payload)

    def metrics(self, payload):
        url = f"{self.__generate_api_link(1)}/metrics"

        available_commands = [
            "request_stats_by_hour",
            "request_stats_by_minute",
            "match_stats_by_hour",
            "block_stats_by_endpoint",
            "entity_stats_by_entity_by_quarter_hour",
            "rules_matched_by_ip_by_quarter_hour",
            "request_stats_by_endpoint",
            "threat_stats_by_endpoint",
            "threat_stats_by_hour",
            "threat_stats_by_quarter_hour",
            "threat_stats_by_site",
            "status_codes_by_site",
            "request_stats_hourly_by_site",
            "request_stats_hourly_by_endpoint"
        ]

        return self.__process_response(url, available_commands, payload)

    def subscriptions(self, payload):
        url = f"{self.__generate_api_link(1)}/subscriptions"

        available_commands = ["save", "delete", "list", "enable", "disable"]

        return self.__process_response(url, available_commands, payload)

    def list_whitelist(self, payload):
        url = f"{self.__generate_api_link(1)}/whitelist"

        available_commands = ["list"]

        return self.__process_response(url, available_commands, payload)

    def list_blacklist(self, payload):
        url = f"{self.__generate_api_link(1)}/blacklist"

        available_commands = ["list"]

        return self.__process_response(url, available_commands, payload)

    def list_blocklist(self, payload):
        url = f"{self.__generate_api_link(1)}/blocklist"

        available_commands = ["list"]

        return self.__process_response(url, available_commands, payload)

    def list_mutelist(self, payload):
        url = f"{self.__generate_api_link(1)}/mutelist"

        available_commands = ["list"]

        return self.__process_response(url, available_commands, payload)

    def list_ignorelist(self, payload):
        url = f"{self.__generate_api_link(1)}/ignorelist"

        available_commands = ["list"]

        return self.__process_response(url, available_commands, payload)

    def global_tags(self, payload):
        url = f"{self.__generate_api_link(1)}/globaltags"

        available_commands = ["new", "list"]

        return self.__process_response(url, available_commands, payload)

    def actor_tags(self, payload):
        url = f"{self.__generate_api_link(1)}/actortags"

        available_commands = ["new", "list", "delete"]

        return self.__process_response(url, available_commands, payload)

    def features(self, payload):
        url = f"{self.__generate_api_link(1)}/features"

        available_commands = ["list", "query", "save", "delete"]

        return self.__process_response(url, available_commands, payload)

    def metrics_tech(self, payload):
        url = f"{self.__generate_api_link(1)}/metrics/tech"

        available_commands = ["list_endpoint_profiles", "list_site_profiles"]

        return self.__process_response(url, available_commands, payload)

    def channels(self, payload):
        url = f"{self.__generate_api_link(1)}/channels"

        available_commands = ["new", "list", "update"]

        return self.__process_response(url, available_commands, payload)

    def global_settings(self, payload):
        url = f"{self.__generate_api_link(1)}/globalsettings"

        available_commands = ["get"]

        return self.__process_response(url, available_commands, payload)

    def dns_info(self, payload):
        url = f"{self.__generate_api_link(1)}/dnsinfo"

        available_commands = ["list"]

        return self.__process_response(url, available_commands, payload)

    def logs(self, payload):
        url = f"{self.__generate_api_link(1)}/logs"

        available_commands = [
            "events",
            "entities",
            "blocks",
            "actions",
            "matches",
            "rule_hits",
            "sysinfo",
            "audit_log"
        ]

        # TODO: investigate if it is still used
        # enrich data (customer_name)
        # if "customer_name" in payload:
        #     for log in response:
        #         log["customer"] = payload["customer_name"]

        return self.__process_response(url, available_commands, payload)

    def logs_v2(self, payload):
        url = f"{self.__generate_api_link(2)}/logs"

        available_commands = [
            "block_events",
            "match_events",
            "audit_events"
        ]

        # TODO: investigate if it is still used
        # enrich data (customer_name)
        # if "customer_name" in payload:
        #     for log in response:
        #         log["customer"] = payload["customer_name"]

        return self.__process_response(url, available_commands, payload)

    def lists(self, payload):
        url = f"{self.__generate_api_link(1)}/lists"

        available_commands = [
            "list_blacklist",
            "list_blocklist",
            "list_whitelist",
            "list_ignorelist",
            "new_blacklist",
            "new_blocklist",
            "new_whitelist",
            "new_ignorelist",
            "bulk_new_blacklist",
            "bulk_new_blocklist",
            "bulk_new_whitelist",
            "bulk_new_ignorelist",
            "get_blacklist",
            "get_blocklist",
            "get_whitelist",
            "get_ignorelist",
            "delete_blacklist",
            "delete_blocklist",
            "delete_whitelist",
            "delete_ignorelist",
            "bulk_delete_blacklist",
            "bulk_delete_blocklist",
            "bulk_delete_whitelist",
            "bulk_delete_ignorelist"
            "ip_to_link",
        ]

        return self.__process_response(url, available_commands, payload)

    def rules(self, payload):
        url = f"{self.__generate_api_link(1)}/rules"

        available_commands = [
            "list_customer_rules",
            "list_whitelist_rules",
            "list_profiler_rules",
            "list_common_rules",
            "new_customer_rule",
            "new_whitelist_rule",
            "new_common_rule",
            "update_customer_rule",
            "update_whitelist_rule",
            "update_profiler_rule",
            "update_common_rule",
            "get_customer_rule",
            "get_whitelist_rule",
            "get_profiler_rule",
            "get_common_rule",
            "delete_customer_rule",
            "delete_whitelist_rule",
            "delete_profiler_rule",
            "delete_common_rule",
            "validate_rule"
        ]

        return self.__process_response(url, available_commands, payload)
