import asyncio

import aiohttp

from threatx_api_client.exceptions import (
    TXAPIIncorrectCommandError,
    TXAPIIncorrectEnvironmentError,
    TXAPIIncorrectTokenError,
    TXAPIResponseError,
)


class Client:
    """Main API Client class."""

    def __init__(self, api_env, api_key):
        """Main Client class initializer."""
        self.host_parts = {
            "prod": "",
            "pod": "tx-us-east-2a",
            "qa": "qa0",
            "dev": "dev0",
            "staging": "staging0"
        }
        self.api_path = "tx_api"

        self.api_env = api_env
        self.api_key = api_key

        self.parallel_requests = 10

        self.session_token = self.__get_session_token()

    def __get_api_env_host(self):
        if self.api_env not in self.host_parts:
            raise TXAPIIncorrectEnvironmentError(f"TX API Env '{self.api_env}' not found!")

        part = (f"-{self.host_parts.get(self.api_env)}"
                if self.host_parts.get(self.api_env) else "")

        return f"https://provision{part}.threatx.io"

    def __generate_api_link(self, api_ver: int):
        return f"/{self.api_path}/v{api_ver}"

    def __init_http_session(self):
        self.http_session = aiohttp.ClientSession(
            base_url=self.__get_api_env_host()
        )

    async def __post(self, session, path: str, post_payload: dict):
        async with asyncio.Semaphore(self.parallel_requests):
            async with session.post(path, json=post_payload) as raw_response:
                response = await raw_response.json()
                response_ok_data = response.get("Ok")
                response_error_data = response.get("Error")

                if response_ok_data:
                    return response_ok_data

                if response_error_data == "Token Expired. Please re-authenticate.":
                    self.session_token = self.__get_session_token()
                    return self.__post(session, path, post_payload)
                else:
                    raise TXAPIResponseError(response_error_data)

    async def __process_response(self, path: str, available_commands: list, payloads):
        for payload in payloads:
            if payload.get("command") not in available_commands:
                raise TXAPIIncorrectCommandError(payload.get("command"))

        async with aiohttp.ClientSession(base_url=self.__get_api_env_host()) as session:
            responses = await asyncio.gather(*(
                self.__post(
                    session,
                    path,
                    {"token": self.session_token, **payload}) for payload in payloads
            ))

        return responses

    async def __login(self):
        path = f"{self.__generate_api_link(1)}/login"

        if not self.api_key:
            raise TXAPIIncorrectTokenError("Please provide TX API Key.")

        async with aiohttp.ClientSession(base_url=self.__get_api_env_host()) as session:
            response = await asyncio.gather(
                self.__post(
                    session,
                    path,
                    {"command": "login", "api_token": self.api_key}
                )
            )
        return response[0]["token"]

    def __get_session_token(self):
        loop = asyncio.get_event_loop()
        results = loop.run_until_complete(self.__login())
        return results

    # TODO: Remove this?
    # def auth(self, payload):
    #     url = f"{self.__generate_api_link(1)}/auth"
    #
    #     available_commands = ["authorize", "refresh", "issue_password_reset", "redeem_password_reset"]
    #
    #     return self.__process_response(url, available_commands, payload)
    #
    # def auth_v2(self, payload):
    #     url = f"{self.__generate_api_link(2)}/auth"
    #
    #     available_commands = ["authorize", "refresh"]
    #
    #     return self.__process_response(url, available_commands, payload)

    def api_keys(self, payload: dict):
        """API Keys management.

        Method allows to manage API keys, allowing authorized users to
        create (and revoke) keys granting automated access to the ThreatX API.
        :param dict payload: API payload containing main command and additional parameters.
        :return:
        """
        url = f"{self.__generate_api_link(2)}/apikeys"

        available_commands = ["list", "new", "update", "revoke"]

        return self.__process_response(url, available_commands, payload)

    def api_schemas(self, payload):
        """API schemas management.

        Method allows to manage API schemas.
        :param dict payload: API payload containing main command and additional parameters.
        :return:
        """
        url = f"{self.__generate_api_link(1)}/apischemas"

        available_commands = ["save", "list", "delete"]

        return self.__process_response(url, available_commands, payload)

    def customers(self, payload):
        """Customers management.

        Method allows to create, manage and remove customers.
        :param dict payload: API payload containing main command and additional parameters.
        :return:
        """
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
        """Users management.

        Method allows to create, manage and remove users.
        :param dict payload: API payload containing main command and additional parameters.
        :return:
        """
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
        """Sites management.

        Method allows to create, manage and remove sites.
        :param dict payload: API payload containing main command and additional parameters.
        :return:
        """
        url = f"{self.__generate_api_link(2)}/sites"

        available_commands = ["list", "new", "get", "delete", "update", "unset"]

        return self.__process_response(url, available_commands, payload)

    def site_groups(self, payload):
        """Site groups management.

        Method allows to create, manage and remove site groups.
        Site groups provide access control features similar to UNIX user groups, restricting access to ThreatX sites.
        :param dict payload: API payload containing main command and additional parameters.
        :return:
        """
        url = f"{self.__generate_api_link(1)}/sitegroups"

        available_commands = ["list", "save", "delete"]

        return self.__process_response(url, available_commands, payload)

    def templates(self, payload):
        """Templates management.

        Method allows to create, manage and remove customer templates.
        :param dict payload: API payload containing main command and additional parameters.
        :return:
        """
        url = f"{self.__generate_api_link(1)}/templates"

        available_commands = ["set", "get", "delete"]

        return self.__process_response(url, available_commands, payload)

    def sensors(self, payload):
        """Sensors information.

        Method provides information of on-premises deployed sensors and sensor metadata.
        :param dict payload: API payload containing main command and additional parameters.
        :return:
        """
        url = f"{self.__generate_api_link(1)}/sensors"

        available_commands = ["list", "tags"]

        return self.__process_response(url, available_commands, payload)

    def services(self, payload):
        """Services information.

        Method provides information on ThreatX system services and their public IP addresses.
        :param dict payload: API payload containing main command and additional parameters.
        :return:
        """
        url = f"{self.__generate_api_link(1)}/services"

        available_commands = ["list"]

        return self.__process_response(url, available_commands, payload)

    def entities(self, payload):
        """Entities management.

        Method allows to list and manage entities.
        :param dict payload: API payload containing main command and additional parameters.
        :return:
        """
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
        """Statistical metrics.

        Method provides statistical metrics on ThreatX system operations.
        :param dict payload: API payload containing main command and additional parameters.
        :return:
        """
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
        """Subscriptions management.

        Method allows to configure customer notification subscriptions.
        Subscriptions are used to receive notifications related to ThreatX events, delivered either via email,
        webhook, or through a log emitter communicating directly to an analyzer.
        :param dict payload: API payload containing main command and additional parameters.
        :return:
        """
        url = f"{self.__generate_api_link(1)}/subscriptions"

        available_commands = ["save", "delete", "list", "enable", "disable"]

        return self.__process_response(url, available_commands, payload)

    def list_whitelist(self, payload):
        """Get whitelist IPs.

        Method allows to get customer whitelisted IPs.
        :param dict payload: API payload containing main command and additional parameters.
        :return:
        """
        url = f"{self.__generate_api_link(1)}/whitelist"

        available_commands = ["list"]

        return self.__process_response(url, available_commands, payload)

    def list_blacklist(self, payloads):
        """Get blacklist IPs.

        Method allows to get customer blacklisted IPs.
        :param dict payload: API payload containing main command and additional parameters.
        :return:
        """
        url = f"{self.__generate_api_link(1)}/blacklist"

        available_commands = ["list"]

        loop = asyncio.get_event_loop()
        results = loop.run_until_complete(self.__process_response(url, available_commands, payloads))
        return results

    def list_blocklist(self, payload):
        """Get blocklisted IPs.

        Method allows to get customer blocked IPs.
        :param dict payload: API payload containing main command and additional parameters.
        :return:
        """
        url = f"{self.__generate_api_link(1)}/blocklist"

        available_commands = ["list"]

        return self.__process_response(url, available_commands, payload)

    def list_mutelist(self, payload):
        """Get mutelisted IPs.

        Method allows to get customer mutelisted IPs.
        :param dict payload: API payload containing main command and additional parameters.
        :return:
        """
        url = f"{self.__generate_api_link(1)}/mutelist"

        available_commands = ["list"]

        return self.__process_response(url, available_commands, payload)

    def list_ignorelist(self, payload):
        """Get ignorelisted IPs.

        Method allows to get customer ignorelisted IPs.
        :param dict payload: API payload containing main command and additional parameters.
        :return:
        """
        url = f"{self.__generate_api_link(1)}/ignorelist"

        available_commands = ["list"]

        return self.__process_response(url, available_commands, payload)

    def global_tags(self, payload):
        """Global tags management.

        Method allows to create new and provides information of global tags available for use.
        :param dict payload: API payload containing main command and additional parameters.
        :return:
        """
        url = f"{self.__generate_api_link(1)}/globaltags"

        available_commands = ["new", "list"]

        return self.__process_response(url, available_commands, payload)

    def actor_tags(self, payload):
        """Actor tags management.

        Method allows to create, manage and remove actor tags.
        :param dict payload: API payload containing main command and additional parameters.
        :return:
        """
        url = f"{self.__generate_api_link(1)}/actortags"

        available_commands = ["new", "list", "delete"]

        return self.__process_response(url, available_commands, payload)

    def features(self, payload):
        url = f"{self.__generate_api_link(1)}/features"

        available_commands = ["list", "query", "save", "delete"]

        return self.__process_response(url, available_commands, payload)

    def metrics_tech(self, payload):
        """API Profiler information.

        Method provides information of customer API Profiler.
        :param dict payload: API payload containing main command and additional parameters.
        :return:
        """
        url = f"{self.__generate_api_link(1)}/metrics/tech"

        available_commands = ["list_endpoint_profiles", "list_site_profiles"]

        return self.__process_response(url, available_commands, payload)

    def channels(self, payload):
        """Channels management.

        Method allows to create, manage and remove customer channels.
        :param dict payload: API payload containing main command and additional parameters.
        :return:
        """
        url = f"{self.__generate_api_link(1)}/channels"

        available_commands = ["new", "list", "update"]

        return self.__process_response(url, available_commands, payload)

    def global_settings(self, payload):
        """Customer-wide settings.

        Method allows to get default customer-wide settings applied.
        :param dict payload: API payload containing main command and additional parameters.
        :return:
        """
        url = f"{self.__generate_api_link(1)}/globalsettings"

        available_commands = ["get"]

        return self.__process_response(url, available_commands, payload)

    def dns_info(self, payload):
        url = f"{self.__generate_api_link(1)}/dnsinfo"

        available_commands = ["list"]

        return self.__process_response(url, available_commands, payload)

    def logs(self, payload):
        """Customer logs.

        Method allows to get customer logs including audit logs, match events, etc.
        :param dict payload: API payload containing main command and additional parameters.
        :return:
        """
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
        """Customer logs.

        Method allows to get customer logs including block, match and audit events.
        :param dict payload: API payload containing main command and additional parameters.
        :return:
        """
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
        """Lists management.

        Method allows to manage IP addresses within black, block and whitelists.
        :param dict payload: API payload containing main command and additional parameters.
        :return:
        """
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
        """Rules management.

        Method allows to create, manage and remove customer rules.
        :param dict payload: API payload containing main command and additional parameters.
        :return:
        """
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
