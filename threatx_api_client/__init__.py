import asyncio
import importlib.metadata
from json import JSONDecodeError

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

        self.headers = {
            "User-Agent": f"ThreatX-API-Client/{importlib.metadata.version('threatx_api_client')}"
        }

        self.parallel_requests = 10
        self.base_url = self.__get_api_env_host()
        self.session_token = asyncio.run(self.__login())

    def __get_api_env_host(self):
        if self.api_env not in self.host_parts:
            raise TXAPIIncorrectEnvironmentError(
                f"TX API Env '{self.api_env}' not found!"
            )

        part = (f"-{self.host_parts.get(self.api_env)}"
                if self.host_parts.get(self.api_env) else "")

        return f"https://provision{part}.threatx.io"

    def __generate_api_link(self, api_ver: int):
        return f"/{self.api_path}/v{api_ver}"

    async def __post(self, session, path: str, post_payload: dict):
        async with asyncio.Semaphore(self.parallel_requests):
            marker_var = post_payload.get("marker_var")
            clean_post_payload = post_payload.copy()
            clean_post_payload.pop("marker_var", None)

            async with session.post(path, json=clean_post_payload) as raw_response:
                try:
                    response = await raw_response.json(content_type=None)
                except JSONDecodeError:
                    request_id = raw_response.headers.get("X-Request-ID")
                    raise TXAPIResponseError(
                        f"Could not parse the API response.\n"
                        f"Request ID: {request_id}\n"
                        f"Please contact: support@threatx.com"
                    )

                response_ok_data = response.get("Ok")
                response_error_data = response.get("Error")

                if response_ok_data is not None:
                    if marker_var:
                        return {marker_var: response_ok_data}
                    return response_ok_data

                if response_error_data == "Token Expired. Please re-authenticate.":
                    self.session_token = asyncio.run(self.__login())
                    return self.__post(session, path, post_payload)
                elif response_error_data:
                    error_msg = {marker_var: response_error_data} if marker_var else response_error_data
                    raise TXAPIResponseError(error_msg)
                else:
                    return {marker_var: response} if marker_var else response

    async def __process_response(self, path: str, available_commands: list, payloads):
        if isinstance(payloads, dict):
            payloads = [payloads]

        for payload in payloads:
            if payload.get("command") not in available_commands:
                raise TXAPIIncorrectCommandError(payload.get("command"))

        async with aiohttp.ClientSession(
                base_url=self.base_url, headers=self.headers,
                connector=aiohttp.TCPConnector(force_close=True, enable_cleanup_closed=True)
        ) as session:
            responses = await asyncio.gather(*(
                self.__post(
                    session,
                    path,
                    {"token": self.session_token, **payload}) for payload in payloads
            ), return_exceptions=True)

        if len(responses) == 1:
            return responses[0]

        return responses

    async def __login(self):
        path = f"{self.__generate_api_link(1)}/login"

        if not self.api_key:
            raise TXAPIIncorrectTokenError("Please provide TX API Key.")

        async with aiohttp.ClientSession(
                base_url=self.base_url, headers=self.headers,
                connector=aiohttp.TCPConnector(force_close=True, enable_cleanup_closed=True)
        ) as session:
            response = await asyncio.gather(
                self.__post(
                    session,
                    path,
                    {"command": "login", "api_token": self.api_key}
                )
            )

        token_value = response[0]["token"]

        if not token_value:
            raise TXAPIIncorrectTokenError("TX API Token is not correct!")

        return token_value

    def api_keys(self, payloads):
        """API Keys management.

        Method allows to manage API keys, allowing authorized users to
        create (and revoke) keys granting automated access to the ThreatX API.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(2)}/apikeys"

        available_commands = ["list", "new", "update", "revoke"]

        return asyncio.run(self.__process_response(url, available_commands, payloads))

    def api_schemas(self, payloads):
        """API schemas management.

        Method allows to manage API schemas.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/apischemas"

        available_commands = ["save", "list", "delete"]

        return asyncio.run(self.__process_response(url, available_commands, payloads))

    def customers(self, payloads):
        """Customers management.

        Method allows to create, manage and remove customers.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/customers"

        available_commands = [
            "list",
            "list_all",
            "new",
            "get",
            "update",
            "delete",
            "list_api_keys",
            "new_api_key",
            "delete_api_key",
            "get_customer_config",
            "set_customer_config"
        ]

        return asyncio.run(self.__process_response(url, available_commands, payloads))

    def users(self, payloads):
        """Users management.

        Method allows to create, manage and remove users.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/users"

        available_commands = [
            "list",
            "new",
            "get",
            "update",
            "delete"
        ]

        return asyncio.run(self.__process_response(url, available_commands, payloads))

    def sites(self, payloads):
        """Sites management.

        Method allows to create, manage and remove sites.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(2)}/sites"

        available_commands = ["list", "new", "get", "delete", "update", "unset"]

        return asyncio.run(self.__process_response(url, available_commands, payloads))

    def site_groups(self, payloads):
        """Site groups management.

        Method allows to create, manage and remove site groups.
        Site groups provide access control features similar to UNIX user groups,
        restricting access to ThreatX sites.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/sitegroups"

        available_commands = ["list", "save", "delete"]

        return asyncio.run(self.__process_response(url, available_commands, payloads))

    def templates(self, payloads):
        """Templates management.

        Method allows to create, manage and remove customer templates.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/templates"

        available_commands = ["set", "get", "delete"]

        return asyncio.run(self.__process_response(url, available_commands, payloads))

    def sensors(self, payloads):
        """Sensors information.

        Method provides information of on-premises deployed sensors and sensor metadata.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/sensors"

        available_commands = ["list", "tags"]

        return asyncio.run(self.__process_response(url, available_commands, payloads))

    def services(self, payloads):
        """Services information.

        Method provides information on ThreatX system services
        and their public IP addresses.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/services"

        available_commands = ["list"]

        return asyncio.run(self.__process_response(url, available_commands, payloads))

    def entities(self, payloads):
        """Entities management.

        Method allows to list and manage entities.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
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

        return asyncio.run(self.__process_response(url, available_commands, payloads))

    def metrics(self, payloads):
        """Statistical metrics.

        Method provides statistical metrics on ThreatX system operations.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
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

        return asyncio.run(self.__process_response(url, available_commands, payloads))

    def subscriptions(self, payloads):
        """Subscriptions management.

        Method allows to configure customer notification subscriptions.
        Subscriptions are used to receive notifications related
        to ThreatX events, delivered either via email,
        webhook, or through a log emitter communicating directly to an analyzer.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/subscriptions"

        available_commands = ["save", "delete", "list", "enable", "disable"]

        return asyncio.run(self.__process_response(url, available_commands, payloads))

    def list_whitelist(self, payloads):
        """Get whitelist IPs.

        Method allows to get customer whitelisted IPs.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/whitelist"

        available_commands = ["list"]

        return asyncio.run(self.__process_response(url, available_commands, payloads))

    def list_blacklist(self, payloads):
        """Get blacklist IPs.

        Method allows to get customer blacklisted IPs.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/blacklist"

        available_commands = ["list"]

        return asyncio.run(self.__process_response(url, available_commands, payloads))

    def list_blocklist(self, payloads):
        """Get blocklisted IPs.

        Method allows to get customer blocked IPs.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/blocklist"

        available_commands = ["list"]

        return asyncio.run(self.__process_response(url, available_commands, payloads))

    def list_mutelist(self, payloads):
        """Get mutelisted IPs.

        Method allows to get customer mutelisted IPs.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/mutelist"

        available_commands = ["list"]

        return asyncio.run(self.__process_response(url, available_commands, payloads))

    def list_ignorelist(self, payloads):
        """Get ignorelisted IPs.

        Method allows to get customer ignorelisted IPs.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/ignorelist"

        available_commands = ["list"]

        return asyncio.run(self.__process_response(url, available_commands, payloads))

    def global_tags(self, payloads):
        """Global tags management.

        Method allows to create new and provides information of
        global tags available for use.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/globaltags"

        available_commands = ["new", "list"]

        return asyncio.run(self.__process_response(url, available_commands, payloads))

    def actor_tags(self, payloads):
        """Actor tags management.

        Method allows to create, manage and remove actor tags.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/actortags"

        available_commands = ["new", "list", "delete"]

        return asyncio.run(self.__process_response(url, available_commands, payloads))

    def features(self, payloads):
        url = f"{self.__generate_api_link(1)}/features"

        available_commands = ["list", "query", "save", "delete"]

        return asyncio.run(self.__process_response(url, available_commands, payloads))

    def metrics_tech(self, payloads):
        """API Profiler information.

        Method provides information of customer API Profiler.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/metrics/tech"

        available_commands = ["list_endpoint_profiles", "list_site_profiles"]

        return asyncio.run(self.__process_response(url, available_commands, payloads))

    def channels(self, payloads):
        """Channels management.

        Method allows to create, manage and remove customer channels.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/channels"

        available_commands = ["new", "list", "update"]

        return asyncio.run(self.__process_response(url, available_commands, payloads))

    def global_settings(self, payloads):
        """Customer-wide settings.

        Method allows to get default customer-wide settings applied.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/globalsettings"

        available_commands = ["get"]

        return asyncio.run(self.__process_response(url, available_commands, payloads))

    def dns_info(self, payloads):
        """DNS configuration information.

        Method allows clients to retrieve information necessary for configuring DNS to address ThreatX services.
        :param list[dict]|dict payloads: API payloads or a single payload containing main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(1)}/dnsinfo"

        available_commands = ["list"]

        return asyncio.run(self.__process_response(url, available_commands, payloads))

    def logs(self, payloads):
        """Customer logs.

        Method allows to get customer logs including audit logs, match events, etc.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
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

        return asyncio.run(self.__process_response(url, available_commands, payloads))

    def logs_v2(self, payloads):
        """Customer logs.

        Method allows to get customer logs including block, match and audit events.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
        """
        url = f"{self.__generate_api_link(2)}/logs"

        available_commands = [
            "block_events",
            "match_events",
            "audit_events"
        ]

        return asyncio.run(self.__process_response(url, available_commands, payloads))

    def lists(self, payloads):
        """Lists management.

        Method allows to manage IP addresses within black, block and whitelists.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
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

        return asyncio.run(self.__process_response(url, available_commands, payloads))

    def rules(self, payloads):
        """Rules management.

        Method allows to create, manage and remove customer rules.
        :param list[dict]|dict payloads: API payloads or a single payload containing
        main command and additional parameters.
        :return: responses: API responses
        :rtype: list[dict]|dict
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

        return asyncio.run(self.__process_response(url, available_commands, payloads))
