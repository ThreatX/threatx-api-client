from threatx_api_client import Client

tx_api = Client("prod", "")


def get_customer_sites_data(customer_name: str, sites: list) -> list:
    """Getting sites data.

    Get tenant sites data with customer name and a list of sites provided.
    :param customer_name:
    :param sites:
    :return: API responses
    :rtype: list
    """
    sites_data = tx_api.sites([
        {
            "command": "get",
            "customer_name": customer_name,
            "name": site
        } for site in sites
    ])
    return sites_data


if __name__ == '__main__':
    customer_name = ""
    sites = ["example.com", "test.local"]
    print(get_customer_sites_data(customer_name, sites))
