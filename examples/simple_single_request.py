from threatx_api_client import Client

tx_api = Client("prod", "")


def get_customer_sites(customer_name: str) -> list:
    """Getting customer sites.

    Get tenant sites data with customer name provided.
    :param customer_name:
    :return: API responses
    :rtype: list
    """
    sites = tx_api.sites(
        {
            "command": "list",
            "customer_name": customer_name,
        }
    )
    return sites


if __name__ == '__main__':
    customer_name = ""
    print(get_customer_sites(customer_name))
