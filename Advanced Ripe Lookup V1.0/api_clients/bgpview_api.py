import requests

class BGPViewAPI:
    BASE_URL = "https://api.bgpview.io"

    @staticmethod
    def get_prefix_info(prefix):
        url = f"{BGPViewAPI.BASE_URL}/prefix/{prefix}"
        resp = requests.get(url)
        resp.raise_for_status()
        return resp.json()
