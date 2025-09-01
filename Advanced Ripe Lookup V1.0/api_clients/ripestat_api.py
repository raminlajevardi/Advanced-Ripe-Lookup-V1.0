import requests

class RipeStatAPI:
    BASE_URL = "https://stat.ripe.net/data"

    @staticmethod
    def get_routing_status(resource):
        url = f"{RipeStatAPI.BASE_URL}/routing-status/data.json"
        resp = requests.get(url, params={"resource": resource})
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def get_rpki_validation(resource):
        url = f"{RipeStatAPI.BASE_URL}/rpki-validation/data.json"
        resp = requests.get(url, params={"resource": resource})
        resp.raise_for_status()
        return resp.json()
