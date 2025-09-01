import requests

class RipeDBAPI:
    BASE_URL = "https://rest.db.ripe.net/search.json"

    @staticmethod
    def query(object_type, query):
        params = {"query-string": query, "type-filter": object_type}
        resp = requests.get(RipeDBAPI.BASE_URL, params=params)
        resp.raise_for_status()
        return resp.json()
