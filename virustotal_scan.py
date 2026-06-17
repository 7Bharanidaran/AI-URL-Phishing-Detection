import requests
import time

API_KEY = "9f25101673f760f995dafe88c59bdb428d1868fd624a5b328b092d3e60b4ee4e"

headers = {
    "x-apikey":"9f25101673f760f995dafe88c59bdb428d1868fd624a5b328b092d3e60b4ee4e" 
}

def scan_url(url):

    submit_response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url}
    )

    submit_json = submit_response.json()

    analysis_id = submit_json["data"]["id"]

    while True:

        result = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers
        )

        result_json = result.json()

        status = result_json["data"]["attributes"]["status"]

        if status == "completed":
            break

        time.sleep(2)

    stats = result_json["data"]["attributes"]["stats"]

    return stats
