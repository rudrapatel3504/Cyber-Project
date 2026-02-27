import requests
import logging

def run_http_analysis(target):
    logging.info("Running HTTP header analysis")

    try:
        response = requests.get(f"http://{target}", timeout=5)
        headers = dict(response.headers)
        return headers
    except Exception as e:
        logging.error(f"HTTP analysis failed: {e}")
        return {}