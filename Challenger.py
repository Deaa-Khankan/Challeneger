abuseIp_Key= "xxxxxxxxx"
vt_key = "xxxxxxx"
shodan_key = "xxxxxxx"
censys = "cxxxxxxx"
censys_id = "xxxxxx"
proxychecker_key = "xxxxxxxxxxxx"
import requests, json

BASE_URL = "https://api.abuseipdb.com/api/v2/check"
BASE_URL_VT = "https://www.virustotal.com/api/v3/ip_addresses/"

def check_ip(ip):

    headers = {
        "Accept": "application/json",
        "Key": abuseIp_Key
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose" : "true"
    }

    response = requests.get(BASE_URL, headers=headers, params=params, timeout=10)

    # Basic error handling
    if response.status_code != 200:
        raise Exception(f"AbuseIPDB API error: {response.status_code} - {response.text}")

    data = response.json()["data"]
    print(json.dumps(response.json(), indent=4))
    return {
        "ip": data["ipAddress"],
        "abuse_score": data["abuseConfidenceScore"],
        "total_reports": data["totalReports"],
        "country": data.get("countryName"),  # Use "countryName" instead of "countryCode"
        "country_code": data.get("countryCode"), # Keep this for flags/icons if needed
        "isp": data["isp"],
        "domain": data["domain"],
        "usage_type": data["usageType"],
        "reports": data.get("reports", []),  # Ensure this list is included!
    }


def check_ip_vt(ip):
    headers = {"x-apikey": vt_key}
    url = BASE_URL_VT + ip
    response = requests.get(url, headers=headers, timeout=10)
    if response.status_code != 200:
        raise Exception("VirusTotal API error: {} - {}".format(response.status_code, response.text))
    
    data = response.json()["data"]["attributes"]
    
    return {
        "ip": ip,
        "reputation": data.get("reputation"),
        "asn": data.get("asn"),
        "as_owner": data.get("as_owner"),
        "country": data.get("country"),
        "last_analysis_stats": data.get("last_analysis_stats"),
        "tags": data.get("tags"),
        "total_votes": data.get("total_votes"),
        "detected_communicating_samples": data.get("detected_communicating_samples"),
        "resolutions": data.get("resolutions"),
        "last_analysis_date": data.get("last_analysis_date")
    }


# def get_censys_ip_info(ip):
#     url = f"https://api.platform.censys.io/v3/global/asset/host/{ip}?subviews=services"

#     headers = {
#         "Accept": "application/vnd.censys.api.v3.host.v1+json",
#         "Authorization": f"Bearer {censys}",
#     }

#     response = requests.get(url, headers=headers, timeout=10)

#     if response.status_code != 200:
#         raise Exception(f"Censys API error: {response.status_code} - {response.text}")

#     data = response.json()

#     resource = data.get("result", {}).get("resource", {})
#     services = data.get("services", [])

#     print(json.dumps(data, indent=2))

#     # Extract list of ports and software
#     ports = []
    
#     for s in services:
#         port = s.get("port")
#         proto = s.get("service_name")
#         ports.append(f"{port}/{proto}")
    
    
#     print ( data)

#     return {
#     "ip": resource.get("ip"),
#     "labels": sorted({
#             lbl.get("value") 
#             for s in services 
#             for lbl in s.get("labels", []) 
#             if lbl.get("value")
#             }),
#         "open_ports": ports,
#         "services": sorted({s.get("service_name") or s.get("protocol") for s in services}),
#         "org": resource.get("autonomous_system", {}).get("organization_name"),
#         "asn": resource.get("autonomous_system", {}).get("asn"),
#         "country": resource.get("location", {}).get("country"),
#         "last_seen": max((s.get("scan_time") for s in services if s.get("scan_time")), default=None)
#     }



def check_vpn_proxycheck(ip):

    BASE_URL = f"https://proxycheck.io/v3/{ip}"
    params = {
            "vpn": 1,
            "asn": 1,
            "risk": 2
        }

    if proxychecker_key:
        params["key"] = proxychecker_key

    response = requests.get(BASE_URL,  params=params, timeout=10)

    # Basic error handling
    if response.status_code != 200:
        raise Exception(f"Proxycheck API error: {response.status_code} - {response.text}")

    data = response.json()
    ip_data = data.get(ip, {})
    detections = ip_data.get("detections", {})

    if not ip_data:
        raise Exception(f"Proxycheck error: IP {ip} not found in response. Status: {data.get('status')}")
    

    return {
        "ip": ip,
        "is_proxy": detections.get("proxy", False),
        "is_vpn": detections.get("vpn", False),
        "is_compromised": detections.get("compromised", False),
        "is_scraper": detections.get("scraper", False),
        "is_tor": detections.get("tor", False),
        "is_hosting": detections.get("hosting", False),
        "is_anonymous": detections.get("anonymous", False),
        "risk_score": detections.get("risk", 0),
        "confidence": detections.get("confidence", 0),
        "first_seen": detections.get("first_seen", "Never"),
        "last_seen": detections.get("last_seen", "Never")
        }




if __name__ == "__main__":

    ip = input("Enter IP address: ").strip()

    try:
        result_abuse = check_ip(ip)
        result_vt = check_ip_vt(ip)
    except Exception as e:
        print(f"❌ Error: {e}")
        exit(1)

    print("\n🔍 AbuseIPDB Result")
    print("=" * 30)
    print(f"IP Address        : {result_abuse['ip']}")
    print(f"Abuse Confidence  : {result_abuse['abuse_score']}%")
    print(f"Total Reports     : {result_abuse['total_reports']}")
    print(f"Country           : {result_abuse['country']}")
    print(f"ISP               : {result_abuse['isp']}")
    print(f"Domain            : {result_abuse['domain']}")
    print(f"Usage Type        : {result_abuse['usage_type']}")


    print("\n🔍 AbuseIPDB Result")
    print("=" * 30)
    print(f"Reputation: {result_vt.get('reputation')}")
    stats = result_vt.get('last_analysis_stats', {})
    print(f"Malicious: {stats.get('malicious', 0)}")
    print(f"Suspicious: {stats.get('suspicious', 0)}")
    print(f"Harmless: {stats.get('harmless', 0)}")
    print(f"Undetected: {stats.get('undetected', 0)}")
    print(f"Tags: {', '.join(result_vt.get('tags', [])) or 'None'}")
    print(f"ASN: {result_vt.get('asn')}")
    print(f"Owner: {result_vt.get('as_owner')}")
    print(f"Country: {result_vt.get('country')}")
    print(f"Last Analysis Date: {result_vt.get('last_analysis_date')}\n")