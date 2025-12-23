from flask import Flask, render_template, request
from Challenger import check_ip, check_ip_vt ,check_vpn_proxycheck

app = Flask(__name__)

def abuse_color(score):
    if score == 0:
        return "bg-success text-white px-2 py-1 rounded"
    elif score <= 49:
        return "bg-warning text-dark px-2 py-1 rounded"
    elif score <= 80:
        return "bg-warning text-dark px-2 py-1 rounded"
    else:
        return "bg-danger text-white px-2 py-1 rounded"


def vt_color(malicious):
    if malicious == 0:
        return "bg-success text-white px-2 py-1 rounded"
    elif malicious <= 4:
        return "bg-warning text-dark px-2 py-1 rounded"
    else:
        return "bg-danger text-white px-2 py-1 rounded"

app.jinja_env.globals.update(abuse_color=abuse_color)
app.jinja_env.globals.update(vt_color=vt_color)


# The master list of AbuseIPDB categories
ABUSE_CATEGORIES = {
    1: "DNS Compromise",  2: "DNS Poisoning", 3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force",
    6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy", 10: "Web Spam",
    11: "Email Spam", 12: "Blog Spam", 13: "VPN IP", 14: "Port Scan", 15: "Hacking",
    16: "SQL Injection", 17: "Spoofing", 18: "Brute-Force", 19: "Bad Web Bot",
    20: "Exploited Host", 21: "Web App Attack", 22: "SSH", 23: "IoT Targeted"
}

@app.context_processor
def utility_processor():
    def get_category_name(category_id):
        # Looks up the name, returns the ID number if not found
        return ABUSE_CATEGORIES.get(category_id, f"Category {category_id}")
    
    # This makes the function available as 'get_category_name' in HTML
    return dict(get_category_name=get_category_name)


@app.route("/", methods=["GET", "POST"])
def index():
    report = None
    ip = "0.0.0.0"

    if request.method == "POST":
        ip = request.form.get("ip")
        abuse = check_ip(ip)
        vt = check_ip_vt(ip)
        # censys = get_censys_ip_info(ip)
        proxy =  check_vpn_proxycheck(ip)
        report = {"abuse": abuse, "vt": vt, "vpn":proxy }
    return render_template("index.html", report=report, ip=ip)

if __name__ == "__main__":
    app.run(debug=True)
