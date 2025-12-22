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
