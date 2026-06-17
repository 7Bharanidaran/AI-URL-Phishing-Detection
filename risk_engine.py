def calculate_risk(prediction, vt_result):

    malicious = vt_result["malicious"]
    suspicious = vt_result["suspicious"]

    if prediction == "phishing" and malicious >= 10:
        return "CRITICAL"

    elif prediction == "phishing" and malicious >= 5:
        return "HIGH"

    elif prediction == "phishing":
        return "MEDIUM"

    elif malicious > 0 or suspicious > 0:
        return "MEDIUM"

    else:
        return "LOW"
