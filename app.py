from flask import Flask, render_template, request, jsonify
import pickle
import re
import os, json
from datetime import datetime
from flask_cors import CORS

#flask app creation
app = Flask(__name__)
CORS(app)

#load LR model & vectorizer
vector = pickle.load(open("vectorizer.pkl", 'rb'))
model = pickle.load(open("phishing.pkl", 'rb'))

#file path for history
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(BASE_DIR, "history.json")

#load history function
def load_history():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return []

#save history function
def save_history(history):
    with open(DATA_FILE, "w") as f:
        json.dump(history, f, indent=4)

#Rule-based phishing detection
def detect_url(url):
    phishing_keywords = [
        "verify", "verification", "login", "secure",
        "account", "update", "alert", "confirm", "banking", "free"
    ]

    # 1️⃣ If IP address used → phishing
    if re.search(r"\d+\.\d+\.\d+\.\d+", url):
        return "PHISHING"

    # 2️⃣ Long URL → phishing
    if len(url) > 75:
        return "PHISHING"

    # 3️⃣ Suspicious keywords
    for word in phishing_keywords:
        if word in url.lower():
            return "PHISHING"

    # 4️⃣ Brand name not official domain
    if "paypal" in url.lower() and not url.startswith("https://www.paypal.com"):
        return "PHISHING"

    # else safe
    return "LEGITIMATE"

#Counters used for statistics
phishing_count = 0
legitimate_count = 0

#Home route
@app.route("/", methods=['GET', 'POST'])
def index():
    url = ""
    predict = None
    confidence = None
    risk = None

    # 🔹 load previous history
    history = load_history()

    if request.method == "POST":
        url = request.form['url']
        
        predict = detect_url(url)
        
        cleaned_url = re.sub(r'^https?://(www\.)?', '', url)

        result = model.predict(vector.transform([cleaned_url]))[0]
        prob = model.predict_proba(vector.transform([cleaned_url]))[0]

        classes = model.classes_
        phishing_index = list(classes).index('bad')
        phishing_prob = prob[phishing_index] * 100

        confidence = round(phishing_prob, 2)

        if result == 'bad':
            predict = "PHISHING"
        else:
            predict = "LEGITIMATE"

        if phishing_prob >= 85:
            risk = "HIGH"
        elif phishing_prob >= 45:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        # ✅ ADD TO HISTORY
        history.append({
            "url": url,
            "result": predict,
            "confidence": confidence,
            "risk": risk,
            "time": datetime.now().strftime("%d-%m-%Y %H:%M")
        })

        save_history(history)

    return render_template(
    "index.html",
    predict=predict,
    confidence=confidence,
    risk=risk,
    url=url
    )

    return render_template("index.html")

@app.route("/history")
def history_page():
    history = load_history()
    return render_template("history.html", history=history)

@app.route("/stats")
def stats():
    history = load_history()

    phishing = sum(1 for h in history if h["result"] == "PHISHING")
    legitimate = sum(1 for h in history if h["result"] == "LEGITIMATE")

    return {
        "phishing": phishing,
        "legitimate": legitimate
    }

@app.route("/api/predict", methods=["POST"])
def api_predict():
    data = request.get_json()
    url = data.get("url")

    cleaned_url = re.sub(r'^https?://(www\.)?', '', url)

    result = model.predict(vector.transform([cleaned_url]))[0]
    prob = model.predict_proba(vector.transform([cleaned_url]))[0]

    classes = model.classes_
    phishing_index = list(classes).index('bad')
    phishing_prob = round(prob[phishing_index] * 100, 2)

    if result == "bad":
        label = "PHISHING"
    else:
        label = "LEGITIMATE"

    if phishing_prob >= 85:
        risk = "HIGH"
    elif phishing_prob >= 65:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return jsonify({
        "url": url,
        "result": label,
        "confidence": phishing_prob,
        "risk": risk
    })

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({"error": "No URL received"}), 400

    url = data["url"]

    # ---- YOUR DETECTION LOGIC ----
    predict = detect_url(url)   # your existing function

    return jsonify({
        "prediction": predict  # "PHISHING" or "LEGITIMATE"
    })

if __name__ == "__main__":
    app.run(debug=True)