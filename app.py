from flask import Flask, render_template, request, jsonify
import os, pandas as pd
from scipy.sparse import hstack
from utils.data_fetch import fetch_tranco_legit, fetch_phishtank_phish
from utils.feature_extraction import extract_features
from utils.model_utils import build_or_load_model

app = Flask(__name__)
DATA_DIR = "data"

# Load ML model and vectorizer
model, vectorizer, feature_columns = build_or_load_model()

@app.route("/")
def home():
    return render_template("home/index.html")

@app.route("/about")
def about():
    return render_template("about/index.html")

@app.route("/predict", methods=["POST"])
def predict():
    import matplotlib
    matplotlib.use('Agg')  # Use headless backend
    import matplotlib.pyplot as plt
    from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay, classification_report
    import io, base64

    url = request.form.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL required"}), 400

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    # Feature extraction
    features = pd.DataFrame([extract_features(url)])
    for col in feature_columns:
        if col not in features.columns:
            features[col] = 0
    features = features[feature_columns]
    X_tfidf = vectorizer.transform([url])
    X = hstack([features.values, X_tfidf])

    pred = model.predict(X)[0]
    prob = model.predict_proba(X)[0][1]
    label = "Phishing" if pred == 1 else "Legitimate"

    # --- Visualization Section ---
    #nw push
    # Generate sample confusion matrix (using model on a small set for demo)
    sample_urls = ["http://paypal-login.com", "https://google.com", "http://bank-update.net", "https://openai.com"]
    Xs = hstack([
        pd.DataFrame([extract_features(u) for u in sample_urls])[feature_columns].values,
        vectorizer.transform(sample_urls)
    ])
    ys_pred = model.predict(Xs)
    ys_true = [1, 0, 1, 0]  # Simulated truth

    cm = confusion_matrix(ys_true, ys_pred)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Legitimate", "Phishing"])
    fig, ax = plt.subplots(figsize=(4, 4))
    disp.plot(ax=ax, cmap="Blues", colorbar=False)
    plt.title("Confusion Matrix")
    plt.tight_layout()

    # Convert to base64 image
    buf = io.BytesIO()
    plt.savefig(buf, format="png", bbox_inches="tight")
    buf.seek(0)
    encoded_img = base64.b64encode(buf.read()).decode('utf-8')
    plt.close(fig)

    # --- Classification Report ---
    report = classification_report(ys_true, ys_pred, target_names=["Legitimate", "Phishing"], output_dict=True)
    df_report = pd.DataFrame(report).transpose().round(2)
    html_report = df_report.to_html(classes="report-table", border=0)

    return render_template(
        "home/index.html",
        url=url,
        prediction=label,
        confidence=f"{prob*100:.2f}%",
        confusion_img=encoded_img,
        report_html=html_report
    )

@app.route('/refresh-data')
def refresh_data():
    legit = fetch_tranco_legit()
    phish = fetch_phishtank_phish()

    if phish is None:
        return jsonify({
            "status": "error",
            "message": "Failed to fetch phishing data. Please try again later."
        }), 500

    data = pd.concat([legit, phish], ignore_index=True)
    data.to_json(os.path.join(DATA_DIR, "combined_data.json"), orient="records", indent=2)
    return jsonify({
        "status": "success",
        "message": "Live datasets updated successfully.",
        "count": len(data)
    })

if __name__ == "__main__":
    app.run(debug=True)
