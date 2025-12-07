# utils/model_utils.py
import os, joblib, pandas as pd
from xgboost import XGBClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from scipy.sparse import hstack
from utils.data_fetch import fetch_tranco_legit, fetch_phishtank_phish
from utils.feature_extraction import extract_features

MODEL_DIR = "model"

def build_or_load_model():
    model_path = os.path.join(MODEL_DIR, "phishing_model.joblib")
    vec_path = os.path.join(MODEL_DIR, "vectorizer.joblib")
    feat_path = os.path.join(MODEL_DIR, "feature_columns.joblib")

    os.makedirs(MODEL_DIR, exist_ok=True)

    # ✅ Reuse trained model if present
    if all(os.path.exists(p) for p in [model_path, vec_path, feat_path]):
        print("🔁 Loading existing model...")
        return joblib.load(model_path), joblib.load(vec_path), joblib.load(feat_path)

    print("⚙️ Training new model...")

    legit = fetch_tranco_legit(500)
    phish = fetch_phishtank_phish(500)
    data = pd.concat([legit, phish], ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)

    # Feature extraction
    features = pd.DataFrame([extract_features(u) for u in data["domain"]])
    vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(3,5), max_features=500)
    tfidf_matrix = vectorizer.fit_transform(data["domain"])

    # Store the feature column names
    feature_columns = list(features.columns)

    X = hstack([features.values, tfidf_matrix])
    y = data["label"]

    model = XGBClassifier(
        n_estimators=250, 
        max_depth=6, 
        learning_rate=0.1, 
        eval_metric="logloss", 
        use_label_encoder=False
    )
    model.fit(X, y)

    joblib.dump(model, model_path)
    joblib.dump(vectorizer, vec_path)
    joblib.dump(feature_columns, feat_path)
    print("✅ Model trained and saved successfully.")

    return model, vectorizer, feature_columns
