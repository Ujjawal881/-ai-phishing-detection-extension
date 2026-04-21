import pandas as pd
import joblib
import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix
from sklearn.utils import class_weight

import matplotlib.pyplot as plt

# ============================================
# LOAD DATA
# ============================================

data = pd.read_csv("../dataset/Phishing_Legitimate_full.csv")

# Drop ID safely
if "id" in data.columns:
    data = data.drop(columns=["id"])

# ============================================
# SELECT URL FEATURES
# ============================================

url_features = [
    "NumDots",
    "SubdomainLevel",
    "PathLevel",
    "UrlLength",
    "NumDash",
    "NumDashInHostname",
    "AtSymbol",
    "TildeSymbol",
    "NumUnderscore",
    "NumPercent",
    "NumQueryComponents",
    "NumAmpersand",
    "NumHash",
    "NumNumericChars",
    "NoHttps",
    "IpAddress",
    "HttpsInHostname",
    "HostnameLength",
    "PathLength",
    "QueryLength",
    "DoubleSlashInPath",
    "NumSensitiveWords"
]

X = data[url_features]
y = data["CLASS_LABEL"]

# ============================================
# HANDLE CLASS IMBALANCE 🔥
# ============================================

weights = class_weight.compute_class_weight(
    class_weight="balanced",
    classes=np.unique(y),
    y=y
)

class_weights = dict(zip(np.unique(y), weights))

# ============================================
# TRAIN TEST SPLIT (STRATIFIED)
# ============================================

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# ============================================
# MODEL + HYPERPARAMETER TUNING 🔥
# ============================================

base_model = RandomForestClassifier(
    random_state=42,
    class_weight=class_weights
)

param_grid = {
    "n_estimators": [200, 300],
    "max_depth": [None, 20],
    "min_samples_split": [2, 5]
}

grid = GridSearchCV(
    base_model,
    param_grid,
    cv=3,
    n_jobs=-1,
    verbose=1
)

grid.fit(X_train, y_train)

model = grid.best_estimator_

print("✅ Best Parameters:", grid.best_params_)

# ============================================
# EVALUATION
# ============================================

pred = model.predict(X_test)
probs = model.predict_proba(X_test)[:, 1]

print("\n📊 Classification Report:")
print(classification_report(y_test, pred))

print("📊 ROC-AUC:", roc_auc_score(y_test, probs))

print("📊 Confusion Matrix:")
print(confusion_matrix(y_test, pred))

# ============================================
# 🔥 THRESHOLD TUNING (CRITICAL)
# ============================================

threshold = 0.4   # more sensitive to phishing

custom_pred = (probs >= threshold).astype(int)

print("\n⚠ Custom Threshold (0.4) Performance:")
print(classification_report(y_test, custom_pred))

# ============================================
# SAVE MODEL
# ============================================

joblib.dump(model, "../models/url_only_model.pkl")

print("✅ URL-only model saved successfully!")

# ============================================
# FEATURE IMPORTANCE
# ============================================

importances = model.feature_importances_
indices = np.argsort(importances)[-10:]

plt.figure()
plt.title("Top 10 URL Feature Importance")
plt.barh(range(len(indices)), importances[indices])
plt.yticks(range(len(indices)), [url_features[i] for i in indices])
plt.xlabel("Importance")
plt.show()