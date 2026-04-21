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

# Drop ID column
if "id" in data.columns:
    data = data.drop(columns=["id"])

# ============================================
# FEATURES / TARGET
# ============================================

X = data.drop(columns=["CLASS_LABEL"])
y = data["CLASS_LABEL"]

# ============================================
# HANDLE CLASS IMBALANCE
# ============================================

weights = class_weight.compute_class_weight(
    class_weight="balanced",
    classes=np.unique(y),
    y=y
)

class_weights = dict(zip(np.unique(y), weights))

# ============================================
# TRAIN TEST SPLIT
# ============================================

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# ============================================
# MODEL (WITH TUNING)
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

print("Best Params:", grid.best_params_)

# ============================================
# PREDICTIONS
# ============================================

pred = model.predict(X_test)
probs = model.predict_proba(X_test)[:, 1]

# ============================================
# EVALUATION
# ============================================

print("\n📊 Classification Report:")
print(classification_report(y_test, pred))

print("📊 ROC-AUC:", roc_auc_score(y_test, probs))

print("📊 Confusion Matrix:")
print(confusion_matrix(y_test, pred))

# ============================================
# THRESHOLD TUNING (IMPORTANT 🔥)
# ============================================

threshold = 0.4  # more sensitive for phishing

custom_pred = (probs >= threshold).astype(int)

print("\n⚠ Custom Threshold Evaluation (0.4):")
print(classification_report(y_test, custom_pred))

# ============================================
# SAVE MODEL
# ============================================

joblib.dump(model, "../models/url_only_model.pkl")

print("✅ Model saved successfully!")

# ============================================
# FEATURE IMPORTANCE
# ============================================

importances = model.feature_importances_
feature_names = X.columns

indices = np.argsort(importances)[-10:]

plt.figure()
plt.title("Top 10 Important Features")
plt.barh(range(len(indices)), importances[indices])
plt.yticks(range(len(indices)), [feature_names[i] for i in indices])
plt.xlabel("Feature Importance")
plt.show()