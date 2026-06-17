import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

from feature_extraction import extract_features

# Load dataset
df = pd.read_csv("../data/phishing_simple (1).csv")

print("Dataset loaded successfully")

# Create features
X = []

for url in df['URL']:
    X.append(extract_features(url))

# Labels
y = df['label']

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

# Train model
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

print("Training model...")
model.fit(X_train, y_train)

# Predictions
y_pred = model.predict(X_test)

# Accuracy
accuracy = accuracy_score(y_test, y_pred)

print("Accuracy:", accuracy)

# Save model


print("Classes:", model.classes_)
print(df["label"].value_counts())
print(df["label"].unique())

joblib.dump(model, "../models/phishing_model.pkl")

print("Model saved successfully!")
joblib.dump(model, "../models/phishing_model.pkl")

print("Model saved successfully!")
