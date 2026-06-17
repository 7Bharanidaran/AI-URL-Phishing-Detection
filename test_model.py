import joblib

model = joblib.load("../models/phishing_model.pkl")

# Feature vector for a very simple URL
sample = [18,1,0,2,0,0,0,0,0,1,0,0,0,0,0,0,0]

print("Classes:", model.classes_)

pred = model.predict([sample])
proba = model.predict_proba([sample])

print("Prediction:", pred)
print("Probabilities:", proba)
