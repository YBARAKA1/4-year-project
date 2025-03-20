from sklearn.ensemble import IsolationForest
import joblib

# Example training data (replace with real network traffic features)
X_train = [[100], [200], [300], [400], [500]]  # Example: packet sizes

# Train the model
model = IsolationForest(contamination=0.1)  # Adjust contamination as needed
model.fit(X_train)

# Save the model
joblib.dump(model, "anomaly_detection_model.pkl")
print("Model saved as anomaly_detection_model.pkl")