import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib
import os
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix

file_path = 'processed_data.csv'
if not os.path.exists(file_path):
    print(f"Error: {file_path} not found. Run process_data.py first!")
    exit()

data = pd.read_csv(file_path)

# Define features
features = [
	'url_length', 'dot_count', 'has_at_symbol', 'has_dash',
            'is_ip', 'is_https', 'has_login', 'has_verify', 'has_bank',
            'has_shortener', 'digit_count', 'heavy_subdomains', 'has_semicolon',
            'has_underscore', 'has_query_param', 'has_equal_sign', 'slash_count',
            'fake_https_token'
]

# Check features exist
existing_features = [f for f in features if f in data.columns]
if len(existing_features) == 0:
    print("Error: None of the required features found in CSV.")
    print(f"Available columns: {data.columns.tolist()}")
    exit()

print(f"Training with features: {existing_features}")

X = data[existing_features]
y = data['label']

# Split and train
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Accuracy
accuracy = model.score(X_test, y_test)
print(f"✅ Accuracy: {accuracy * 100:.2f}%")

# Save model
joblib.dump(model, 'phishing_model.pkl')
print("💾 Model saved as 'phishing_model.pkl'")

# --- Visualization Section ---
output_folder = 'results'
if not os.path.exists(output_folder):
    os.makedirs(output_folder)

# Confusion Matrix
print("📊 Generating Confusion Matrix...")
y_pred = model.predict(X_test)
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=['Safe', 'Phishing'],
            yticklabels=['Safe', 'Phishing'])
plt.title('Phishing Detection - Confusion Matrix')
plt.xlabel('Predicted Label')
plt.ylabel('True Label')
plt.savefig(f'{output_folder}/confusion_matrix.png')
plt.close()

# Feature Importance
print("📈 Generating Feature Importance Graph...")
importances = model.feature_importances_
feature_imp_df = pd.DataFrame({'Feature': existing_features, 'Importance': importances})
feature_imp_df = feature_imp_df.sort_values(by='Importance', ascending=False)
plt.figure(figsize=(10, 6))
sns.barplot(x='Importance', y='Feature', data=feature_imp_df, palette='viridis')
plt.title('Most Important Features for Detecting Phishing')
plt.savefig(f'{output_folder}/feature_importance.png')
plt.close()

# Donut Dashboard
print("🍩 Generating Donut Dashboard...")
class_counts = y.value_counts()
plt.figure(figsize=(6,6))
plt.pie(class_counts, labels=['Safe','Phishing'], autopct='%1.1f%%',
        startangle=90, wedgeprops=dict(width=0.4))
plt.title('Dataset Distribution (Safe vs Phishing)')
plt.savefig(f'{output_folder}/donut_dashboard.png')
plt.close()

print(f"✅ Success! Graphs are saved in the '{output_folder}' folder.")
