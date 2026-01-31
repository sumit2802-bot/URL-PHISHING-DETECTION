import pandas as pd
import urllib.request
import os
import re
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix

# ==========================================
# PHASE 1: DATA COLLECTION & PROCESSING
# ==========================================

FILE_PATH = 'processed_data.csv'

def extract_features(url):
    """Extracts 18 numerical features from a URL string."""
    url = str(url).lower()
    return [
        len(url),                                                    # 1. url_length
        url.count('.'),                                              # 2. dot_count
        1 if '@' in url else 0,                                      # 3. has_at_symbol
        1 if '-' in url else 0,                                      # 4. has_dash
        1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0,           # 5. is_ip
        1 if url.startswith('https') else 0,                         # 6. is_https
        1 if 'login' in url else 0,                                  # 7. has_login
        1 if 'verify' in url else 0,                                 # 8. has_verify
        1 if 'bank' in url else 0,                                   # 9. has_bank
        1 if re.search(r'bit\.ly|goo\.gl|tinyurl', url) else 0,      # 10. has_shortener
        sum(c.isdigit() for c in url),                               # 11. digit_count
        1 if url.count('.') > 3 else 0,                              # 12. heavy_subdomains
        1 if ';' in url else 0,                                      # 13. has_semicolon
        1 if '_' in url else 0,                                      # 14. has_underscore
        1 if '?' in url else 0,                                      # 15. has_query_param
        1 if '=' in url else 0,                                      # 16. has_equal_sign
        url.count('/'),                                              # 17. slash_count
        1 if 'https' in url.replace('https://', '') else 0           # 18. fake_https_token
    ]

def get_raw_data(url, filename):
    """Downloads and standardizes raw CSV data."""
    if not os.path.exists('data'):
        os.makedirs('data')
        
    try:
        path = os.path.join('data', filename)
        if not os.path.exists(path):
            print(f"⬇️ Downloading {filename}...")
            urllib.request.urlretrieve(url, path)
        
        df = pd.read_csv(path)
        df.columns = [col.lower().strip() for col in df.columns]
        
        # Standardize 'domain' column to 'url'
        if 'domain' in df.columns and 'url' not in df.columns:
            df.rename(columns={'domain': 'url'}, inplace=True)
            
        return df[['url', 'label']] if 'url' in df.columns else None
    except Exception as e:
        print(f"⚠️ Error with {filename}: {e}")
        return None

def prepare_data():
    """Main driver for data collection and processing."""
    if os.path.exists(FILE_PATH):
        print(f"✅ Found existing '{FILE_PATH}'. Skipping download/processing.")
        return

    print("--- 🔄 Starting Data Processing Phase ---")
    
    # Raw Data Sources
    url_1 = "https://raw.githubusercontent.com/shreyagopal/Phishing-Website-Detection-by-Machine-Learning-Techniques/master/DataFiles/5.urldata.csv"
    url_2 = "https://raw.githubusercontent.com/manish-9245/Phishing-Website-Detection/master/dataset.csv"

    # Load and Combine
    df1 = get_raw_data(url_1, "raw_urls_1.csv")
    df2 = get_raw_data(url_2, "phishing_site_urls.csv")
    
    if df1 is None and df2 is None:
        print("❌ Critical Error: Could not download any data.")
        exit()

    combined_df = pd.concat([d for d in [df1, df2] if d is not None], ignore_index=True)
    combined_df.drop_duplicates(subset='url', inplace=True)
    print(f"📊 Processing {len(combined_df)} unique URLs...")

    # Feature Names
    feature_names = [
        'url_length', 'dot_count', 'has_at_symbol', 'has_dash',
        'is_ip', 'is_https', 'has_login', 'has_verify', 'has_bank',
        'has_shortener', 'digit_count', 'heavy_subdomains', 'has_semicolon',
        'has_underscore', 'has_query_param', 'has_equal_sign', 'slash_count',
        'fake_https_token'
    ]

    # Apply Extraction
    print("⚙️ Extracting features (this may take a moment)...")
    feature_results = combined_df['url'].apply(extract_features)
    feature_df = pd.DataFrame(feature_results.tolist(), columns=feature_names)

    # Combine with Labels
    final_df = pd.concat([feature_df, combined_df['label'].reset_index(drop=True)], axis=1)

    # Map Labels to Binary (1 = Phishing, 0 = Safe)
    label_map = {'bad': 1, 'phishing': 1, 'good': 0, 'legitimate': 0}
    final_df['label'] = final_df['label'].map(label_map).fillna(0).astype(int)

    # Save
    final_df.to_csv(FILE_PATH, index=False)
    print(f"✅ Processed data saved to '{FILE_PATH}'")

# Run the data preparation logic
prepare_data()

# ==========================================
# PHASE 2: MODEL TRAINING & EVALUATION
# ==========================================

print("\n--- 🤖 Starting Model Training Phase ---")

# Load Data
data = pd.read_csv(FILE_PATH)

# Define features (Must match extract_features list)
features = [
    'url_length', 'dot_count', 'has_at_symbol', 'has_dash',
    'is_ip', 'is_https', 'has_login', 'has_verify', 'has_bank',
    'has_shortener', 'digit_count', 'heavy_subdomains', 'has_semicolon',
    'has_underscore', 'has_query_param', 'has_equal_sign', 'slash_count',
    'fake_https_token'
]

# Verify features exist
existing_features = [f for f in features if f in data.columns]
if not existing_features:
    print("❌ Error: Required features not found in CSV.")
    exit()

X = data[existing_features]
y = data['label']

# Split and Train
print(f"🧠 Training Random Forest on {len(data)} samples...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Accuracy Check
accuracy = model.score(X_test, y_test)
print(f"🎯 Model Accuracy: {accuracy * 100:.2f}%")

# Save Model
joblib.dump(model, 'phishing_model.pkl')
print("💾 Model saved as 'phishing_model.pkl'")

# ==========================================
# PHASE 3: VISUALIZATION
# ==========================================

output_folder = 'results'
if not os.path.exists(output_folder):
    os.makedirs(output_folder)

print("\n--- 🎨 Generating Visualizations ---")

# 1. Confusion Matrix
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

# 2. Feature Importance
print("📈 Generating Feature Importance Graph...")
importances = model.feature_importances_
feature_imp_df = pd.DataFrame({'Feature': existing_features, 'Importance': importances})
feature_imp_df = feature_imp_df.sort_values(by='Importance', ascending=False)

plt.figure(figsize=(10, 6))
sns.barplot(x='Importance', y='Feature', data=feature_imp_df, palette='viridis')
plt.title('Most Important Features for Detecting Phishing')
plt.tight_layout()
plt.savefig(f'{output_folder}/feature_importance.png')
plt.close()

# 3. Donut Dashboard
print("🍩 Generating Donut Dashboard...")
class_counts = y.value_counts()
plt.figure(figsize=(6,6))
plt.pie(class_counts, labels=['Safe', 'Phishing'], autopct='%1.1f%%',
        startangle=90, wedgeprops=dict(width=0.4))
plt.title('Dataset Distribution (Safe vs Phishing)')
plt.savefig(f'{output_folder}/donut_dashboard.png')
plt.close()

print(f"✅ All done! Check the '{output_folder}' folder for graphs.")
