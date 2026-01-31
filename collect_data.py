import pandas as pd
import urllib.request
import os

# Setup directory
if not os.path.exists('data'):
    os.makedirs('data')

print("--- Phase 1: Data Collection Started ---")

# UPDATED WORKING URLS
# Dataset 1: Shreya Gopal (Has columns: index, domain, label)
url_1 = "https://raw.githubusercontent.com/shreyagopal/Phishing-Website-Detection-by-Machine-Learning-Techniques/master/DataFiles/5.urldata.csv"
# Dataset 2: Alternative source for phishing_site_urls
url_2 = "https://raw.githubusercontent.com/manish-9245/Phishing-Website-Detection/master/dataset.csv"

def get_data(url, filename):
    try:
        path = os.path.join('data', filename)
        print(f"Attempting to download {filename}...")
        urllib.request.urlretrieve(url, path)
        
        # Load and fix column names immediately
        df = pd.read_csv(path)
        df.columns = [col.lower().strip() for col in df.columns]
        
        # Rename 'domain' to 'url' if it exists (fixes your KeyError)
        if 'domain' in df.columns and 'url' not in df.columns:
            df.rename(columns={'domain': 'url'}, inplace=True)
            
        # Ensure we have the basics
        if 'url' in df.columns and 'label' in df.columns:
            return df[['url', 'label']]
        else:
            print(f"Warning: {filename} missing 'url' or 'label'. Found: {list(df.columns)}")
            return None
            
    except Exception as e:
        print(f"Skipping {filename} due to error: {e}")
        return None

# Process both
df1 = get_data(url_1, "raw_urls_1.csv")
df2 = get_data(url_2, "phishing_site_urls.csv")

# Combine results
dfs = [d for d in [df1, df2] if d is not None]

if dfs:
    final_df = pd.concat(dfs, ignore_index=True)
    final_df.drop_duplicates(subset='url', inplace=True)
    
    # Save
    final_df.to_csv("data/cleaned_dataset.csv", index=False)
    print(f"\n--- Success! ---")
    print(f"Final dataset size: {len(final_df)} rows")
    print("Saved to: data/cleaned_dataset.csv")
else:
    print("Error: No data could be processed.")
