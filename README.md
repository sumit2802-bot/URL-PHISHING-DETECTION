🔐 URL Phishing Detection Using Machine Learning

Phishing attacks are one of the most common cyber threats today, where malicious URLs trick users into revealing sensitive information such as passwords, bank details, and personal data.
This project focuses on detecting phishing URLs using Machine Learning techniques, helping users and organizations stay safe from online fraud.

🚀 Project Overview

🔍 Problem: Phishing URLs look similar to legitimate websites

💡 Solution: Automated detection of phishing URLs using Machine Learning

🧠 Approach: Feature extraction from URLs + ML classification

🌐 Input: URL entered by user

📊 Output: Legitimate or Phishing

The project also includes a Flask-based web application for real-time URL analysis.

🧠 Machine Learning Details

Algorithms used:

Logistic Regression

Random Forest

Decision Tree

Support Vector Machine (SVM) (optional)

Feature extraction from URL structure:

URL length

Presence of IP address

Special characters (@, -, //)

HTTPS usage

Sub-domain count

🧪 Dataset

Public phishing URL datasets

Combination of:

Legitimate URLs

Phishing URLs

Dataset link is provided in the Blog / Documentation Section

🛠️ Technologies Used

Python 3.8

Scikit-learn

Pandas

NumPy

Flask

HTML / CSS

Jupyter Notebook

📁 Project Structure
URL-Phishing-Detection/
│
├── Flask App/
│   ├── app.py
│   ├── templates/
│   ├── static/
│   └── phishing_model.pkl
│
├── Model/
│   ├── training.ipynb
│   ├── feature_extraction.py
│   └── model.pkl
│
├── Dataset/
│   └── phishing_urls.csv
│
├── requirements.txt
├── README.md
└── LICENSE

⭐ Run Project on Your Machine
🔹 Prerequisites

Python 3.8 installed

🔹 Step-by-Step Setup
1️⃣ Create & Activate Virtual Environment
python -m venv venv
source venv/bin/activate   # Linux / Mac
venv\Scripts\activate      # Windows

2️⃣ Install Required Dependencies
pip install -r requirements.txt

3️⃣ Navigate to Flask App Folder
cd "Flask App"

4️⃣ Download / Place Trained Model

Place phishing_model.pkl inside Flask App folder

5️⃣ Run Flask Application
python app.py

6️⃣ Open Browser
http://127.0.0.1:5000/


🎉 URL Phishing Detection App is now live!

🧪 Testing URLs

You can test:

Legitimate URLs

Suspicious URLs

Known phishing URLs

The model will instantly classify the URL as:

✅ Legitimate

❌ Phishing

🧑‍💻 Jupyter Notebook (Optional)

Train your own model

Experiment with different algorithms

Improve accuracy

Visualize results

🌐 Web Application Features

Simple and clean UI

Real-time URL prediction

Fast response

Beginner-friendly interface

📝 Blog

📖 URL Phishing Detection Using Machine Learning

Covers:

Feature engineering

Dataset explanation

Model training

Accuracy comparison

🤝 Contribution (Open Source)

This project is open source 🚀

You can contribute by:

Improving UI

Adding Deep Learning models

Improving feature extraction

Adding documentation

Contribution Guidelines:

Fork the repository

Make sure code runs without errors

Upload updated .md, .pdf, .ipynb if model changes

Create a Pull Request after testing

🔗 How to create a Pull Request
https://opensource.com/article/19/7/create-pull-request-github

📦 Releases

🚫 No releases published yet

📜 License

This project is licensed under the MIT License

⭐ Support

If you find this project useful:

⭐ Star this repository

🍴 Fork it

🔐 Help make the internet safer
