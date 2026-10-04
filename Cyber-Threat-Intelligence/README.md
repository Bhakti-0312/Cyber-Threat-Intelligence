# Cyber Threat Intelligence System Using NLP

## Project Overview

**Cyber Threat Intelligence System Using NLP for Security Log Classification** is a small academic web application that analyzes cybersecurity logs and incident reports using Natural Language Processing (NLP) and machine learning.

The system classifies an input security log into one of three threat categories:

- **Malware**
- **Phishing**
- **Ransomware**

Along with classification, the application demonstrates several NLP preprocessing and analysis techniques used in the practical work.

## Objectives

- Analyze security logs and incident reports using NLP.
- Remove common noise from raw cybersecurity text.
- Demonstrate tokenization, stop-word removal, stemming, and lemmatization.
- Perform lightweight POS tagging and named-entity extraction.
- Generate bigrams and trigrams from threat-related text.
- Classify security logs using TF-IDF features and Logistic Regression.
- Calculate text similarity with the threat categories.
- Present the analysis through a simple Flask web interface.

## NLP and Machine Learning Techniques

1. **Tokenization** – splits the security log into individual words/tokens.
2. **Noise Filtering** – removes items such as IP addresses, hexadecimal codes, and unnecessary delimiters.
3. **Stop-word Removal** – removes common words that add little classification value.
4. **Stemming** – reduces words to simplified root-like forms.
5. **Lemmatization** – normalizes common word forms.
6. **POS Tagging** – assigns simple grammatical tags to tokens.
7. **Named Entity Extraction** – identifies items such as IP addresses, email addresses, URLs, and hexadecimal codes.
8. **Bigram Analysis** – identifies two-word combinations.
9. **Trigram Analysis** – identifies three-word combinations.
10. **TF-IDF** – converts text into numerical features for machine learning and similarity analysis.
11. **Logistic Regression** – predicts the threat category.
12. **Text Similarity** – compares the input with category representations using cosine similarity.

## Technology Stack

- **Python**
- **Flask**
- **scikit-learn**
- **HTML**
- **CSS**
- **JavaScript**

## Project Structure

```text
Cyber-Threat-Intelligence/
├── app.py
├── requirements.txt
├── README.md
├── templates/
│   └── index.html
└── static/
    ├── style.css
    └── script.js
```

## How the System Works

```text
Security Log / Incident Report
              ↓
       Noise Filtering
              ↓
         Tokenization
              ↓
       NLP Preprocessing
   (Stop Words, Stemming,
      Lemmatization)
              ↓
   POS / Entity / N-grams
              ↓
        TF-IDF Features
              ↓
      Logistic Regression
              ↓
       Threat Category
              ↓
       NLP Analysis Output
```

## Installation

### 1. Open the project in VS Code

Open the `Cyber-Threat-Intelligence` folder in Visual Studio Code.

### 2. Create and activate a virtual environment (recommended)

Windows:

```bash
python -m venv venv
venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the application

```bash
python app.py
```

### 5. Open the web application

Open the following address in a browser:

```text
http://127.0.0.1:5000
```

## Example Inputs

### Malware

```text
A malicious executable was detected on the workstation. The malware created a backdoor and attempted to download an additional payload from a remote server. The security system detected suspicious activity and isolated the infected machine.
```

Expected category: **Malware**

### Phishing

```text
A suspicious email was received from an unknown sender. The message contained a fake login link asking the user to verify their account password. The user entered credentials on the malicious website, and the attacker attempted to access the corporate email account.
```

Expected category: **Phishing**

### Ransomware

```text
Multiple files on the workstation were encrypted by ransomware. The attacker displayed a ransom note demanding Bitcoin payment in exchange for a decryption key. The affected files could no longer be opened by the user.
```

Expected category: **Ransomware**

## Output

For each submitted log, the application displays:

- Predicted threat category
- Model confidence/probabilities
- Processed text
- Removed noise
- Tokens
- Stop-word filtered tokens
- Stemmed tokens
- Lemmatized tokens
- POS tags
- Named entities
- Bigrams
- Trigrams
- Category similarity scores

## Testing

The final prototype was tested using representative Malware, Phishing, and Ransomware incident reports. These three primary test cases produced their expected categories.

An additional suspicious login example was also tested. Because the current classifier is trained only on the three predefined threat categories, an unseen log can still be assigned to the closest learned category even when its confidence is low.

## Important Limitation

This is an **academic prototype**, not a production cybersecurity detection system. The Logistic Regression classifier uses a small built-in training dataset containing examples for the three supported categories. Therefore, the model should not be interpreted as a real-world threat detection engine or as a measure of production-level accuracy.

A future version could use a larger labeled cybersecurity dataset and add an explicit **Unknown/Suspicious** class with a confidence threshold.

## Academic Scope

The project demonstrates how NLP and machine learning can be applied to cybersecurity text. It is designed to remain small and understandable for a college mini-project while connecting the implementation with common NLP practical concepts.

## Author

College Mini-Project – Cyber Threat Intelligence using NLP
