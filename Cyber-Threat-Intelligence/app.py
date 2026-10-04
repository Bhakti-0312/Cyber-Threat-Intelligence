from flask import Flask, render_template, request, jsonify
import re
from collections import Counter
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression

app = Flask(__name__)

# Small built-in training set for the mini-project.
TRAINING_TEXTS = [
    "malware detected malicious executable trojan infected workstation",
    "virus infected computer malicious software payload",
    "spyware keylogger captured user information",
    "backdoor installed by malicious program on system",
    "worm spread across network systems",
    "malicious executable downloaded additional payload",
    "trojan malware opened unauthorized backdoor",
    "phishing email fake login page requested password",
    "suspicious link asked user to verify account credentials",
    "fake banking website collected username and password",
    "attacker sent phishing message with malicious login link",
    "social engineering email requested account verification",
    "credential theft through fake authentication website",
    "ransomware encrypted files and demanded ransom",
    "files were locked and attacker demanded bitcoin payment",
    "ransomware attack encrypted documents on workstation",
    "victim received ransom note for decryption key",
    "encrypted files could not be opened after ransomware attack",
    "attacker demanded cryptocurrency to decrypt files",
]

TRAINING_LABELS = [
    "Malware", "Malware", "Malware", "Malware", "Malware", "Malware", "Malware",
    "Phishing", "Phishing", "Phishing", "Phishing", "Phishing", "Phishing",
    "Ransomware", "Ransomware", "Ransomware", "Ransomware", "Ransomware", "Ransomware"
]

CLASSIFIER = Pipeline([
    ("tfidf", TfidfVectorizer(ngram_range=(1, 2), lowercase=True)),
    ("model", LogisticRegression(max_iter=1000, random_state=42))
])
CLASSIFIER.fit(TRAINING_TEXTS, TRAINING_LABELS)

def classify_threat(text):
    """Classify a report using TF-IDF features and Logistic Regression."""
    prediction = CLASSIFIER.predict([text])[0]
    probabilities = CLASSIFIER.predict_proba([text])[0]
    classes = CLASSIFIER.named_steps["model"].classes_
    scores = {
        category: {"score": round(float(probability), 4), "matched": []}
        for category, probability in zip(classes, probabilities)
    }
    return prediction, scores


STOP_WORDS = {
    "the", "a", "an", "and", "or", "but", "is", "was", "were", "are",
    "to", "of", "in", "on", "from", "for", "with", "this", "that",
    "has", "have", "had", "by", "as", "at", "it", "be", "been"
}


def remove_noise(text):
    """Remove IP addresses, hex values and special delimiters."""
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", " ", text)
    text = re.sub(r"\b0x[a-fA-F0-9]+\b", " ", text)
    text = re.sub(r"[^A-Za-z0-9\s]", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def tokenize(text):
    return re.findall(r"\b[A-Za-z]+\b", text)


def normalize(tokens):
    """Simple rule-based normalization for a dependency-light first version."""
    filtered = [t.lower() for t in tokens if t.lower() not in STOP_WORDS]

    # Small stemming-style rules for demonstration.
    stemmed = []
    for word in filtered:
        w = word
        for suffix in ("ing", "ed", "es", "s"):
            if len(w) > len(suffix) + 3 and w.endswith(suffix):
                w = w[:-len(suffix)]
                break
        stemmed.append(w)

    # Lightweight lemmatization examples relevant to cybersecurity.
    lemma_map = {
        "exfiltrating": "exfiltrate",
        "exfiltrated": "exfiltrate",
        "attacks": "attack",
        "attacked": "attack",
        "attacking": "attack",
        "detected": "detect",
        "detecting": "detect",
        "deleted": "delete",
        "deleting": "delete",
        "encrypted": "encrypt",
        "encrypting": "encrypt",
        "credentials": "credential",
        "files": "file",
        "logs": "log",
    }
    lemmatized = [lemma_map.get(t, t) for t in filtered]

    return filtered, stemmed, lemmatized


def make_ngrams(tokens, n):
    return [
        " ".join(tokens[i:i+n])
        for i in range(len(tokens) - n + 1)
    ]


def simple_pos_tag(tokens):
    """Lightweight POS tagging for common cybersecurity terms."""
    verbs = {
        "detect", "detected", "attempt", "attempted", "access", "blocked",
        "encrypt", "encrypted", "download", "downloaded", "request",
        "requested", "verify", "verified", "steal", "stole", "install",
        "installed", "spread", "demand", "demanded", "found", "entered"
    }
    adjectives = {
        "suspicious", "malicious", "unknown", "fake", "unauthorized",
        "vulnerable", "remote", "encrypted"
    }
    determiners = {"the", "a", "an", "this", "that"}
    prepositions = {"from", "to", "in", "on", "with", "for", "by", "of", "at"}

    result = []
    for token in tokens:
        w = token.lower()
        if w in determiners:
            tag = "DT"
        elif w in prepositions:
            tag = "IN"
        elif w in verbs or w.endswith(("ed", "ing")):
            tag = "VB"
        elif w in adjectives:
            tag = "JJ"
        elif w.isdigit():
            tag = "CD"
        else:
            tag = "NN"
        result.append({"token": token, "tag": tag})
    return result


def extract_entities(text):
    """Extract useful security entities without requiring an external NLP model."""
    entities = []
    patterns = [
        ("IP_ADDRESS", r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        ("HEX_CODE", r"\b0x[a-fA-F0-9]+\b"),
        ("EMAIL", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        ("URL", r"https?://[^\s]+"),
    ]
    for label, pattern in patterns:
        for match in re.findall(pattern, text):
            entities.append({"text": match.rstrip(".,!?"), "label": label})
    return entities


def similarity_score(text):
    # Compare the entered report with short category descriptions.
    references = [
        "malware malicious software trojan virus infected system payload backdoor",
        "phishing fake login suspicious link credential password verify account email",
        "ransomware encrypted files ransom bitcoin decrypt locked files extortion"
    ]

    try:
        vectorizer = TfidfVectorizer()
        matrix = vectorizer.fit_transform([text] + references)
        score = cosine_similarity(matrix[0:1], matrix[1:])[0]
        return {
            "Malware": round(float(score[0]), 4),
            "Phishing": round(float(score[1]), 4),
            "Ransomware": round(float(score[2]), 4),
        }
    except ValueError:
        return {"Malware": 0.0, "Phishing": 0.0, "Ransomware": 0.0}


def analyze_text(text):
    cleaned = remove_noise(text)
    tokens = tokenize(cleaned)
    filtered, stemmed, lemmatized = normalize(tokens)

    category, classification = classify_threat(cleaned)

    bigrams = Counter(make_ngrams(lemmatized, 2)).most_common(5)
    trigrams = Counter(make_ngrams(lemmatized, 3)).most_common(5)

    ip_addresses = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    hex_codes = re.findall(r"\b0x[a-fA-F0-9]+\b", text)

    return {
        "category": category,
        "confidence": classification.get(category, {}).get("score", 0.0),
        "cleaned_text": cleaned,
        "tokens": tokens,
        "filtered_tokens": filtered,
        "stemmed_tokens": stemmed,
        "lemmatized_tokens": lemmatized,
        "pos_tags": simple_pos_tag(tokens),
        "entities": extract_entities(text),
        "bigram": [{"text": x, "count": y} for x, y in bigrams],
        "trigram": [{"text": x, "count": y} for x, y in trigrams],
        "ip_addresses": ip_addresses,
        "hex_codes": hex_codes,
        "classification": classification,
        "similarity": similarity_score(cleaned),
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    text = (data.get("text") or "").strip()

    if not text:
        return jsonify({"error": "Please enter a security log or incident report."}), 400

    return jsonify(analyze_text(text))


if __name__ == "__main__":
    app.run(debug=True)
