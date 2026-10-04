const sampleTexts = [
    "A malicious executable was detected on the workstation. The malware created a backdoor and attempted to download an additional payload from a remote server.",

    "A suspicious email was received from an unknown sender. The message contained a fake login link asking the user to verify their account password.",

    "Multiple files on the workstation were encrypted by ransomware. The attacker displayed a ransom note demanding Bitcoin payment in exchange for a decryption key.",

    "The security system detected an unusual login from a new device. The user account was accessed outside normal working hours and was flagged for further investigation."
];

let sampleIndex = 0;

function createTags(items) {
    if (!items || items.length === 0) {
        return '<span class="tag">None</span>';
    }
    return items.map(item => `<span class="tag">${escapeHtml(item)}</span>`).join("");
}

function createPhrases(items) {
    if (!items || items.length === 0) {
        return '<span class="tag">Not enough text</span>';
    }

    return items.map(item =>
        `<div class="phrase">
            <span>${escapeHtml(item.text)}</span>
            <strong>${item.count}</strong>
        </div>`
    ).join("");
}

function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

async function analyzeThreat() {
    const input = document.getElementById("logInput").value.trim();
    const error = document.getElementById("errorMessage");
    const button = document.getElementById("analyzeBtn");

    error.textContent = "";

    if (!input) {
        error.textContent = "Please enter a security log or incident report.";
        return;
    }

    button.disabled = true;
    button.textContent = "Analyzing...";

    try {
        const response = await fetch("/analyze", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({text: input})
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Analysis failed.");
        }

        showResults(data);
    } catch (err) {
        error.textContent = err.message;
    } finally {
        button.disabled = false;
        button.textContent = "Analyze Threat";
    }
}

function showResults(data) {
    document.getElementById("results").classList.remove("hidden");

    document.getElementById("category").textContent = data.category;
    document.getElementById("cleanedText").textContent = data.cleaned_text;

    const noise = [
        ...data.ip_addresses.map(ip => `IP removed: ${ip}`),
        ...data.hex_codes.map(hex => `Hex removed: ${hex}`)
    ];
    document.getElementById("noiseResults").innerHTML = createTags(noise);

    document.getElementById("tokens").innerHTML = createTags(data.tokens);
    document.getElementById("filteredTokens").innerHTML = createTags(data.filtered_tokens);
    document.getElementById("stemmedTokens").innerHTML = createTags(data.stemmed_tokens);
    document.getElementById("lemmatizedTokens").innerHTML = createTags(data.lemmatized_tokens);

    document.getElementById("bigrams").innerHTML = createPhrases(data.bigram);
    document.getElementById("trigrams").innerHTML = createPhrases(data.trigram);

    document.getElementById("posTags").innerHTML = data.pos_tags
        .map(item => `<span class="tag">${escapeHtml(item.token)} / ${escapeHtml(item.tag)}</span>`)
        .join("");

    document.getElementById("entities").innerHTML = data.entities.length
        ? data.entities.map(item => `
            <div class="phrase">
                <span>${escapeHtml(item.text)}</span>
                <strong>${escapeHtml(item.label)}</strong>
            </div>
        `).join("")
        : '<span class="tag">No entities detected</span>';

    const matches = document.getElementById("matches");
    matches.innerHTML = "";

    Object.entries(data.classification).forEach(([category, info]) => {
        matches.innerHTML += `
            <div class="match-box">
                <strong>${escapeHtml(category)}</strong>
                <span>Model probability: ${(info.score * 100).toFixed(2)}%</span>
            </div>
        `;
    });

    const similarity = document.getElementById("similarity");
    similarity.innerHTML = "";

    Object.entries(data.similarity).forEach(([category, score]) => {
        const percentage = Math.min(score * 100, 100);
        similarity.innerHTML += `
            <div class="sim-row">
                <div class="sim-head">
                    <span>${escapeHtml(category)}</span>
                    <strong>${score.toFixed(4)}</strong>
                </div>
                <div class="bar"><span style="width:${percentage}%"></span></div>
            </div>
        `;
    });
}

function loadSample() {
    document.getElementById("logInput").value = sampleTexts[sampleIndex];

    sampleIndex = (sampleIndex + 1) % sampleTexts.length;
}

function clearAll() {
    document.getElementById("logInput").value = "";
    document.getElementById("results").classList.add("hidden");
    document.getElementById("errorMessage").textContent = "";
}
