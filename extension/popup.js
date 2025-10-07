// This function updates the HTML of the popup with the analysis results
function displayResults(data) {
  const statusIcon = document.getElementById("status-icon");
  const statusText = document.getElementById("status-text");
  const probabilitiesDiv = document.getElementById("probabilities");
  const readMoreBtn = document.getElementById("read-more-btn");
  const reasonsDiv = document.getElementById("reasons");
  document.getElementById("loading").style.display = "none";

  let reasonsHTML = "";

  if (data.is_phishing) {
    statusIcon.textContent = "⚠️";
    statusText.textContent = "Phishing";
    statusText.className = "phishing";

    probabilitiesDiv.innerHTML = `<strong>Probability of Phishing:</strong> ${data.prob_phishing}`;

    if (data.is_on_blocklist) {
      reasonsHTML +=
        "<strong>❗️ Pre-check Result: PHISHING (Found on GitHub blocklist)</strong><br><br>";
    }
    reasonsHTML += `<strong>Result: Phishing</strong><br><span>Reasoning (Phishing features detected with a value of 1):</span>
                        <ul>${data.risky_features
                          .map((f) => `<li>${f}</li>`)
                          .join("")}</ul>`;
  } else {
    statusIcon.textContent = "✅";
    statusText.textContent = "Benign";
    statusText.className = "benign";

    probabilitiesDiv.innerHTML = `
            <strong>Probability of Phishing:</strong> ${data.prob_phishing}<br>
            <strong>Probability of Legitimate:</strong> ${data.prob_legitimate}
        `;

    reasonsHTML = `<strong>Result: Benign</strong><br><span>Reasoning (Benign features detected with a value of -1):</span>
                       <ul>${data.safe_features
                         .slice(0, 5)
                         .map((f) => `<li>${f}</li>`)
                         .join("")}</ul>`;
  }

  reasonsDiv.innerHTML = reasonsHTML;
  readMoreBtn.style.display = "block";
  readMoreBtn.onclick = () => {
    reasonsDiv.style.display =
      reasonsDiv.style.display === "none" ? "block" : "none";
  };
}

// --- Main execution when popup is opened ---
chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
  const currentTab = tabs[0];
  if (currentTab && currentTab.url && currentTab.url.startsWith("http")) {
    fetch("http://127.0.0.1:5000/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: currentTab.url }),
    })
      .then((response) => response.json())
      .then((data) => {
        if (data.error) {
          document.getElementById("status-text").textContent = "Error";
          document.getElementById(
            "loading"
          ).textContent = `Could not analyze page: ${
            data.details || data.error
          }`;
        } else {
          displayResults(data);
        }
      })
      .catch((error) => {
        document.getElementById("status-text").textContent = "Connection Error";
        document.getElementById("loading").textContent =
          "Could not connect to the backend server. Make sure app.py is running.";
      });
  } else {
    document.getElementById("status-text").textContent = "Not a webpage";
    document.getElementById("loading").textContent =
      "This extension only works on http/https websites.";
  }
});
