// This function updates the enhanced UI of the popup with the analysis results
function displayResults(data) {
  const statusIcon = document.getElementById("status-icon");
  const statusText = document.getElementById("status-text");
  const probabilitiesDiv = document.getElementById("probabilities");
  const readMoreBtn = document.getElementById("read-more-btn");
  const reasonsDiv = document.getElementById("reasons");
  const reasonsTitle = document.getElementById("reasons-title");
  const reasonsList = document.getElementById("reasons-list");

  // Hide the initial loading text
  document.getElementById("loading-text").style.display = "none";
  probabilitiesDiv.style.display = "block";

  let listItemsHTML = "";

  if (data.is_phishing) {
    statusIcon.src = "icon.png"; // Your shield icon
    statusText.textContent = "Phishing";
    statusText.className = "phishing";

    probabilitiesDiv.innerHTML = `<strong>Probability of Phishing:</strong> ${data.prob_phishing}`;

    reasonsTitle.textContent = "Reasoning (Phishing features detected):";
    if (data.is_on_blocklist) {
      listItemsHTML += `<li><strong>Found on live phishing blocklist!</strong></li>`;
    }
    data.risky_features.forEach((f) => {
      listItemsHTML += `<li>${f}</li>`;
    });
    if (data.risky_features.length === 0 && !data.is_on_blocklist) {
      listItemsHTML += `<li>Verdict based on a combination of factors.</li>`;
    }
  } else {
    statusIcon.src = "icon.png"; // Your shield icon
    statusText.textContent = "Benign";
    statusText.className = "benign";

    probabilitiesDiv.innerHTML = `
            <strong>Probability of Phishing:</strong> ${data.prob_phishing}<br>
            <strong>Probability of Legitimate:</strong> ${data.prob_legitimate}
        `;

    reasonsTitle.textContent = "Reasoning (Benign features confirmed):";
    data.safe_features.slice(0, 5).forEach((f) => {
      listItemsHTML += `<li>${f}</li>`;
    });
    if (data.safe_features.length === 0) {
      listItemsHTML += `<li>No significant phishing indicators found.</li>`;
    }
  }

  reasonsList.innerHTML = listItemsHTML;
  readMoreBtn.style.display = "block";

  readMoreBtn.onclick = () => {
    const isHidden =
      reasonsDiv.style.display === "none" || reasonsDiv.style.display === "";
    reasonsDiv.style.display = isHidden ? "block" : "none";
    readMoreBtn.textContent = isHidden ? "Hide Details" : "Show Details";
  };
}

// --- Main execution when popup is opened ---
document.addEventListener("DOMContentLoaded", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    const currentTab = tabs[0];
    if (currentTab && currentTab.url && currentTab.url.startsWith("http")) {
      fetch("http://127.0.0.1:5000/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: currentTab.url }),
      })
        .then((response) => {
          if (!response.ok)
            throw new Error(`Server responded with status: ${response.status}`);
          return response.json();
        })
        .then((data) => {
          if (data.error) throw new Error(data.details || data.error);
          displayResults(data);
        })
        .catch((error) => {
          document.getElementById("status-text").textContent =
            "Connection Error";
          document.getElementById("status-text").className = "loading";
          document.getElementById("loading-text").textContent =
            "Could not connect to the backend server. Make sure app.py is running.";
        });
    } else {
      document.getElementById("status-text").textContent = "Not a Webpage";
      document.getElementById("status-text").className = "loading";
      document.getElementById("loading-text").textContent =
        "This extension only works on http/https websites.";
    }
  });
});
