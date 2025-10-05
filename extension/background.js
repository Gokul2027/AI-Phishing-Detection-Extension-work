// This listener fires when a tab is updated (e.g., a new URL is loaded)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // We only want to act when the tab is fully loaded and has a URL
  if (
    changeInfo.status === "complete" &&
    tab.url &&
    tab.url.startsWith("http")
  ) {
    // Send the URL to our local Python server for analysis
    fetch("http://127.0.0.1:5000/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: tab.url }),
    })
      .then((response) => response.json())
      .then((data) => {
        // If the server says it's phishing, we take action
        if (data.is_phishing) {
          // Inject the content script into the dangerous page
          chrome.scripting
            .executeScript({
              target: { tabId: tabId },
              files: ["content.js"],
            })
            .then(() => {
              // After the script is injected, send it the reasons why the site is dangerous
              chrome.tabs.sendMessage(tabId, {
                is_phishing: true,
                reasons: data.reasons, // Pass the feature list
              });
            })
            .catch((err) =>
              console.error("AI Detector: Script injection failed: " + err)
            );
        }
      })
      .catch((error) => {
        console.error(
          "AI Detector: Could not connect to the analysis server.",
          error
        );
      });
  }
});
