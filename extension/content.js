chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // Check if the message is a phishing alert and if the banner already exists
  if (
    request.is_phishing &&
    !document.getElementById("ai-phishing-alert-overlay")
  ) {
    // --- Create the Warning Elements ---
    const overlay = document.createElement("div");
    overlay.id = "ai-phishing-alert-overlay";
    Object.assign(overlay.style, {
      position: "fixed",
      top: "0",
      left: "0",
      width: "100%",
      height: "100%",
      backgroundColor: "rgba(0, 0, 0, 0.75)",
      zIndex: "2147483647",
      display: "flex",
      justifyContent: "center",
      alignItems: "center",
      fontFamily: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
    });

    const modal = document.createElement("div");
    Object.assign(modal.style, {
      backgroundColor: "white",
      borderRadius: "10px",
      padding: "30px 40px",
      width: "500px",
      textAlign: "center",
      boxShadow: "0 5px 15px rgba(0,0,0,0.3)",
    });

    const icon = document.createElement("div");
    icon.textContent = "⚠️";
    icon.style.fontSize = "50px";

    const title = document.createElement("h1");
    title.textContent = "Phishing Site Detected";
    title.style.color = "#d93025";
    title.style.margin = "10px 0";

    const message = document.createElement("p");
    message.textContent =
      "Our AI model has determined this site may be trying to steal your personal information. We strongly advise you to go back.";
    message.style.fontSize = "16px";
    message.style.color = "#555";
    message.style.marginBottom = "25px";

    const readMoreButton = document.createElement("button");
    readMoreButton.textContent = "Read More...";
    Object.assign(readMoreButton.style, {
      background: "none",
      border: "none",
      color: "#007bff",
      cursor: "pointer",
      fontSize: "14px",
      marginBottom: "20px",
    });

    const reasonsDiv = document.createElement("div");
    reasonsDiv.style.display = "none"; // Hidden by default
    reasonsDiv.style.textAlign = "left";
    reasonsDiv.style.padding = "10px";
    reasonsDiv.style.border = "1px solid #eee";
    reasonsDiv.style.borderRadius = "5px";
    reasonsDiv.style.maxHeight = "150px";
    reasonsDiv.style.overflowY = "auto";
    reasonsDiv.style.marginBottom = "20px";
    reasonsDiv.innerHTML =
      "<strong>Suspicious Features Found:</strong><ul>" +
      request.reasons.map((reason) => `<li>${reason}</li>`).join("") +
      "</ul>";

    readMoreButton.onclick = () => {
      reasonsDiv.style.display =
        reasonsDiv.style.display === "none" ? "block" : "none";
    };

    const websiteLink = document.createElement("a");
    websiteLink.textContent = "Visit our Phishing Check Website";
    websiteLink.href = "https://example.com"; // Your future website link
    websiteLink.target = "_blank"; // Open in new tab
    websiteLink.style.display = "block";
    websiteLink.style.marginBottom = "25px";

    const backButton = document.createElement("button");
    backButton.textContent = "Go Back to Safety";
    Object.assign(backButton.style, {
      backgroundColor: "#d93025",
      color: "white",
      border: "none",
      padding: "12px 25px",
      borderRadius: "5px",
      fontSize: "16px",
      cursor: "pointer",
      marginRight: "10px",
    });
    backButton.onclick = () => window.history.back();

    const proceedButton = document.createElement("button");
    proceedButton.textContent = "Proceed Anyway";
    Object.assign(proceedButton.style, {
      backgroundColor: "#f0f0f0",
      color: "#333",
      border: "1px solid #ccc",
      padding: "12px 25px",
      borderRadius: "5px",
      fontSize: "16px",
      cursor: "pointer",
    });
    proceedButton.onclick = () => overlay.remove();

    // --- Assemble the Modal ---
    modal.appendChild(icon);
    modal.appendChild(title);
    modal.appendChild(message);
    modal.appendChild(readMoreButton);
    modal.appendChild(reasonsDiv);
    modal.appendChild(websiteLink);
    modal.appendChild(backButton);
    modal.appendChild(proceedButton);
    overlay.appendChild(modal);
    document.body.appendChild(overlay);
  }
});
