/**
 * background.js - Extension background service worker
 * 
 * Handles extension lifecycle, settings management, and communication
 * between content scripts and popup.
 */

chrome.runtime.onInstalled.addListener(function() {
    console.log('[Phishing Detector] Extension installed');
    
    // Initialize default settings
    chrome.storage.sync.set({
        apiEndpoint: 'http://localhost:8080/api/analyze',
        enabled: true,
        showLowRisk: false
    });
});
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "analyze") {
        fetch('http://localhost:8080/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(request.data)
        })
		// Inside background.js
		.then(async response => {
		    const contentType = response.headers.get("content-type");
		    if (response.ok && contentType && contentType.includes("application/json")) {
		        return response.json();
		    } else {
		        // Log the actual text to see the error message from Spring
		        const errorText = await response.text();
		        throw new Error(`Server Error: ${response.status} - ${errorText}`);
		    }
		})
      
        .then(result => sendResponse(result))
        .catch(error => {
            console.error('Fetch Error:', error);
            sendResponse({ error: error.message });
        });
        return true; // Keeps the channel open for the async response
    }
});
// Listen for messages from content scripts
chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    if (request.action === 'getSettings') {
        chrome.storage.sync.get({
            apiEndpoint: 'http://localhost:8080/api/analyze',
            enabled: true,
            showLowRisk: false
        }, function(settings) {
            sendResponse(settings);
        });
        return true; // Keep message channel open for async response
    }
});

// Handle extension icon clicks (if no popup is set)
chrome.action.onClicked.addListener(function(tab) {
    // This is a fallback in case popup doesn't work
    chrome.tabs.create({ url: 'popup.html' });
});