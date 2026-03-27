/**
 * content.js - Feature Extraction Engine
 * 
 * This script runs in the context of web pages and extracts phishing detection features
 * from URLs, DOM elements, and JavaScript behavior. It also monitors DOM changes
 * using MutationObserver to detect dynamic injection of malicious content.
 */

class FeatureExtractor {
    constructor() {
        this.features = {};
        this.mutationObserver = null;
        this.lastAnalysisTime = 0;
        this.analysisThrottleMs = 1000; // Prevent excessive API calls
    }

    /**
     * Initialize feature extraction and DOM monitoring
     */
    initialize() {
        console.log('[Phishing Detector] Initializing feature extraction...');
        
        // Extract initial features
        this.extractAllFeatures();
        
        // Send initial analysis
        this.sendAnalysis();
        
        // Setup DOM monitoring
        this.setupMutationObserver();
        
        // Monitor JavaScript behavior
        this.setupBehaviorMonitoring();
    }

    /**
     * Extract all feature categories
     */
    extractAllFeatures() {
        this.features = {
            // URL lexical features
            ...this.extractURLFeatures(),
            
            // Entropy features
            ...this.extractEntropyFeatures(),
            
            // DOM security features
            ...this.extractDOMFeatures(),
            
            // JavaScript behavior features
            ...this.extractBehaviorFeatures()
        };
    }

    /**
     * Extract URL lexical features
     */
    extractURLFeatures() {
        const url = window.location.href;
        
        return {
            url_length: url.length,
            token_count: url.split(/[./\-?_=&]/).filter(t => t.length > 0).length,
            hyphenated_domain: this.hasHyphenatedDomain(url),
            uses_ip_address: this.usesIPAddress(url),
            uses_shortener: this.usesShortener(url)
        };
    }

    /**
     * Check if domain contains hyphens
     */
    hasHyphenatedDomain(url) {
        try {
            const domain = new URL(url).hostname;
            return domain.includes('-') ? 1 : 0;
        } catch {
            return 0;
        }
    }

    /**
     * Check if URL uses IP address instead of domain
     */
    usesIPAddress(url) {
        try {
            const hostname = new URL(url).hostname;
            const ipRegex = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
            return ipRegex.test(hostname) ? 1 : 0;
        } catch {
            return 0;
        }
    }

    /**
     * Check if URL uses known URL shorteners
     */
    usesShortener(url) {
        const shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly'];
        try {
            const domain = new URL(url).hostname.toLowerCase();
            return shorteners.some(shortener => domain.includes(shortener)) ? 1 : 0;
        } catch {
            return 0;
        }
    }

    /**
     * Extract entropy features
     */
    extractEntropyFeatures() {
        const url = window.location.href;
        
        return {
            char_entropy: this.calculateCharEntropy(url),
            token_entropy: this.calculateTokenEntropy(url),
            ngram_entropy: this.calculateNgramEntropy(url, 3)
        };
    }

    /**
     * Calculate character entropy of URL
     */
    calculateCharEntropy(str) {
        const charCounts = {};
        for (const char of str) {
            charCounts[char] = (charCounts[char] || 0) + 1;
        }
        
        let entropy = 0;
        const len = str.length;
        for (const count of Object.values(charCounts)) {
            const p = count / len;
            entropy -= p * Math.log2(p);
        }
        
        return entropy;
    }

    /**
     * Calculate token entropy (segments separated by special chars)
     */
    calculateTokenEntropy(url) {
        const tokens = url.split(/[^a-zA-Z0-9]/).filter(token => token.length > 0);
        const tokenString = tokens.join('');
        return this.calculateCharEntropy(tokenString);
    }

    /**
     * Calculate n-gram entropy
     */
    calculateNgramEntropy(str, n) {
        const ngrams = {};
        for (let i = 0; i <= str.length - n; i++) {
            const ngram = str.substr(i, n);
            ngrams[ngram] = (ngrams[ngram] || 0) + 1;
        }
        
        let entropy = 0;
        const total = Object.values(ngrams).reduce((sum, count) => sum + count, 0);
        for (const count of Object.values(ngrams)) {
            const p = count / total;
            entropy -= p * Math.log2(p);
        }
        
        return entropy;
    }

    /**
     * Extract DOM security features
     */
    extractDOMFeatures() {
        return {
            form_count: document.forms.length,
            password_field_present: this.hasPasswordField(),
            email_field_present: this.hasEmailField(),
            external_form_action: this.hasExternalFormAction(),
            iframe_count: document.querySelectorAll('iframe').length,
            redirect_indicator: this.hasRedirectIndicator()
        };
    }

    /**
     * Check for password input fields
     */
    hasPasswordField() {
        return document.querySelectorAll('input[type="password"]').length > 0 ? 1 : 0;
    }

    /**
     * Check for email input fields
     */
    hasEmailField() {
        const emailInputs = document.querySelectorAll('input[type="email"]');
        const textInputs = document.querySelectorAll('input[type="text"]');
        
        // Check for email type inputs
        if (emailInputs.length > 0) return 1;
        
        // Check for text inputs with email-related names/placeholders
        for (const input of textInputs) {
            const name = (input.name || '').toLowerCase();
            const placeholder = (input.placeholder || '').toLowerCase();
            if (name.includes('email') || placeholder.includes('email')) {
                return 1;
            }
        }
        
        return 0;
    }

    /**
     * Check if forms submit to external domains
     */
    hasExternalFormAction() {
        const currentDomain = window.location.hostname;
        
        for (const form of document.forms) {
            try {
                const action = form.action || window.location.href;
                const actionDomain = new URL(action).hostname;
                if (actionDomain !== currentDomain) {
                    return 1;
                }
            } catch {
                // Invalid URL, consider suspicious
                return 1;
            }
        }
        
        return 0;
    }

    /**
     * Check for redirect indicators in DOM
     */
    hasRedirectIndicator() {
        const redirectKeywords = ['redirect', 'redirecting', 'forward', 'continue'];
        const textContent = document.body ? document.body.textContent.toLowerCase() : '';
        
        return redirectKeywords.some(keyword => textContent.includes(keyword)) ? 1 : 0;
    }

    /**
     * Extract JavaScript behavior features
     */
    extractBehaviorFeatures() {
        return {
            possible_js_obfuscation: this.detectObfuscation(),
            status_bar_customized: this.detectStatusBarCustomization(),
            right_click_disabled: this.detectRightClickDisabled()
        };
    }

    /**
     * Detect possible JavaScript obfuscation
     */
    detectObfuscation() {
        const scripts = document.querySelectorAll('script');
        let obfuscationScore = 0;
        
        for (const script of scripts) {
            const content = script.textContent || '';
            if (content.length > 100) {
                // Check for high entropy (compressed/obfuscated code)
                const entropy = this.calculateCharEntropy(content);
                if (entropy > 5.5) obfuscationScore++;
                
                // Check for unusual character patterns
                const unusualChars = content.match(/[^\w\s]/g) || [];
                if (unusualChars.length / content.length > 0.3) obfuscationScore++;
            }
        }
        
        return obfuscationScore > 0 ? 1 : 0;
    }

    /**
     * Detect status bar customization (common in phishing)
     */
    detectStatusBarCustomization() {
        // Check for onmouseover events that might change status bar
        const elements = document.querySelectorAll('[onmouseover]');
        for (const element of elements) {
            const onmouseover = element.getAttribute('onmouseover') || '';
            if (onmouseover.toLowerCase().includes('status') || 
                onmouseover.toLowerCase().includes('window.status')) {
                return 1;
            }
        }
        return 0;
    }

    /**
     * Detect if right-click is disabled
     */
    detectRightClickDisabled() {
        // Check for event handlers that prevent context menu
        const body = document.body;
        if (body) {
            const contextMenuHandler = body.getAttribute('oncontextmenu') || '';
            if (contextMenuHandler.toLowerCase().includes('return false') || 
                contextMenuHandler.toLowerCase().includes('preventdefault')) {
                return 1;
            }
        }
        return 0;
    }

    /**
     * Setup MutationObserver to monitor DOM changes
     */
    setupMutationObserver() {
        this.mutationObserver = new MutationObserver((mutations) => {
            let shouldReanalyze = false;
            
            for (const mutation of mutations) {
                // Check for added nodes
                for (const node of mutation.addedNodes) {
                    if (node.nodeType === Node.ELEMENT_NODE) {
                        // Check for injected forms
                        if (node.tagName === 'FORM' || node.querySelector('form')) {
                            shouldReanalyze = true;
                        }
                        
                        // Check for injected password fields
                        if (node.querySelector('input[type="password"]')) {
                            shouldReanalyze = true;
                        }
                        
                        // Check for injected iframes
                        if (node.tagName === 'IFRAME' || node.querySelector('iframe')) {
                            shouldReanalyze = true;
                        }
                    }
                }
                
                // Check for attribute changes that might indicate credential harvesting
                if (mutation.type === 'attributes') {
                    const target = mutation.target;
                    if (target.tagName === 'FORM' && mutation.attributeName === 'action') {
                        shouldReanalyze = true;
                    }
                }
            }
            
            if (shouldReanalyze) {
                console.log('[Phishing Detector] DOM changes detected, re-analyzing...');
                this.throttledAnalysis();
            }
        });
        
        // Start observing
        this.mutationObserver.observe(document, {
            childList: true,
            subtree: true,
            attributes: true,
            attributeFilter: ['action', 'type']
        });
    }

    /**
     * Setup behavior monitoring
     */
    setupBehaviorMonitoring() {
        // Monitor for suspicious form submissions
        document.addEventListener('submit', (event) => {
            const form = event.target;
            console.log('[Phishing Detector] Form submission detected');
            
            // Extract form data for additional analysis
            const formData = new FormData(form);
            const hasCredentials = Array.from(formData.keys()).some(key => 
                key.toLowerCase().includes('password') || 
                key.toLowerCase().includes('email') ||
                key.toLowerCase().includes('username')
            );
            
            if (hasCredentials) {
                console.log('[Phishing Detector] Credential form submission detected');
                this.throttledAnalysis();
            }
        });
    }

    /**
     * Throttled analysis to prevent excessive API calls
     */
    throttledAnalysis() {
        const now = Date.now();
        if (now - this.lastAnalysisTime > this.analysisThrottleMs) {
            this.lastAnalysisTime = now;
            this.extractAllFeatures();
            this.sendAnalysis();
        }
    }

    /**
     * Send features to backend for analysis
     */
	async sendAnalysis() {
	    try {
	        const url = window.location.href; 
            const urlNoScheme = url.replace(/^https?:\/\//, '');
	        const features = {
	            url_length: urlNoScheme.length,
	            token_count: urlNoScheme.split(/[./\-?_=&]/).length,
	            hyphenated_domain: this.hasHyphenatedDomain(url),
	            uses_ip_address: this.usesIPAddress(url),
	            uses_shortener: this.usesShortener(url),
	            char_entropy: this.calculateCharEntropy(urlNoScheme),
	            token_entropy: this.calculateTokenEntropy(urlNoScheme),
	            ngram_entropy: this.calculateNgramEntropy(urlNoScheme, 3),
	            form_count: document.forms.length,
	            password_field_present: this.hasPasswordField(),
	            email_field_present: this.hasEmailField(),
	            external_form_action: this.hasExternalFormAction(),
	            iframe_count: document.querySelectorAll('iframe').length,
	            redirect_indicator: this.hasRedirectIndicator(),
	            possible_js_obfuscation: this.detectObfuscation(),
	            status_bar_customized: this.detectStatusBarCustomization(),
	            right_click_disabled: this.detectRightClickDisabled(),
	            url: url
	        };

	        // Send message to background.js
	        chrome.runtime.sendMessage({ action: "analyze", data: features }, (response) => {
	            if (response && !response.error) {
	                this.handleAnalysisResult(response);
	            } else {
	                console.error('[Phishing Detector] Background analysis failed:', response?.error);
	            }
	        });

	    } catch (error) {
	        console.error('[Phishing Detector] Communication error:', error);
	    }
	}
    /**
     * Handle analysis result from backend
     */
    handleAnalysisResult(result) {
        console.log('[Phishing Detector] Analysis result:', result);
        
        // Store result for popup
        chrome.storage.local.set({
            lastAnalysis: {
                ...result,
                url: window.location.href,
                timestamp: Date.now()
            }
        });
        
        // Show popup if risk score >= 4
        if (result.risk_score >= 4) {
            this.showWarningPopup(result);
        }
    }

    /**
     * Show warning popup
     */
    showWarningPopup(result) {
        // Create overlay
        const overlay = document.createElement('div');
        overlay.id = 'phishing-detector-overlay';
        overlay.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.7);
            z-index: 999999;
            display: flex;
            align-items: center;
            justify-content: center;
        `;
        
        // Create popup
        const popup = document.createElement('div');
        popup.style.cssText = `
            background: White;
            border-radius: 8px;
            padding: 20px;
            max-width: 400px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
            font-family: Arial, sans-serif;
        `;
        
        const riskColor = result.risk_level === 'HIGH' ? '#eb1414' : '#ffc107';
        
        popup.innerHTML = `
            <div style="text-align: center; margin-bottom: 15px;">
                <div style="font-size: 24px; color: ${riskColor}; margin-bottom: 10px;">
                    ⚠️ ${result.risk_level} RISK DETECTED
                </div>
                <div style="font-size: 18px; font-weight: bold;">
                    Risk Score: ${result.risk_score.toFixed(1)}/10
                </div>
            </div>
            
            <div style="margin-bottom: 15px;color: #000000;">
                <strong>Reasons for suspicion:</strong>
                <ul style="margin-top: 5px;">
                    ${result.reasons.map(reason => `<li>${reason}</li>`).join('')}
                </ul>
            </div>
            
            <div style="text-align: center;">
                <button id="phishing-close-btn" style="
                    background: #0000ff;
                    color: white;
                    border: none;
                    padding: 10px 20px;
                    border-radius: 4px;
                    cursor: pointer;
                    margin-right: 10px;
                ">Continue</button>
                <button id="phishing-leave-btn" style="
                    background: #6c757d;
                    color: white;
                    border: none;
                    padding: 10px 20px;
                    border-radius: 4px;
                    cursor: pointer;
                ">Leave Site</button>
            </div>
        `;
        
        overlay.appendChild(popup);
        document.body.appendChild(overlay);
        
        // Event listeners
        document.getElementById('phishing-close-btn').addEventListener('click', () => {
            overlay.remove();
        });
        
        document.getElementById('phishing-leave-btn').addEventListener('click', () => {
            if (document.referrer) {
        window.history.back(); // Goes to the previous safe page
    } else {
        window.location.href = "https://www.google.com"; // Fallback
    }
        });
    }
}

// Initialize feature extractor when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        const extractor = new FeatureExtractor();
        extractor.initialize();
    });
} else {
    const extractor = new FeatureExtractor();
    extractor.initialize();
}