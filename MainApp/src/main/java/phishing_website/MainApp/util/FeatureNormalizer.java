package phishing_website.MainApp.util;


import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import phishing_website.MainApp.entity.AnalysisRequest;

/**
 * FeatureNormalizer - Feature scaling and normalization
 * 
 * Normalizes extracted features to the ranges expected by the ML model.
 * Uses min-max scaling for numerical features based on training data statistics.
 */
@Slf4j
@Component
public class FeatureNormalizer {
    
    // Feature statistics from training data (adjust based on actual training dataset)
    private static final float URL_LENGTH_MAX = 200;
    private static final float TOKEN_COUNT_MAX = 50;
    private static final float CHAR_ENTROPY_MAX = 6.0f;
    private static final float TOKEN_ENTROPY_MAX = 5.0f;
    private static final float NGRAM_ENTROPY_MAX = 6.0f;
    private static final float FORM_COUNT_MAX = 10;
    private static final float IFRAME_COUNT_MAX = 10;
    
    public static float getUrlLengthMax() {
		return URL_LENGTH_MAX;
	}

	public static float getTokenCountMax() {
		return TOKEN_COUNT_MAX;
	}

	public static float getCharEntropyMax() {
		return CHAR_ENTROPY_MAX;
	}

	public static float getTokenEntropyMax() {
		return TOKEN_ENTROPY_MAX;
	}

	public static float getNgramEntropyMax() {
		return NGRAM_ENTROPY_MAX;
	}

	public static float getFormCountMax() {
		return FORM_COUNT_MAX;
	}

	public static float getIframeCountMax() {
		return IFRAME_COUNT_MAX;
	}

	
    
    /**
     * Normalize all features in the request
     * 
     * @param request Raw feature request
     * @return Request with normalized features
     */
    public AnalysisRequest normalize(AnalysisRequest request) {
        AnalysisRequest normalized = new AnalysisRequest();
        
        // Copy metadata
        normalized.setUrl(request.getUrl());
        
        // Normalize URL features (these are already binary or counts, minimal scaling needed)
        normalized.setUrl_length(normalizeUrlLength(request.getUrl_length()));
        normalized.setToken_count(normalizeTokenCount(request.getToken_count()));
        normalized.setHyphenated_domain(request.getHyphenated_domain());
        normalized.setUses_ip_address(request.getUses_ip_address());
        normalized.setUses_shortener(request.getUses_shortener());
        
        // Normalize entropy features (continuous, need scaling)
        normalized.setChar_entropy(normalizeCharEntropy(request.getChar_entropy()));
        normalized.setToken_entropy(normalizeTokenEntropy(request.getToken_entropy()));
        normalized.setNgram_entropy(normalizeNgramEntropy(request.getNgram_entropy()));
        
        // Normalize DOM features
        normalized.setForm_count(normalizeFormCount(request.getForm_count()));
        normalized.setPassword_field_present(request.getPassword_field_present());
        normalized.setEmail_field_present(request.getEmail_field_present());
        normalized.setExternal_form_action(request.getExternal_form_action());
        normalized.setIframe_count(normalizeIframeCount(request.getIframe_count()));
        normalized.setRedirect_indicator(request.getRedirect_indicator());
        
        // Normalize behavioral features (binary)
        normalized.setPossible_js_obfuscation(request.getPossible_js_obfuscation());
        normalized.setStatus_bar_customized(request.getStatus_bar_customized());
        normalized.setRight_click_disabled(request.getRight_click_disabled());
        
//        log.debug("Features normalized successfully for URL: {}", request.getUrl());
        return normalized;
    }
    
    /**
     * Normalize URL length with min-max scaling
     */
    private Integer normalizeUrlLength(Integer value) {
        if (value == null || value <= 0) return 0;
        return Math.min(value, (int)URL_LENGTH_MAX);
    }
    
    /**
     * Normalize token count
     */
    private Integer normalizeTokenCount(Integer value) {
        if (value == null || value <= 0) return 0;
        return Math.min(value, (int)TOKEN_COUNT_MAX);
    }
    
    /**
     * Normalize character entropy with min-max scaling
     */
    private Double normalizeCharEntropy(Double value) {
        if (value == null || value < 0) return 0.0;
        // Clip to max entropy value
        return Math.min(value, CHAR_ENTROPY_MAX);
    }
    
    /**
     * Normalize token entropy
     */
    private Double normalizeTokenEntropy(Double value) {
        if (value == null || value < 0) return 0.0;
        return Math.min(value, TOKEN_ENTROPY_MAX);
    }
    
    /**
     * Normalize n-gram entropy
     */
    private Double normalizeNgramEntropy(Double value) {
        if (value == null || value < 0) return 0.0;
        return Math.min(value, NGRAM_ENTROPY_MAX);
    }
    
    /**
     * Normalize form count
     */
    private Integer normalizeFormCount(Integer value) {
        if (value == null || value < 0) return 0;
        // More than 10 forms is suspicious, cap it
        return Math.min(value, (int)FORM_COUNT_MAX);
    }
    
    /**
     * Normalize iframe count
     */
    private Integer normalizeIframeCount(Integer value) {
        if (value == null || value < 0) return 0;
        return Math.min(value, (int)IFRAME_COUNT_MAX);
    }
}
