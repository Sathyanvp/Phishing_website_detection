package phishing_website.MainApp.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Data
public class AnalysisRequest {
    
	//URL features
	private Integer url_length;
    private Integer token_count;
    private Integer hyphenated_domain;
    private Integer uses_ip_address;
    private Integer uses_shortener;
    private Double char_entropy;
    private Double token_entropy;
    private Double ngram_entropy;
    //DOM features
    private Integer form_count;
    private Integer password_field_present;
    private Integer email_field_present;
    private Integer external_form_action;
    private Integer iframe_count;
    //Behavioral features
    private Integer redirect_indicator;
    private Integer possible_js_obfuscation;
    private Integer status_bar_customized;
    private Integer right_click_disabled;
    
    private String url;
 
        
        public void setUrl_length(Integer url_length) {
    		this.url_length = url_length;
    	}

    	public void setToken_count(Integer token_count) {
    		this.token_count = token_count;
    	}

    	public void setHyphenated_domain(Integer hyphenated_domain) {
    		this.hyphenated_domain = hyphenated_domain;
    	}

    	public void setUses_ip_address(Integer uses_ip_address) {
    		this.uses_ip_address = uses_ip_address;
    	}

    	public void setUses_shortener(Integer uses_shortener) {
    		this.uses_shortener = uses_shortener;
    	}

    	public void setChar_entropy(Double char_entropy) {
    		this.char_entropy = char_entropy;
    	}

    	public void setToken_entropy(Double token_entropy) {
    		this.token_entropy = token_entropy;
    	}

    	public void setNgram_entropy(Double ngram_entropy) {
    		this.ngram_entropy = ngram_entropy;
    	}

    	public void setForm_count(Integer form_count) {
    		this.form_count = form_count;
    	}

    	public void setPassword_field_present(Integer password_field_present) {
    		this.password_field_present = password_field_present;
    	}

    	public void setEmail_field_present(Integer email_field_present) {
    		this.email_field_present = email_field_present;
    	}

    	public void setExternal_form_action(Integer external_form_action) {
    		this.external_form_action = external_form_action;
    	}

    	public void setIframe_count(Integer iframe_count) {
    		this.iframe_count = iframe_count;
    	}

    	public void setRedirect_indicator(Integer redirect_indicator) {
    		this.redirect_indicator = redirect_indicator;
    	}

    	public void setPossible_js_obfuscation(Integer possible_js_obfuscation) {
    		this.possible_js_obfuscation = possible_js_obfuscation;
    	}

    	public void setStatus_bar_customized(Integer status_bar_customized) {
    		this.status_bar_customized = status_bar_customized;
    	}

    	public void setRight_click_disabled(Integer right_click_disabled) {
    		this.right_click_disabled = right_click_disabled;
    	}


    	
        public Integer getUrl_length() {
    		return url_length;
    	}

    	public Integer getToken_count() {
    		return token_count;
    	}

    	public Integer getHyphenated_domain() {
    		return hyphenated_domain;
    	}

    	public Integer getUses_ip_address() {
    		return uses_ip_address;
    	}

    	public Integer getUses_shortener() {
    		return uses_shortener;
    	}

    	public Double getChar_entropy() {
    		return char_entropy;
    	}

    	public Double getToken_entropy() {
    		return token_entropy;
    	}

    	public Double getNgram_entropy() {
    		return ngram_entropy;
    	}

    	public Integer getForm_count() {
    		return form_count;
    	}

    	public Integer getPassword_field_present() {
    		return password_field_present;
    	}

    	public Integer getEmail_field_present() {
    		return email_field_present;
    	}

    	public Integer getExternal_form_action() {
    		return external_form_action;
    	}

    	public Integer getIframe_count() {
    		return iframe_count;
    	}

    	public Integer getRedirect_indicator() {
    		return redirect_indicator;
    	}

    	public Integer getPossible_js_obfuscation() {
    		return possible_js_obfuscation;
    	}

    	public Integer getStatus_bar_customized() {
    		return status_bar_customized;
    	}

    	public Integer getRight_click_disabled() {
    		return right_click_disabled;
    	}

    	

    	public float[] featuretoVector() {
    		return new float[] {
    	            url_length != null ? url_length : 0,
    	            token_count != null ? token_count : 0,
    	            hyphenated_domain != null ? hyphenated_domain : 0,
    	            uses_ip_address != null ? uses_ip_address : 0,
    	            uses_shortener != null ? uses_shortener : 0,
    	            char_entropy != null ? char_entropy.floatValue() : 0,
    	            token_entropy != null ? token_entropy.floatValue() : 0,
    	            ngram_entropy != null ? ngram_entropy.floatValue() : 0,
    	            form_count != null ? form_count : 0,
    	            password_field_present != null ? password_field_present : 0,
    	            email_field_present != null ? email_field_present : 0,
    	            external_form_action != null ? external_form_action : 0,
    	            iframe_count != null ? iframe_count : 0,
    	            redirect_indicator != null ? redirect_indicator : 0,
    	            possible_js_obfuscation != null ? possible_js_obfuscation : 0,
    	            status_bar_customized != null ? status_bar_customized : 0,
    	            right_click_disabled != null ? right_click_disabled : 0
    	        };
    	}
    
    public void setUrl(String url) {
		this.url = url;
	}

	
    
    public String getUrl() {
		return url;
	}


	
}
