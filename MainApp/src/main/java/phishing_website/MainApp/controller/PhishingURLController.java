package phishing_website.MainApp.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.slf4j.Slf4j;

import phishing_website.MainApp.entity.AnalysisRequest;
import phishing_website.MainApp.entity.AnalysisResponse;

import phishing_website.MainApp.service.AnalyzerService;

@RestController
@Slf4j
@RequestMapping("/api")
//@CrossOrigin(
//	    originPatterns = {
//	        "chrome-extension://*", // Matches any extension ID
//	        "http://localhost:[*]"  // Matches any port on localhost
//	    }, 
//	    allowedHeaders = "*",
//	    methods = {RequestMethod.POST, RequestMethod.GET, RequestMethod.OPTIONS},
//	    allowCredentials = "true"
//	)
public class PhishingURLController {
	


	static final RequestMethod[] REQUEST_METHODS = { };
	private AnalyzerService service;
	public PhishingURLController(AnalyzerService service) {
		this.service = service;
	}
	
	@PostMapping("/analyze")
	public ResponseEntity<AnalysisResponse> analyzeUrl(@RequestBody AnalysisRequest request) {
		log.info("request reached");
		try {
			if(request.getUrl() == null || request.getUrl().isEmpty()) {
				log.info("Bad request: Request is empty");
				return ResponseEntity.badRequest().build();
			}
			AnalysisResponse response = service.analyzeUrl(request);
			
			return ResponseEntity.ok(response);
		}
		catch(Exception e) {
			log.info(e + "internal server error");
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
		}
		
		
	}

}
