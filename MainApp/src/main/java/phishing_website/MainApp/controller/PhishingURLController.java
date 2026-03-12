package phishing_website.MainApp.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import phishing_website.MainApp.entity.AnalysisRequest;
import phishing_website.MainApp.entity.Response;
import phishing_website.MainApp.service.AnalyzerService;

@RestController

@RequestMapping("/api")
public class PhishingURLController {
	


	private AnalyzerService service;
	public PhishingURLController(AnalyzerService service) {
		this.service = service;
	}
	@PostMapping("/analyze")
	public ResponseEntity<Response> analyzeUrl(@RequestBody AnalysisRequest request) {
		try {
			if(request.getUrl() == null || request.getUrl().isEmpty()) {
				return ResponseEntity.badRequest().build();
			}
			Response response = service.analyzeUrl(request);
			System.out.println("sent");
			return ResponseEntity.ok(response);
		}
		catch(Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
		}
		
		
	}

}
