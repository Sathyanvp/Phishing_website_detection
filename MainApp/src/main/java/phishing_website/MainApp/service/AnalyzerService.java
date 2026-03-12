package phishing_website.MainApp.service;


import java.util.List;

import org.springframework.stereotype.Service;

import phishing_website.MainApp.entity.AnalysisRequest;
import phishing_website.MainApp.entity.Response;
import phishing_website.MainApp.util.FeatureNormalizer;


@Service
public class AnalyzerService {
	
	    private AIModelService model;
	    private FeatureNormalizer normalizer;
	    
	   
	    private ExplanationService explanationService;

	public Response analyzeUrl(AnalysisRequest request) {
		try {
			AnalysisRequest normalizedrequest = normalizer.normalize(request);
			float probability = model.predict(normalizedrequest);
			float risk_score = convertProbabilityToRiskScore(probability);
			String risk_level = determineRiskLevel(risk_score);
			List<String> explaination = explanationService.generateExplanations(normalizedrequest, risk_score);
			Response response = new Response(risk_score,
                    risk_level,
                    explaination);
			response.setUrl(request.getUrl());
            response.setTimestamp(System.currentTimeMillis());
			return  response;
		}
		 catch (Exception e) {
//	            log.error("Analysis failed for URL: {}", request.getUrl(), e);
	            throw new RuntimeException("Analysis failed: " + e.getMessage(), e);
	        }
	}

	private String determineRiskLevel(float risk_score) {
		 if (risk_score < 4.0) {
	            return "LOW";
	        } else if (risk_score < 7.0) {
	            return "MEDIUM";
	        } else {
	            return "HIGH";
	        }
		
	}

	private float convertProbabilityToRiskScore(float probability) {
		
		return probability * 10.0f;
	}

}
