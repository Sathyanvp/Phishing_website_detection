//package phishing_website.MainApp.service;
//
//
//import ai.onnxruntime.OnnxTensor;
//import ai.onnxruntime.OrtEnvironment;
//import ai.onnxruntime.OrtSession;
//import jakarta.annotation.PostConstruct;
//import jakarta.annotation.PreDestroy;
//import ai.onnxruntime.OrtException;
//import lombok.extern.slf4j.Slf4j;
//import phishing_website.MainApp.entity.AnalysisRequest;
//
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.stereotype.Service;
//
//
//import java.util.Collections;
//import java.util.Map;
//
///**
// * ONNXModelService - ONNX Runtime Model Inference Engine
// * 
// * Loads and manages the phishing detection ML model trained with XGBoost
// * and exported to ONNX format. Performs inference on extracted features.
// */
//@Slf4j
//@Service
//public class ONNXModelService {
//    
//    @Value("${model.path:models/phishing_detector.onnx}")
//    private String modelPath;
//    
//    private OrtEnvironment environment;
//    private OrtSession session;
//    private static final String INPUT_NAME = "float_input";
//    private static final String OUTPUT_NAME = "probabilities";
//    
//    /**
//     * Initialize ONNX Runtime environment and load the model
//     */
//    @PostConstruct
//    public void initialize() {
//        try {
//            log.info("Initializing ONNX Runtime environment...");
//            this.environment = OrtEnvironment.getEnvironment();
//            
//            log.info("Loading phishing detection model from: {}", modelPath);
//            this.session = environment.createSession(modelPath);
//            
//            log.info("Model loaded successfully. Input: {}, Output: {}", INPUT_NAME, OUTPUT_NAME);
//        } catch (OrtException e) {
//            log.error("Failed to initialize ONNX model", e);
//            throw new RuntimeException("Failed to load ONNX model: " + e.getMessage(), e);
//        }
//    }
//    
//    /**
//     * Perform inference on extracted features
//     * 
//     * @param request Analysis request containing features
//     * @return Probability of phishing (0.0 - 1.0)
//     */
//    public double predict(AnalysisRequest request) {
//        try {
//            // Convert request to feature vector
//            float[] features = request.featuretoVector();
//            
//            // Reshape to [1, 17] for batch processing (1 sample, 17 features)
//            long[] shape = new long[]{1, features.length};
//            
//            // Create ONNX tensor
//            OnnxTensor tensor = OnnxTensor.createTensor(environment, features);
//            
//            // Run inference
//            Map<String, OnnxTensor> inputs = Collections.singletonMap(INPUT_NAME, tensor);
//            var results = session.run(inputs);
//            
//            // Extract output
//            OnnxTensor output = (OnnxTensor) results.get(OUTPUT_NAME);
//            float[][] probabilities = (float[][]) output.getValue();
//            
//            // Return probability of phishing class (index 1)
//            double phishingProbability = probabilities[0][1];
//            
//            log.debug("Features: url_len={}, tokens={}, entropy={}, forms={}. Prediction: {}",
//                    request.getUrl_length(),
//                    request.getToken_count(),
//                    request.getChar_entropy(),
//                    request.getForm_count(),
//                    phishingProbability);
//            
//            tensor.close();
//            results.close();
//            
//            return Math.min(Math.max(phishingProbability, 0.0), 1.0); // Ensure [0, 1]
//            
//        } catch (OrtException e) {
//            log.error("Model inference failed", e);
//            throw new RuntimeException("Model inference failed: " + e.getMessage(), e);
//        } catch (Exception e) {
//            log.error("Unexpected error during prediction", e);
//            throw new RuntimeException("Prediction error: " + e.getMessage(), e);
//        }
//    }
//    
//    /**
//     * Cleanup resources
//     */
//    @PreDestroy
//    public void cleanup() {
//        try {
//            if (session != null) {
//                session.close();
//                log.info("ONNX session closed");
//            }
//        } catch (OrtException e) {
//            log.warn("Error closing ONNX session", e);
//        }
//    }
//}
