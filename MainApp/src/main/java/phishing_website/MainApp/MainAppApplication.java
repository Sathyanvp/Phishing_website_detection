package phishing_website.MainApp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import lombok.extern.slf4j.Slf4j;


@Slf4j
@SpringBootApplication
public class MainAppApplication {

	public static void main(String[] args) {
//		log.info("g");
		SpringApplication.run(MainAppApplication.class, args);
//		log.info("Application succesfully started");
//		log.info("Starting Phishing Detection Backend Service...");
	}
	@Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/api/**")
                        .allowedOriginPatterns("chrome-extension://*")
                        .allowedOriginPatterns("http://localhost*")
                        .allowedMethods("POST", "GET", "OPTIONS")
                        .allowedHeaders("*")
                        .allowCredentials(true)
                        .maxAge(3600);
            }
        };
	}

}
