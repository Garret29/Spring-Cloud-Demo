package pl.piotrowski.bar.config;

import org.springframework.boot.autoconfigure.jms.artemis.ArtemisConfigurationCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ArtemisConfig {

    @Bean
    ArtemisConfigurationCustomizer artemisCustomizer() {
        return configuration -> {
            try {
                configuration.addAcceptorConfiguration("netty", "tcp://0.0.0.0:61616");
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };
    }
}