package pl.piotrowski.foo.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.jms.core.JmsTemplate;
import pl.piotrowski.foo.service.BarService;
import pl.piotrowski.foo.service.BrokerBarService;
import pl.piotrowski.foo.service.ResilientBarService;

@Configuration
@ConditionalOnProperty(name = "bar.transport", havingValue = "jms")
public class BrokerBarConfiguration {
    @Bean
    @Primary()
    public BarService barService(JmsTemplate jmsTemplate) {
        return new ResilientBarService(new BrokerBarService(jmsTemplate));
    }
}
