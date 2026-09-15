package pl.piotrowski.foo.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import pl.piotrowski.foo.service.BarService;
import pl.piotrowski.foo.service.FeignBarService;
import pl.piotrowski.foo.service.ResilientBarService;

@Configuration
@ConditionalOnProperty(name = "bar.transport", havingValue = "feign", matchIfMissing = true)
@EnableFeignClients(clients = FeignBarService.class)
public class FeignBarConfiguration {
    @Bean()
    @Primary()
    BarService barService(FeignBarService feignBarService) {
        return new ResilientBarService(feignBarService);
    }
}
