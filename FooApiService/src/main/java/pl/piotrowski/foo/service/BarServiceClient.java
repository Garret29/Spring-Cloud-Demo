package pl.piotrowski.foo.service;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;

@FeignClient(name = "bar-service")
public interface BarServiceClient {
    @GetMapping("/api/bar")
    String getBar();
}
