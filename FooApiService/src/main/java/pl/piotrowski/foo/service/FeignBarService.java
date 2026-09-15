package pl.piotrowski.foo.service;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;

@FeignClient(name = "bar-service", primary = false)
public interface FeignBarService extends BarService {
    @Override
    @GetMapping("/api/bar")
    String getBar();
}
