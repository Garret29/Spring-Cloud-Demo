package pl.piotrowski.foo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import pl.piotrowski.foo.service.BrokerBarServiceClient;
import pl.piotrowski.foo.service.FeignBarServiceClient;

@RestController
@RequestMapping("/api/foo")
public class FooController {
    BrokerBarServiceClient barServiceClient;

    @Autowired
    public FooController(BrokerBarServiceClient barServiceClient) {
        this.barServiceClient = barServiceClient;
    }

    @GetMapping
    public String getFoo() {
        return "foo" + barServiceClient.getBar();
    }
}
