package pl.piotrowski.bar.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/bar")
public class BarController {

    @GetMapping
    public String getBar() {
        return "bar";
    }
}
