package pl.piotrowski.bar.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import pl.piotrowski.bar.service.BarService;

@RestController
@RequestMapping("/api/bar")
public class BarController {

    @Autowired
    BarService barService;

    @GetMapping
    public String getBar() {
        return barService.getBar();
    }
}
