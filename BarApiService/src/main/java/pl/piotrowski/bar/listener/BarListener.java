package pl.piotrowski.bar.listener;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jms.annotation.JmsListener;
import org.springframework.stereotype.Component;
import pl.piotrowski.bar.service.BarService;

@Component
public class BarListener {

    @Autowired
    BarService barService;

    @JmsListener(destination = "bar.queue")
    public String bar(String ignored) {
        return barService.getBar();
    }
}