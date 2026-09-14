package pl.piotrowski.bar.listener;

import org.springframework.jms.annotation.JmsListener;
import org.springframework.stereotype.Component;

@Component
public class BarListener {

    @JmsListener(destination = "bar.queue")
    public String bar(String ignored) {
        return "bar";
    }
}