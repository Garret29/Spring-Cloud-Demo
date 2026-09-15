package pl.piotrowski.bar.service;

import org.springframework.stereotype.Service;

import java.util.Random;

@Service
public class BarService {

    private final Random random = new Random();

    public String getBar() {
        boolean value = random.nextBoolean();
        if (value) {
            return "bar";
        } else {
            throw new RuntimeException("bar failed");
        }
    }
}
