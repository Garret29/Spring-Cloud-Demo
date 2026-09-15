package pl.piotrowski.foo.service;

import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.retry.annotation.Retry;

public class ResilientBarService implements BarService {
    private static final String FALLBACK_BAR = "fallbackBar";
    BarService barService;

    public ResilientBarService(BarService barService) {
        this.barService = barService;
    }

    @Retry(name = "bar")
    @CircuitBreaker(name = "bar", fallbackMethod = "getBarFallback")
    @Override
    public String getBar() {
        return barService.getBar();
    }

    public String getBarFallback(Throwable error) {
        return FALLBACK_BAR;
    }
}
