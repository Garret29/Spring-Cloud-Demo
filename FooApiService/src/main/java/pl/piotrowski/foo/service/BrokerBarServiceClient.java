package pl.piotrowski.foo.service;

import jakarta.jms.JMSException;
import jakarta.jms.Message;
import jakarta.jms.TextMessage;
import org.springframework.jms.core.JmsTemplate;
import org.springframework.stereotype.Component;

@Component
public class BrokerBarServiceClient implements BarService {
    private final JmsTemplate jmsTemplate;

    public BrokerBarServiceClient(JmsTemplate jmsTemplate) {
        this.jmsTemplate = jmsTemplate;
    }

    @Override
    public String getBar() {
        Message replyMessage = jmsTemplate.sendAndReceive(
                "bar.queue",
                session -> session.createTextMessage("getBar")
        );

        try {
            return (replyMessage instanceof TextMessage tm) ? tm.getText() : null;
        } catch (JMSException e) {
            throw new RuntimeException(e);
        }
    }
}
