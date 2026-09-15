package pl.piotrowski.foo.service;

import jakarta.jms.JMSException;
import jakarta.jms.Message;
import jakarta.jms.TextMessage;
import org.springframework.jms.core.JmsTemplate;

public class BrokerBarService implements BarService {
    private final JmsTemplate jmsTemplate;

    public BrokerBarService(JmsTemplate jmsTemplate) {
        this.jmsTemplate = jmsTemplate;
    }

    @Override
    public String getBar() {
        Message replyMessage = jmsTemplate.sendAndReceive(
                "bar.queue",
                session -> session.createTextMessage("getBar")
        );

        if (replyMessage == null) {
            throw new RuntimeException("bar failed");
        }

        try {
            return (replyMessage instanceof TextMessage tm) ? tm.getText() : null;
        } catch (JMSException e) {
            throw new RuntimeException(e);
        }
    }
}
