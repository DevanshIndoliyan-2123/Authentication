package com.Devansh.Authentication_System.service;

import com.Devansh.Authentication_System.service.mail.FailoverMailSender;
import com.Devansh.Authentication_System.service.mail.MailProvider;
import org.junit.jupiter.api.Test;
import org.springframework.mail.MailException;
import org.springframework.mail.MailSendException;
import org.springframework.mail.MailSender;
import org.springframework.mail.SimpleMailMessage;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class FailoverMailSenderTest {

    private final MailSender gmail = mock(MailSender.class);
    private final MailSender brevo = mock(MailSender.class);

    private FailoverMailSender sender() {
        return new FailoverMailSender(List.of(
                new MailProvider("gmail", gmail, "gmail@example.test"),
                new MailProvider("brevo", brevo, "brevo@example.test")
        ));
    }

    private SimpleMailMessage message() {
        SimpleMailMessage m = new SimpleMailMessage();
        m.setTo("user@example.test");
        m.setSubject("Hi");
        m.setText("Body");
        return m;
    }

    @Test
    void usesPrimaryProviderWhenItWorks() {
        sender().send(message());

        verify(gmail).send(any(SimpleMailMessage.class));
        verifyNoInteractions(brevo);
    }

    @Test
    void fallsBackToBrevoWhenGmailFails() {
        doThrow(new MailSendException("gmail down"))
                .when(gmail).send(any(SimpleMailMessage.class));

        sender().send(message());

        verify(brevo).send(any(SimpleMailMessage.class));
    }

    @Test
    void setsTheFromAddressOfTheProviderThatSends() {
        doThrow(new MailSendException("gmail down"))
                .when(gmail).send(any(SimpleMailMessage.class));

        sender().send(message());

        var captor = org.mockito.ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(brevo).send(captor.capture());
        assertEquals("brevo@example.test", captor.getValue().getFrom());
    }

    @Test
    void throwsWhenEveryProviderFails() {
        doThrow(new MailSendException("gmail down"))
                .when(gmail).send(any(SimpleMailMessage.class));
        doThrow(new MailSendException("brevo down"))
                .when(brevo).send(any(SimpleMailMessage.class));

        MailException ex = assertThrows(
                MailException.class,
                () -> sender().send(message())
        );

        assertTrue(ex.getMessage().contains("any configured provider"));
    }

    @Test
    void requiresAtLeastOneProvider() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new FailoverMailSender(List.of())
        );
    }
}
