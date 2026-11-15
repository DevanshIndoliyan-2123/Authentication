
package com.Devansh.Authentication_System.service.mail;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mail.MailException;
import org.springframework.mail.MailParseException;
import org.springframework.mail.MailPreparationException;
import org.springframework.mail.MailSendException;
import org.springframework.mail.MailSender;
import org.springframework.mail.SimpleMailMessage;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class FailoverMailSender implements MailSender {

    private static final Logger log =
            LoggerFactory.getLogger(FailoverMailSender.class);

    private final List<MailProvider> providers;

    public FailoverMailSender(List<MailProvider> providers) {

        if (providers == null || providers.isEmpty()) {
            throw new IllegalArgumentException(
                    "At least one mail provider is required"
            );
        }

        this.providers = List.copyOf(providers);
    }

    public List<String> providerNames() {
        return providers.stream()
                .map(MailProvider::name)
                .toList();
    }

    @Override
    public void send(SimpleMailMessage message) throws MailException {

        Map<String, MailException> failures =
                new LinkedHashMap<>();

        MailException lastFailure = null;

        for (MailProvider provider : providers) {

            // Create a copy for the current provider.
            SimpleMailMessage copy =
                    new SimpleMailMessage(message);

            copy.setFrom(provider.from());

            try {

                // Attempt email delivery.
                provider.sender().send(copy);

            } catch (MailParseException |
                     MailPreparationException ex) {

                // Invalid message cannot be fixed by another provider.
                throw ex;

            } catch (MailException ex) {

                failures.put(provider.name(), ex);
                lastFailure = ex;

                log.warn(
                        "Mail provider '{}' failed: {}",
                        provider.name(),
                        rootMessage(ex)
                );

                // Continue to the next provider.
                continue;
            }

            if (failures.isEmpty()) {

                log.debug(
                        "Email sent via '{}'",
                        provider.name()
                );

            } else {

                log.warn(
                        "Email sent via fallback provider '{}' after failure on {}",
                        provider.name(),
                        failures.keySet()
                );
            }

            // Stop after the first successful provider.
            return;
        }

        // All configured providers failed.
        MailSendException exhausted =
                new MailSendException(
                        "Email could not be delivered by any configured provider "
                                + failures.keySet(),
                        lastFailure
                );

        for (MailException failure : failures.values()) {

            if (failure != lastFailure) {
                exhausted.addSuppressed(failure);
            }
        }

        throw exhausted;
    }

    @Override
    public void send(SimpleMailMessage... messages)
            throws MailException {

        Map<Object, Exception> failedMessages =
                new LinkedHashMap<>();

        for (SimpleMailMessage message : messages) {

            try {

                send(message);

            } catch (MailException ex) {

                failedMessages.put(message, ex);
            }
        }

        if (!failedMessages.isEmpty()) {
            throw new MailSendException(failedMessages);
        }
    }

    private static String rootMessage(Throwable throwable) {

        Throwable root = throwable;

        while (root.getCause() != null
                && root.getCause() != root) {

            root = root.getCause();
        }

        return root.getClass().getSimpleName()
                + ": "
                + root.getMessage();
    }
}


