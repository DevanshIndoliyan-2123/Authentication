
package com.Devansh.Authentication_System.config;

import com.Devansh.Authentication_System.service.mail.FailoverMailSender;
import com.Devansh.Authentication_System.service.mail.MailProvider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSenderImpl;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

@Configuration
@EnableConfigurationProperties(AppMailProperties.class)
public class EmailConfig {

    private static final Logger log =
            LoggerFactory.getLogger(EmailConfig.class);

    @Bean
    public FailoverMailSender mailSender(
            AppMailProperties props
    ) {

        List<MailProvider> providers = buildProviders(props);

        if (providers.isEmpty()) {
            throw new IllegalStateException(
                    "No mail provider configured. Configure Gmail or Brevo SMTP credentials."
            );
        }

        FailoverMailSender sender =
                new FailoverMailSender(providers);

        log.info(
                "Mail providers registered in order: {}",
                sender.providerNames()
        );

        return sender;
    }

    private List<MailProvider> buildProviders(
            AppMailProperties props
    ) {

        List<MailProvider> providers = new ArrayList<>();

        // Gmail: Primary provider
        addIfConfigured(
                providers,
                "gmail",
                props.getGmail(),
                props,
                true
        );

        // Brevo: Fallback provider
        addIfConfigured(
                providers,
                "brevo",
                props.getBrevo(),
                props,
                false
        );

        return providers;
    }

    private void addIfConfigured(
            List<MailProvider> providers,
            String name,
            AppMailProperties.Provider settings,
            AppMailProperties props,
            boolean fromDefaultsToUsername
    ) {

        String host = clean(settings.getHost());
        String username = clean(settings.getUsername());

        // Gmail App Password can be entered with spaces.
        String password = stripWhitespace(settings.getPassword());

        String from = clean(settings.getFrom());

        if (from.isEmpty() && fromDefaultsToUsername) {
            from = username;
        }

        if (host.isEmpty()
                || username.isEmpty()
                || password.isEmpty()
                || from.isEmpty()) {

            log.warn(
                    "Mail provider '{}' is not fully configured and will be skipped.",
                    name
            );

            return;
        }

        providers.add(
                new MailProvider(
                        name,
                        createMailSender(
                                settings,
                                host,
                                username,
                                password,
                                props
                        ),
                        from
                )
        );
    }

    private JavaMailSenderImpl createMailSender(
            AppMailProperties.Provider settings,
            String host,
            String username,
            String password,
            AppMailProperties props
    ) {

        JavaMailSenderImpl sender = new JavaMailSenderImpl();

        sender.setHost(host);
        sender.setPort(settings.getPort());
        sender.setUsername(username);
        sender.setPassword(password);

        sender.setDefaultEncoding(
                StandardCharsets.UTF_8.name()
        );

        Properties mailProperties =
                sender.getJavaMailProperties();

        mailProperties.put("mail.transport.protocol", "smtp");
        mailProperties.put("mail.smtp.auth", "true");

        // STARTTLS for SMTP port 587
        mailProperties.put("mail.smtp.starttls.enable", "true");
        mailProperties.put("mail.smtp.starttls.required", "true");

        // SMTP server identity verification
        mailProperties.put(
                "mail.smtp.ssl.checkserveridentity",
                "true"
        );

        // Connection timeout
        mailProperties.put(
                "mail.smtp.connectiontimeout",
                String.valueOf(props.getConnectionTimeoutMs())
        );

        // Read timeout
        mailProperties.put(
                "mail.smtp.timeout",
                String.valueOf(props.getReadTimeoutMs())
        );

        // Write timeout
        mailProperties.put(
                "mail.smtp.writetimeout",
                String.valueOf(props.getWriteTimeoutMs())
        );

        return sender;
    }

    private String clean(String value) {
        return value == null ? "" : value.trim();
    }

    private String stripWhitespace(String value) {
        return value == null
                ? ""
                : value.replaceAll("\\s+", "");
    }
}
