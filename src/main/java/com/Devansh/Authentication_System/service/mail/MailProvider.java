
package com.Devansh.Authentication_System.service.mail;

import org.springframework.mail.MailSender;

/**
 * One way of delivering email.
 *
 * @param name   provider name, e.g. gmail or brevo
 * @param sender SMTP sender
 * @param from   sender email address
 */
public record MailProvider(
        String name,
        MailSender sender,
        String from
) {
}
