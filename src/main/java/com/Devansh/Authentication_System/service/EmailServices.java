
package com.Devansh.Authentication_System.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;

import org.springframework.mail.MailSender;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.stereotype.Service;

/**
 * Builds application emails.
 *
 * Email delivery is handled by FailoverMailSender:
 * Gmail first, Brevo fallback.
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class EmailServices {

    private final MailSender mailSender;

    /**
     * Sends a welcome email after successful registration.
     */
    public void sendWelcomeMail(
            String toEmail,
            String name
    ) {

        send(
                toEmail,
                "Welcome to our Application",
                "Dear " + name
                        + ",\n\nWelcome to our application! "
                        + "We are excited to have you on board."
                        + "\n\nBest regards,\n Devansh Indoliyan"
        );
    }

    /**
     * Sends an OTP for password reset.
     */
    public void sendResetPasswordMail(
            String toEmail,
            String otp
    ) {

        send(
                toEmail,
                "Password Reset Request",
                "Dear User,\n\n"
                        + "We received a request to reset your password. "
                        + "Please use the following OTP to reset your password:\n\n"
                        + otp
                        + "\n\nIf you did not request a password reset, "
                        + "please ignore this email."
                        + "\n\nBest regards,\nThe Team"
        );
    }

    /**
     * Sends the password reset OTP in the background. Failures are logged
     * and never reach the caller, so the reset endpoint answers the same way
     * (and as fast) whether or not the account exists.
     */
    @Async
    public void sendResetPasswordMailAsync(
            String toEmail,
            String otp
    ) {

        try {
            sendResetPasswordMail(toEmail, otp);
        } catch (Exception ex) {
            log.error("Could not send password reset email: {}",
                    ex.getMessage());
        }
    }

    /**
     * Sends an account verification OTP.
     */
    public void sendOtpEmail(
            String toEmail,
            String otp
    ) {

        send(
                toEmail,
                "Your OTP Code",
                "Dear User,\n\n"
                        + "Your OTP code is: " + otp
                        + "\n\nPlease use this code to complete "
                        + "your verification process."
                        + "\n\nBest regards,\nThe Team"
        );
    }

    /**
     * Common method for sending all application emails.
     * Gmail/Brevo selection is handled by FailoverMailSender.
     */
    private void send(
            String toEmail,
            String subject,
            String text
    ) {

        SimpleMailMessage message = new SimpleMailMessage();

        message.setTo(toEmail);
        message.setSubject(subject);
        message.setText(text);

        mailSender.send(message);
    }
}
