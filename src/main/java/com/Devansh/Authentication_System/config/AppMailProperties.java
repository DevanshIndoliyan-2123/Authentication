
package com.Devansh.Authentication_System.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Outgoing email settings, bound from app.mail.*.
 *
 * Gmail is the primary provider.
 * Brevo is the fallback provider.
 */
@ConfigurationProperties(prefix = "app.mail")
public class AppMailProperties {

    private int connectionTimeoutMs = 5000;
    private int readTimeoutMs = 10000;
    private int writeTimeoutMs = 10000;

    private Provider gmail = new Provider();
    private Provider brevo = new Provider();

    public int getConnectionTimeoutMs() {
        return connectionTimeoutMs;
    }

    public void setConnectionTimeoutMs(int connectionTimeoutMs) {
        this.connectionTimeoutMs = connectionTimeoutMs;
    }

    public int getReadTimeoutMs() {
        return readTimeoutMs;
    }

    public void setReadTimeoutMs(int readTimeoutMs) {
        this.readTimeoutMs = readTimeoutMs;
    }

    public int getWriteTimeoutMs() {
        return writeTimeoutMs;
    }

    public void setWriteTimeoutMs(int writeTimeoutMs) {
        this.writeTimeoutMs = writeTimeoutMs;
    }

    public Provider getGmail() {
        return gmail;
    }

    public void setGmail(Provider gmail) {
        this.gmail = gmail;
    }

    public Provider getBrevo() {
        return brevo;
    }

    public void setBrevo(Provider brevo) {
        this.brevo = brevo;
    }

    public static class Provider {

        private String host;
        private int port = 587;
        private String username;
        private String password;
        private String from;

        public String getHost() {
            return host;
        }

        public void setHost(String host) {
            this.host = host;
        }

        public int getPort() {
            return port;
        }

        public void setPort(int port) {
            this.port = port;
        }

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public String getFrom() {
            return from;
        }

        public void setFrom(String from) {
            this.from = from;
        }
    }
}
