package com.Devansh.Authentication_System.integration;

import com.Devansh.Authentication_System.security.RateLimiter;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mail.MailSender;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end API tests on an in-memory H2 database. Outgoing email is
 * replaced by a mock, and the OTP is read from the captured message.
 */
@SpringBootTest
@ActiveProfiles("test")
class AuthFlowIntegrationTest {

    private static final String PASSWORD = "Password@123";
    private static final ObjectMapper JSON = new ObjectMapper();

    @Autowired
    private WebApplicationContext context;

    @Autowired
    private RateLimiter rateLimiter;

    @MockitoBean
    private MailSender mailSender;

    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.webAppContextSetup(context)
                .apply(springSecurity())
                .build();
        rateLimiter.reset();
        reset(mailSender);
    }

    // ---------- helpers ----------

    private static String email(String name) {
        return name + "-" + System.nanoTime() + "@example.test";
    }

    private static String body(String... pairs) throws Exception {
        var map = new java.util.LinkedHashMap<String, String>();
        for (int i = 0; i < pairs.length; i += 2) {
            map.put(pairs[i], pairs[i + 1]);
        }
        return JSON.writeValueAsString(map);
    }

    private void register(String email) throws Exception {
        mvc.perform(post("/api/v1/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("name", "Devansh",
                                "email", email, "password", PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.isAccountVerified").value(false));
    }

    private String login(String email) throws Exception {
        MvcResult result = mvc.perform(post("/api/v1/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("email", email, "password", PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andReturn();

        JsonNode node = JSON.readTree(result.getResponse().getContentAsString());
        return node.get("token").asText();
    }

    /** Waits for the most recent email and returns the 6-digit code in it. */
    private String lastOtp() {
        ArgumentCaptor<SimpleMailMessage> captor =
                ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender, timeout(3000).atLeastOnce()).send(captor.capture());

        String text = captor.getValue().getText();
        Matcher matcher = Pattern.compile("\\b\\d{6}\\b").matcher(text);
        assertTrue(matcher.find(), "No OTP found in: " + text);
        return matcher.group();
    }

    // ---------- security rules ----------

    @Test
    void healthIsPublic() throws Exception {
        mvc.perform(get("/api/v1/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"));
    }

    @Test
    void protectedEndpointsReturn401WithoutAToken() throws Exception {
        mvc.perform(get("/api/v1/profile")).andExpect(status().isUnauthorized());
        mvc.perform(post("/api/v1/send-otp")).andExpect(status().isUnauthorized());
        mvc.perform(post("/api/v1/verify-otp")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"otp\":\"123456\"}"))
                .andExpect(status().isUnauthorized());
        mvc.perform(post("/api/v1/logout")
                        .header("Authorization", "Bearer abc"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void loginUrlWithATrailingDotIsNotThePublicLoginEndpoint() throws Exception {
        mvc.perform(post("/api/v1/login.")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("email", "a@b.co", "password", PASSWORD)))
                .andExpect(status().isUnauthorized());
    }

    // ---------- registration ----------

    @Test
    void registrationSendsExactlyOneEmailAndRejectsDuplicates() throws Exception {
        String email = email("one-mail");

        register(email);

        verify(mailSender, times(1)).send(any(SimpleMailMessage.class));

        mvc.perform(post("/api/v1/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("name", "Devansh",
                                "email", email, "password", PASSWORD)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value(true));
    }

    @Test
    void registrationValidatesTheBody() throws Exception {
        mvc.perform(post("/api/v1/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("name", "Devansh",
                                "email", email("short"), "password", "short")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(true));
    }

    @Test
    void failedOtpEmailRollsTheSignupBack() throws Exception {
        String email = email("rollback");

        doThrow(new org.springframework.mail.MailSendException("down"))
                .when(mailSender).send(any(SimpleMailMessage.class));

        mvc.perform(post("/api/v1/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("name", "Devansh",
                                "email", email, "password", PASSWORD)))
                .andExpect(status().isInternalServerError());

        // The same email can register again once mail works
        reset(mailSender);
        register(email);
    }

    // ---------- verification flow ----------

    @Test
    void registerLoginVerifyAndLogout() throws Exception {
        String email = email("verify");

        register(email);
        String otp = lastOtp();
        String token = login(email);

        mvc.perform(post("/api/v1/verify-otp")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("otp", otp)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Email verified successfully"));

        mvc.perform(get("/api/v1/profile")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.isAccountVerified").value(true));

        mvc.perform(post("/api/v1/logout")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());

        // The revoked token is rejected
        mvc.perform(get("/api/v1/profile")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void wrongOtpIsABadRequest() throws Exception {
        String email = email("wrong-otp");

        register(email);
        String token = login(email);

        mvc.perform(post("/api/v1/verify-otp")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("otp", "000000")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Invalid or expired OTP"));
    }

    @Test
    void loginWithAWrongPasswordIs401() throws Exception {
        String email = email("badpass");

        register(email);

        mvc.perform(post("/api/v1/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("email", email, "password", "Wrong@1234")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid email or password"));
    }

    // ---------- password reset ----------

    @Test
    void resetPasswordFlow() throws Exception {
        String email = email("reset");

        register(email);
        reset(mailSender);

        mvc.perform(post("/api/v1/send-reset-otp").param("email", email))
                .andExpect(status().isOk());

        String otp = lastOtp();

        mvc.perform(post("/api/v1/reset-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("email", email,
                                "otp", otp, "newPassword", "NewPassword@456")))
                .andExpect(status().isOk());

        // Old password no longer works, new one does
        mvc.perform(post("/api/v1/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("email", email, "password", PASSWORD)))
                .andExpect(status().isUnauthorized());

        mvc.perform(post("/api/v1/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("email", email,
                                "password", "NewPassword@456")))
                .andExpect(status().isOk());
    }

    @Test
    void resetPasswordWithAWrongOtpIs400NotA500() throws Exception {
        String email = email("reset-bad");

        register(email);

        mvc.perform(post("/api/v1/send-reset-otp").param("email", email))
                .andExpect(status().isOk());

        mvc.perform(post("/api/v1/reset-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body("email", email,
                                "otp", "000000", "newPassword", "NewPassword@456")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Invalid or expired OTP"));
    }

    @Test
    void sendResetOtpDoesNotRevealWhetherTheEmailExists() throws Exception {
        String known = email("known");
        register(known);

        String knownResponse = mvc.perform(
                        post("/api/v1/send-reset-otp").param("email", known))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        String unknownResponse = mvc.perform(
                        post("/api/v1/send-reset-otp")
                                .param("email", email("unknown")))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        assertEquals(knownResponse, unknownResponse);
    }

    @Test
    void resetOtpRequestsAreRateLimitedPerEmail() throws Exception {
        String email = email("limited");

        for (int i = 0; i < 3; i++) {
            mvc.perform(post("/api/v1/send-reset-otp").param("email", email))
                    .andExpect(status().isOk());
        }

        mvc.perform(post("/api/v1/send-reset-otp").param("email", email))
                .andExpect(status().isTooManyRequests());
    }
}
