package com.example.deviceauth;

import com.google.gson.Gson;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.ProxyServer;
import net.kyori.adventure.text.Component;
import org.slf4j.Logger;

import javax.inject.Inject;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Plugin(
    id = "deviceauthplugin",
    name = "DeviceAuthPlugin",
    version = "1.0.0",
    authors = {"Copilot"}
)
public final class DeviceAuthPlugin {

    private static final String DEFAULT_USERNAME = "YourUsername";
    private static final String PLACEHOLDER_ID = "PLACEHOLDER_ID";

    private static final String DEFAULT_DEVICE_CODE_URL =
        "https://microsoftonline.com";
    private static final String DEFAULT_TOKEN_URL =
        "https://microsoftonline.com";

    private static final HttpClient HTTP = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(15))
        .build();

    private static final Gson GSON = new Gson();

    private final ProxyServer server;
    private final Logger logger;
    private final Path dataDirectory;

    private final ConcurrentMap<String, String> authenticatedUsers = new ConcurrentHashMap<>();

    @Inject
    public DeviceAuthPlugin(ProxyServer server, Logger logger, @DataDirectory Path dataDirectory) {
        this.server = server;
        this.logger = logger;
        this.dataDirectory = dataDirectory;
    }

    @Subscribe
    public void onProxyInitialize(ProxyInitializeEvent event) {
        try {
            PluginConfig config = loadConfig();

            if (PLACEHOLDER_ID.equals(config.clientId)) {
                logger.error("=========================================");
                logger.error("Device auth is not configured.");
                logger.error("Open config.yml in the plugin data folder and set:");
                logger.error("  client-id: 'YOUR_REAL_CLIENT_ID'");
                logger.error("The placeholder value is currently active.");
                logger.error("=========================================");
                return;
            }

            logger.info("DeviceAuthPlugin initialized.");
            logger.info("Target username: {}", config.username);
            logger.info("Client ID configured: {}", config.clientId);
        } catch (Exception e) {
            logger.error("Failed to initialize DeviceAuthPlugin", e);
        }
    }

    @Subscribe
    public void onPreLogin(PreLoginEvent event) {
        try {
            PluginConfig config = loadConfig();
            String requestedName = event.getUsername();

            if (!config.enabled) {
                return;
            }

            if (!config.username.equalsIgnoreCase(requestedName)) {
                return;
            }

            String authToken = authenticatedUsers.get(requestedName);
            if (authToken != null && !authToken.isBlank()) {
                event.setResult(PreLoginEvent.PreLoginComponentResult.allowed());
                return;
            }

            if (PLACEHOLDER_ID.equals(config.clientId)) {
                logger.error("Client ID is still the placeholder. Please update config.yml.");
                event.setResult(PreLoginEvent.PreLoginComponentResult.denied(
                    Component.text("Microsoft device auth is not configured. Check the proxy console.")
                ));
                return;
            }

            logger.warn("Intercepted login for configured username: {}", requestedName);
            logger.warn("Starting Microsoft device-code login flow...");
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(
                Component.text("Microsoft login required. Please complete the device code flow in the proxy console.")
            ));

            startDeviceAuthFlow(requestedName, config.clientId);
        } catch (Exception e) {
            logger.error("Error while handling PreLoginEvent for {}", event.getUsername(), e);
        }
    }

    private void startDeviceAuthFlow(String username, String clientId) {
        new Thread(() -> {
            try {
                DeviceCodeResponse deviceCodeResponse = requestDeviceCode(clientId);
                if (deviceCodeResponse == null || deviceCodeResponse.user_code == null) {
                    logger.error("Microsoft device code request failed. No user_code received.");
                    return;
                }

                logger.warn("=========================================");
                logger.warn("Microsoft Device Login Required");
                logger.warn("Username: {}", username);
                logger.warn("User code: {}", deviceCodeResponse.user_code);
                logger.warn("Open: https://microsoft.com");
                logger.warn("=========================================");

                pollForToken(username, clientId, deviceCodeResponse);
            } catch (Exception e) {
                logger.error("Exception during Microsoft device login flow for {}", username, e);
            }
        }, "DeviceAuthPoll-" + username).start();
    }

    private void pollForToken(String username, String clientId, DeviceCodeResponse deviceCodeResponse) throws Exception {
        long expiresAt = System.currentTimeMillis() + (deviceCodeResponse.expires_in * 1000L);
        int intervalSeconds = Math.max(5, deviceCodeResponse.interval);
        int attempts = 0;

        while (System.currentTimeMillis() < expiresAt) {
            Thread.sleep(intervalSeconds * 1000L);

            TokenResponse tokenResponse = requestToken(clientId, deviceCodeResponse.device_code);

            if (tokenResponse == null) {
                attempts++;
                continue;
            }

            if (tokenResponse.access_token != null && !tokenResponse.access_token.isBlank()) {
                logger.info("Microsoft device code flow completed successfully for {}", username);
                logger.info("Access token received successfully. You may now rejoin the proxy server.");
                authenticatedUsers.put(username, tokenResponse.access_token);
                return;
            }

            if ("authorization_pending".equalsIgnoreCase(tokenResponse.error)) {
                logger.info("Waiting for Microsoft user authentication... ({})", ++attempts);
                continue;
            }

            if ("slow_down".equalsIgnoreCase(tokenResponse.error)) {
                logger.warn("Microsoft token endpoint requested slower polling.");
                intervalSeconds = Math.max(10, intervalSeconds + 5);
                continue;
            }

            if (tokenResponse.error != null) {
                logger.error("Device flow failed: {} - {}", tokenResponse.error, tokenResponse.error_description);
                return;
            }
        }
        logger.error("Microsoft device login timed out for {}.", username);
    }

    private DeviceCodeResponse requestDeviceCode(String clientId) throws IOException, InterruptedException {
        Map<String, String> form = Map.of(
            "client_id", clientId,
            "scope", "openid profile offline_access"
        );
        String body = buildUrlEncodedForm(form);

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(DEFAULT_DEVICE_CODE_URL))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build();

        HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 200) {
            return GSON.fromJson(response.body(), DeviceCodeResponse.class);
        }
        logger.error("Device code endpoint returned HTTP Status {}: {}", response.statusCode(), response.body());
        return null;
    }

    private TokenResponse requestToken(String clientId, String deviceCode) throws IOException, InterruptedException {
        Map<String, String> form = Map.of(
            "grant_type", "urn:ietf:params:oauth:grant-type:device_code",
            "client_id", clientId,
            "device_code", deviceCode
        );
        String body = buildUrlEncodedForm(form);

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(DEFAULT_TOKEN_URL))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build();

        HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 200 || response.statusCode() == 400) {
            return GSON.fromJson(response.body(), TokenResponse.class);
        }
        return null;
    }

    private String buildUrlEncodedForm(Map<String, String> form) {
        return form.entrySet().stream()
            .map(e -> e.getKey() + "=" + java.net.URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
            .collect(Collectors.joining("&"));
    }

    private PluginConfig loadConfig() throws IOException {
        if (!Files.exists(dataDirectory)) {
