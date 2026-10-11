package com.example.velocityauth;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.LoginEvent;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.util.GameProfile;
import com.velocitypowered.api.util.GameProfile.Property;
import org.slf4j.Logger;
import org.yaml.snakeyaml.Yaml;

import javax.inject.Inject;
import java.io.IOException;
import java.lang.reflect.Field;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

@Plugin(
    id = "microsoftdeviceauth",
    name = "MicrosoftDeviceAuth",
    version = "1.0.0",
    authors = {"Copilot"}
)
public class MicrosoftDeviceAuthVelocityPlugin {

    private static final String PLACEHOLDER_ID = "PLACEHOLDER_ID";
    private static final Gson GSON = new Gson();

    private final ProxyServer proxy;
    private final Logger logger;
    private final Path dataDirectory;
    private final Map<String, GameProfile> profileOverrides = new ConcurrentHashMap<>();

    private String clientId = PLACEHOLDER_ID;
    private String targetUsername = "YourUsername";

    @Inject
    public MicrosoftDeviceAuthVelocityPlugin(ProxyServer proxy, Logger logger, @DataDirectory Path dataDirectory) {
        this.proxy = proxy;
        this.logger = logger;
        this.dataDirectory = dataDirectory;
        loadConfiguration();
    }

    @Subscribe
    public void onPreLogin(PreLoginEvent event) {
        String username = event.getUsername();
        if (!username.equalsIgnoreCase(targetUsername)) {
            return;
        }

        if (isPlaceholderClientId()) {
            logger.error("Microsoft OAuth client-id is still the placeholder value. Update config.yml in the plugin data folder with your real client-id.");
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied("Microsoft authentication is not configured. Update the plugin config.yml and set a real client-id."));
            return;
        }

        logger.info("Intercepted login for username '{}'. Starting Microsoft device-code OAuth flow.", username);
        event.setResult(PreLoginEvent.PreLoginComponentResult.denied("Authentication required. Please complete the Microsoft authentication flow shown in the console."));
        beginDeviceCodeFlow(username);
    }

    @Subscribe
    public void onLogin(LoginEvent event) {
        String username = event.getPlayer().getUsername();
        GameProfile override = profileOverrides.remove(username);
        if (override == null) {
            return;
        }

        logger.info("Applying premium profile override to player {}.", username);
        applyGameProfileOverride(event.getPlayer(), override);
    }

    private void loadConfiguration() {
        try {
            Files.createDirectories(dataDirectory);
        } catch (IOException e) {
            logger.error("Could not create plugin data directory.", e);
            return;
        }

        Path configFile = dataDirectory.resolve("config.yml");
        if (!Files.exists(configFile)) {
            String defaultYaml = String.join(System.lineSeparator(),
                "client-id: 'PLACEHOLDER_ID'",
                "target-username: 'YourUsername'",
                "device-code-url: 'https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode'",
                "token-url: 'https://login.microsoftonline.com/consumers/oauth2/v2.0/token'",
                "xbl-auth-url: 'https://user.auth.xboxlive.com/user/authenticate'",
                "xsts-auth-url: 'https://xsts.auth.xboxlive.com/xsts/authorize'",
                "minecraft-token-url: 'https://api.minecraftservices.com/authentication/login_with_xbox'",
                "minecraft-profile-url: 'https://api.minecraftservices.com/minecraft/profile'",
                "poll-interval-seconds: 5"
            );
            try {
                Files.writeString(configFile, defaultYaml + System.lineSeparator(), StandardCharsets.UTF_8);
            } catch (IOException e) {
                logger.error("Failed to write default config.yml", e);
            }
        }

        try {
            String yaml = Files.readString(configFile, StandardCharsets.UTF_8);
            Yaml snakeYAML = new Yaml();
            Object loaded = snakeYAML.load(yaml);
            if (loaded instanceof Map<?, ?> map) {
                Object clientIdValue = map.get("client-id");
                if (clientIdValue != null) {
                    clientId = String.valueOf(clientIdValue).trim();
                }

                Object usernameValue = map.get("target-username");
                if (usernameValue != null) {
                    targetUsername = String.valueOf(usernameValue).trim();
                }
            }
        } catch (IOException | JsonParseException ex) {
            logger.error("Could not read config.yml; using defaults.", ex);
        }

        if (isPlaceholderClientId()) {
            logger.error("The plugin is still using the placeholder client-id. Update the config.yml in {} with your real Microsoft OAuth client ID.", dataDirectory);
        }
    }

    private boolean isPlaceholderClientId() {
        return clientId == null || clientId.trim().isEmpty() || PLACEHOLDER_ID.equalsIgnoreCase(clientId.trim());
    }

    private void beginDeviceCodeFlow(String username) {
        if (isPlaceholderClientId()) {
            return;
        }

        CompletableFuture.runAsync(() -> {
            try {
                Map<String, String> form = new HashMap<>();
                form.put("client_id", clientId);
                form.put("scope", "XboxLive.signin offline_access");

                JsonObject deviceCodeResponse = formPost("https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode", form);
                String userCode = deviceCodeResponse.has("user_code") ? deviceCodeResponse.get("user_code").getAsString() : "UNKNOWN";
                String verificationUri = deviceCodeResponse.has("verification_uri")
                    ? deviceCodeResponse.get("verification_uri").getAsString()
                    : "https://microsoft.com";
                String deviceCode = deviceCodeResponse.has("device_code") ? deviceCodeResponse.get("device_code").getAsString() : "";
                int intervalSeconds = deviceCodeResponse.has("interval") ? deviceCodeResponse.get("interval").getAsInt() : 5;
                long expiresAtMillis = System.currentTimeMillis() + (deviceCodeResponse.has("expires_in") ? deviceCodeResponse.get("expires_in").getAsLong() * 1000L : 900_000L);

                logger.info("-----------------------------------------------------");
                logger.info("MICROSOFT AUTH REQUIRED for username: {}", username);
                logger.info("MICROSOFT AUTH: user_code = {}", userCode);
                logger.info("MICROSOFT AUTH: open {} and log in with the code above.", verificationUri);
                logger.info("MICROSOFT AUTH: or visit https://microsoft.com");
                logger.info("-----------------------------------------------------");

                while (System.currentTimeMillis() < expiresAtMillis) {
                    Thread.sleep(intervalSeconds * 1000L);

                    Map<String, String> tokenForm = new HashMap<>();
                    tokenForm.put("grant_type", "urn:ietf:params:oauth:grant-type:device_code");
                    tokenForm.put("client_id", clientId);
                    tokenForm.put("device_code", deviceCode);

                    JsonObject pollResponse = formPost("https://login.microsoftonline.com/consumers/oauth2/v2.0/token", tokenForm);
                    if (pollResponse.has("access_token")) {
                        String accessToken = pollResponse.get("access_token").getAsString();
                        GameProfile premiumProfile = authenticateMinecraftProfile(username, accessToken);
                        if (premiumProfile != null) {
                            profileOverrides.put(username, premiumProfile);
                            logger.info("Microsoft authentication succeeded for {}. Premium profile override queued.", username);
                        }
                        return;
                    }

                    String error = pollResponse.has("error") ? pollResponse.get("error").getAsString() : "unknown";
                    if (!"authorization_pending".equalsIgnoreCase(error) && !"slow_down".equalsIgnoreCase(error)) {
                        logger.error("Device-code polling failed with error: {}", error);
                        return;
                    }
                }

                logger.error("Microsoft authentication timed out for {}.", username);
            } catch (Exception e) {
                logger.error("Failed to complete the Microsoft device-code OAuth flow.", e);
            }
        });
    }

    private GameProfile authenticateMinecraftProfile(String username, String accessToken) {
        try {
            JsonObject xblResponse = postJson("https://user.auth.xboxlive.com/user/authenticate",
                "{\"Properties\":{\"AuthMethod\":\"RPS\",\"SiteName\":\"user.auth.xboxlive.com\",\"RpsTicket\":\"d=" + accessToken + "\"},\"RelyingParty\":\"http://auth.xboxlive.com\",\"TokenType\":\"JWT\"}"
            );
            String xblToken = xblResponse.get("Token").getAsString();

            JsonObject xstsResponse = postJson("https://xsts.auth.xboxlive.com/xsts/authorize",
                "{\"Properties\":{\"SandboxId\":\"RETAIL\",\"UserTokens\":[\"" + xblToken + "\"]},\"RelyingParty\":\"rp://api.minecraftservices.com/\",\"TokenType\":\"JWT\"}"
            );

            JsonObject xstsProperties = xstsResponse.getAsJsonObject("Properties");
            JsonArray xui = xstsProperties.getAsJsonArray("UserTokens");
            String xstsToken = xstsResponse.get("Token").getAsString();
            String uhs = xui == null || xui.size() == 0 ? null : xui.get(0).getAsJsonObject().get("DisplayClaims").getAsJsonObject().get("xui").getAsJsonArray().get(0).getAsJsonObject().get("uhs").getAsString();
            if (uhs == null || uhs.isBlank()) {
                logger.error("Unable to extract Xbox UHS token from XSTS response.");
                return null;
            }

            JsonObject minecraftResponse = postJson("https://api.minecraftservices.com/authentication/login_with_xbox",
                "{\"identityToken\":\"XBL3.0 x=\" + uhs + \";\" + xstsToken + \"\"}"
            );
            String minecraftAccessToken = minecraftResponse.get("access_token").getAsString();

            JsonObject profileResponse = getJsonWithBearer("https://api.minecraftservices.com/minecraft/profile", minecraftAccessToken);
            JsonObject profileJson = profileResponse;
            String uuidString = profileJson.has("id") ? profileJson.get("id").getAsString() : null;
            if (uuidString == null || uuidString.isBlank()) {
                logger.error("Minecraft profile response did not include a UUID.");
                return null;
            }

            UUID uuid = UUID.fromString(uuidString.replaceFirst("(\\w{8})(\\w{4})(\\w{4})(\\w{4})(\\w{12})", "$1-$2-$3-$4-$5"));
            GameProfile profile = new GameProfile(uuid, username);

            JsonArray properties = profileJson.has("properties") ? profileJson.getAsJsonArray("properties") : new JsonArray();
            for (JsonElement element : properties) {
                JsonObject prop = element.getAsJsonObject();
                if (!prop.has("name") || !prop.has("value")) {
                    continue;
                }
                String propertyName = prop.get("name").getAsString();
                String propertyValue = prop.get("value").getAsString();
                String signature = prop.has("signature") ? prop.get("signature").getAsString() : null;
                profile.getProperties().add(new Property(propertyName, propertyValue, signature));
            }

            logger.info("Successfully authenticated {} with premium Microsoft UUID {}.", username, uuid);
            return profile;
        } catch (Exception e) {
            logger.error("Failed to exchange Microsoft tokens for a premium Minecraft profile.", e);
            return null;
        }
    }

    private JsonObject formPost(String url, Map<String, String> values) throws IOException, InterruptedException {
        StringBuilder body = new StringBuilder();
        List<String> keys = new ArrayList<>(values.keySet());

        for (int i = 0; i < keys.size(); i++) {
            String key = keys.get(i);
            String encodedKey = URLEncoder.encode(key, StandardCharsets.UTF_8);
            String encodedValue = URLEncoder.encode(values.get(key), StandardCharsets.UTF_8);
            body.append(encodedKey).append('=').append(encodedValue);
            if (i + 1 < keys.size()) {
                body.append('&');
            }
        }

        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Accept", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body.toString(), StandardCharsets.UTF_8))
            .build();

        HttpResponse<String> response = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(15))
            .build()
            .send(request, HttpResponse.BodyHandlers.ofString());

        return GSON.fromJson(response.body(), JsonObject.class);
    }

    private JsonObject postJson(String url, String json) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8))
            .build();

        HttpResponse<String> response = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(15))
            .build()
            .send(request, HttpResponse.BodyHandlers.ofString());

        return GSON.fromJson(response.body(), JsonObject.class);
    }

    private JsonObject getJsonWithBearer(String url, String bearerToken) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
            .header("Authorization", "Bearer " + bearerToken)
            .header("Accept", "application/json")
            .GET()
            .build();

        HttpResponse<String> response = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(15))
            .build()
            .send(request, HttpResponse.BodyHandlers.ofString());

        return GSON.fromJson(response.body(), JsonObject.class);
    }

    private void applyGameProfileOverride(com.velocitypowered.api.proxy.Player player, GameProfile overrideProfile) {
        try {
            for (Class<?> current = player.getClass(); current != null; current = current.getSuperclass()) {
                for (Field field : current.getDeclaredFields()) {
                    if (field.getType().equals(GameProfile.class) || GameProfile.class.isAssignableFrom(field.getType())) {
                        field.setAccessible(true);
                        field.set(player, overrideProfile);
                        return;
                    }
                }
            }
            logger.warn("No GameProfile field was found on {}. The override could not be injected.", player.getClass().getName());
        } catch (IllegalAccessException e) {
            logger.warn("Unable to inject GameProfile override into {}.", player.getClass().getName(), e);
        }
    }
}
