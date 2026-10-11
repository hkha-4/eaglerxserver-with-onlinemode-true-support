package com.example.velocityplugin;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.util.GameProfile;
import org.slf4j.Logger;

import javax.inject.Inject;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

@Plugin(
    id = "microsoft-oauth2-auth",
    name = "Microsoft OAuth2 Authentication",
    version = "1.0.0",
    description = "Authenticate players using Microsoft OAuth2 Device Code Flow",
    authors = {"YourName"}
)
public class MicrosoftOAuth2Plugin {

    private final ProxyServer proxyServer;
    private final Logger logger;
    private final Gson gson = new Gson();
    
    private String clientId;
    private final String targetUsername;
    private final String configPath;
    private final Map<String, PlayerAuthSession> activeSessions = new HashMap<>();

    private static final String DEVICE_CODE_ENDPOINT = "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode";
    private static final String TOKEN_ENDPOINT = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token";
    private static final String XBOX_AUTH_ENDPOINT = "https://user.auth.xboxlive.com/user/authenticate";
    private static final String XSTS_ENDPOINT = "https://xsts.auth.xboxlive.com/xsts/authorize";
    private static final String MINECRAFT_ENDPOINT = "https://api.minecraftservices.com/authentication/login_with_xbox";

    @Inject
    public MicrosoftOAuth2Plugin(ProxyServer proxyServer, Logger logger) {
        this.proxyServer = proxyServer;
        this.logger = logger;
        this.configPath = "plugins/microsoft-oauth2-auth/config.yml";
        this.targetUsername = "YourUsername"; // Default value
        
        loadConfiguration();
    }

    private void loadConfiguration() {
        try {
            Path configFilePath = Paths.get(configPath);
            
            // Create directory if it doesn't exist
            Files.createDirectories(configFilePath.getParent());
            
            if (!Files.exists(configFilePath)) {
                createDefaultConfig(configFilePath);
                logger.error("Configuration file not found! Created default config.yml at: " + configPath);
                logger.error("PLEASE UPDATE THE CLIENT ID IN THE CONFIG FILE!");
                this.clientId = "PLACEHOLDER_ID";
                return;
            }
            
            // Parse YAML manually (simple implementation)
            String configContent = new String(Files.readAllBytes(configFilePath), StandardCharsets.UTF_8);
            String[] lines = configContent.split("\n");
            
            for (String line : lines) {
                line = line.trim();
                if (line.startsWith("client-id:")) {
                    this.clientId = line.substring(10).trim().replaceAll("['\"]", "");
                    break;
                }
            }
            
            if (this.clientId == null || this.clientId.isEmpty()) {
                this.clientId = "PLACEHOLDER_ID";
            }
            
            if ("PLACEHOLDER_ID".equals(this.clientId)) {
                logger.error("╔════════════════════════════════════════════════════════════════╗");
                logger.error("║                    CONFIGURATION ERROR!                         ║");
                logger.error("║                                                                ║");
                logger.error("║  Please update the 'client-id' in the config.yml file!        ║");
                logger.error("║  Location: " + configPath);
                logger.error("║  Replace 'PLACEHOLDER_ID' with your Azure app Client ID       ║");
                logger.error("╚════════════════════════════════════════════════════════════════╝");
            }
            
        } catch (IOException e) {
            logger.error("Failed to load configuration: " + e.getMessage());
            this.clientId = "PLACEHOLDER_ID";
        }
    }

    private void createDefaultConfig(Path configPath) throws IOException {
        String defaultConfig = "# Microsoft OAuth2 Authentication Plugin Configuration\n" +
                "# Register your app at: https://portal.azure.com/\n" +
                "# Set Redirect URI to: http://localhost:8080/callback\n" +
                "\n" +
                "client-id: 'PLACEHOLDER_ID'\n";
        
        Files.write(configPath, defaultConfig.getBytes(StandardCharsets.UTF_8));
    }

    @Subscribe
    public void onPreLogin(PreLoginEvent event) {
        String username = event.getConnection().getRequestedUsername();
        
        // Check if this is the target user
        if (!targetUsername.equals(username)) {
            return;
        }
        
        logger.info("Pre-login detected for: " + username);
        
        if ("PLACEHOLDER_ID".equals(clientId)) {
            logger.error("Cannot authenticate " + username + " - Client ID is not configured!");
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(
                com.velocitypowered.api.util.ProxyVersion.showVersion().componentFromLine(
                    "§cClient ID not configured. Contact administrator."
                )
            ));
            return;
        }
        
        // Handle authentication asynchronously
        event.setResult(PreLoginEvent.PreLoginComponentResult.allowed());
        
        // Start auth process
        proxyServer.getScheduler().buildTask(this, () -> {
            handleDeviceCodeAuth(username, event.getConnection());
        }).schedule();
    }

    private void handleDeviceCodeAuth(String username, Object connection) {
        try {
            logger.info("Starting Device Code Flow for: " + username);
            
            // Step 1: Get device code
            DeviceCodeResponse deviceCodeResp = requestDeviceCode();
            if (deviceCodeResp == null) {
                logger.error("Failed to get device code for: " + username);
                return;
            }
            
            logger.info("═══════════════════════════════════════════════════════════");
            logger.info("║            MICROSOFT OAUTH2 AUTHENTICATION              ║");
            logger.info("═══════════════════════════════════════════════════════════");
            logger.info("║");
            logger.info("║  User Code: " + String.format("%-45s", deviceCodeResp.user_code) + "║");
            logger.info("║");
            logger.info("║  Please visit: " + deviceCodeResp.verification_uri);
            logger.info("║");
            logger.info("║  Enter the code above to authenticate your account.     ║");
            logger.info("║");
            logger.info("═══════════════════════════════════════════════════════════");
            
            PlayerAuthSession session = new PlayerAuthSession(username, deviceCodeResp);
            activeSessions.put(username, session);
            
            // Step 2: Poll for token
            pollForToken(username, deviceCodeResp, session);
            
        } catch (Exception e) {
            logger.error("OAuth2 authentication error for " + username + ": " + e.getMessage(), e);
        }
    }

    private DeviceCodeResponse requestDeviceCode() throws Exception {
        String params = "client_id=" + clientId + "&scope=XboxLive.signin+offline_access";
        
        HttpURLConnection conn = (HttpURLConnection) new URL(DEVICE_CODE_ENDPOINT).openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setDoOutput(true);
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);
        
        try (OutputStream os = conn.getOutputStream()) {
            os.write(params.getBytes(StandardCharsets.UTF_8));
        }
        
        if (conn.getResponseCode() != 200) {
            logger.error("Device code request failed with code: " + conn.getResponseCode());
            return null;
        }
        
        JsonObject response = gson.fromJson(
            new String(conn.getInputStream().readAllBytes(), StandardCharsets.UTF_8),
            JsonObject.class
        );
        
        DeviceCodeResponse resp = new DeviceCodeResponse();
        resp.device_code = response.get("device_code").getAsString();
        resp.user_code = response.get("user_code").getAsString();
        resp.verification_uri = response.get("verification_uri").getAsString();
        resp.expires_in = response.get("expires_in").getAsInt();
        resp.interval = response.has("interval") ? response.get("interval").getAsInt() : 5;
        
        return resp;
    }

    private void pollForToken(String username, DeviceCodeResponse deviceCode, PlayerAuthSession session) {
        long startTime = System.currentTimeMillis();
        long expirationTime = startTime + (deviceCode.expires_in * 1000L);
        
        proxyServer.getScheduler().buildTask(this, new Runnable() {
            private int pollCount = 0;
            
            @Override
            public void run() {
                if (System.currentTimeMillis() > expirationTime) {
                    logger.warn("Device code expired for: " + username);
                    activeSessions.remove(username);
                    return;
                }
                
                try {
                    TokenResponse tokenResp = requestToken(deviceCode.device_code);
                    
                    if (tokenResp != null && tokenResp.access_token != null) {
                        logger.info("Token received for: " + username);
                        session.accessToken = tokenResp.access_token;
                        
                        // Proceed with Xbox/XSTS/Minecraft auth chain
                        completeMinecraftAuthentication(username, session);
                        activeSessions.remove(username);
                    } else if (pollCount < 100) { // Continue polling
                        pollCount++;
                    } else {
                        logger.warn("Token polling timeout for: " + username);
                        activeSessions.remove(username);
                    }
                    
                } catch (Exception e) {
                    logger.error("Poll error for " + username + ": " + e.getMessage());
                }
            }
        }).repeat(deviceCode.interval, TimeUnit.SECONDS).schedule();
    }

    private TokenResponse requestToken(String deviceCode) throws Exception {
        String params = "grant_type=urn:ietf:params:oauth:grant-type:device_code" +
                "&device_code=" + deviceCode +
                "&client_id=" + clientId;
        
        HttpURLConnection conn = (HttpURLConnection) new URL(TOKEN_ENDPOINT).openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setDoOutput(true);
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);
        
        try (OutputStream os = conn.getOutputStream()) {
            os.write(params.getBytes(StandardCharsets.UTF_8));
        }
        
        int responseCode = conn.getResponseCode();
        
        if (responseCode == 400) {
            // Still waiting for user authorization
            return null;
        }
        
        if (responseCode != 200) {
            logger.error("Token request failed with code: " + responseCode);
            return null;
        }
        
        JsonObject response = gson.fromJson(
            new String(conn.getInputStream().readAllBytes(), StandardCharsets.UTF_8),
            JsonObject.class
        );
        
        TokenResponse resp = new TokenResponse();
        resp.access_token = response.get("access_token").getAsString();
        
        return resp;
    }

    private void completeMinecraftAuthentication(String username, PlayerAuthSession session) {
        try {
            logger.info("Starting Xbox/XSTS/Minecraft auth chain for: " + username);
            
            // Xbox Live auth
            String xboxToken = authenticateXboxLive(session.accessToken);
            if (xboxToken == null) {
                logger.error("Xbox Live authentication failed for: " + username);
                return;
            }
            
            // XSTS auth
            XstsResponse xstsResp = authenticateXSTS(xboxToken);
            if (xstsResp == null) {
                logger.error("XSTS authentication failed for: " + username);
                return;
            }
            
            // Minecraft auth
            MinecraftAuthResponse mcResp = authenticateMinecraft(xstsResp);
            if (mcResp == null) {
                logger.error("Minecraft authentication failed for: " + username);
                return;
            }
            
            // Update player profile with premium UUID and textures
            updatePlayerProfile(username, mcResp);
            
            logger.info("Successfully authenticated: " + username);
            logger.info("Premium UUID: " + mcResp.profile.id);
            
        } catch (Exception e) {
            logger.error("Minecraft auth chain error for " + username + ": " + e.getMessage(), e);
        }
    }

    private String authenticateXboxLive(String accessToken) throws Exception {
        JsonObject payload = new JsonObject();
        payload.addProperty("RelyingParty", "http://auth.xboxlive.com");
        payload.addProperty("TokenType", "JWT");
        payload.addProperty("Properties", new JsonObject().toString());
        
        JsonObject props = new JsonObject();
        props.addProperty("AuthMethod", "RPS");
        props.addProperty("SiteName", "user.auth.xboxlive.com");
        props.addProperty("RpsTicket", "d=" + accessToken);
        payload.add("Properties", props);
        
        HttpURLConnection conn = (HttpURLConnection) new URL(XBOX_AUTH_ENDPOINT).openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);
        
        String jsonPayload = gson.toJson(payload);
        try (OutputStream os = conn.getOutputStream()) {
            os.write(jsonPayload.getBytes(StandardCharsets.UTF_8));
        }
        
        if (conn.getResponseCode() != 200) {
            logger.error("Xbox Live auth failed: " + conn.getResponseCode());
            return null;
        }
        
        JsonObject response = gson.fromJson(
            new String(conn.getInputStream().readAllBytes(), StandardCharsets.UTF_8),
            JsonObject.class
        );
        
        return response.get("Token").getAsString();
    }

    private XstsResponse authenticateXSTS(String xboxToken) throws Exception {
        JsonObject payload = new JsonObject();
        payload.addProperty("RelyingParty", "rp://api.minecraftservices.com/");
        payload.addProperty("TokenType", "JWT");
        
        JsonObject props = new JsonObject();
        JsonObject userTokens = new JsonObject();
        userTokens.addProperty("xtoken", xboxToken);
        props.add("UserTokens", new com.google.gson.JsonArray());
        ((com.google.gson.JsonArray) props.get("UserTokens")).add(xboxToken);
        payload.add("Properties", props);
        
        HttpURLConnection conn = (HttpURLConnection) new URL(XSTS_ENDPOINT).openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);
        
        String jsonPayload = gson.toJson(payload);
        try (OutputStream os = conn.getOutputStream()) {
            os.write(jsonPayload.getBytes(StandardCharsets.UTF_8));
        }
        
        if (conn.getResponseCode() != 200) {
            logger.error("XSTS auth failed: " + conn.getResponseCode());
            return null;
        }
        
        JsonObject response = gson.fromJson(
            new String(conn.getInputStream().readAllBytes(), StandardCharsets.UTF_8),
            JsonObject.class
        );
        
        XstsResponse resp = new XstsResponse();
        resp.token = response.get("Token").getAsString();
        resp.uhs = response.getAsJsonObject("DisplayClaims")
            .getAsJsonArray("xui")
            .get(0)
            .getAsJsonObject()
            .get("uhs")
            .getAsString();
        
        return resp;
    }

    private MinecraftAuthResponse authenticateMinecraft(XstsResponse xstsResp) throws Exception {
        JsonObject payload = new JsonObject();
        payload.addProperty("identityToken", "XBL3.0 x=" + xstsResp.uhs + ";a" + xstsResp.token);
        
        HttpURLConnection conn = (HttpURLConnection) new URL(MINECRAFT_ENDPOINT).openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);
        
        String jsonPayload = gson.toJson(payload);
        try (OutputStream os = conn.getOutputStream()) {
            os.write(jsonPayload.getBytes(StandardCharsets.UTF_8));
        }
        
        if (conn.getResponseCode() != 200) {
            logger.error("Minecraft auth failed: " + conn.getResponseCode());
            return null;
        }
        
        JsonObject response = gson.fromJson(
            new String(conn.getInputStream().readAllBytes(), StandardCharsets.UTF_8),
            JsonObject.class
        );
        
        MinecraftAuthResponse resp = new MinecraftAuthResponse();
        resp.accessToken = response.get("access_token").getAsString();
        
        JsonObject profile = response.getAsJsonObject("profile");
        resp.profile = new MinecraftProfile();
        resp.profile.id = profile.get("id").getAsString();
        resp.profile.name = profile.get("name").getAsString();
        
        if (response.has("skins") && response.getAsJsonArray("skins").size() > 0) {
            JsonObject skin = response.getAsJsonArray("skins").get(0).getAsJsonObject();
            resp.profile.skinUrl = skin.get("url").getAsString();
            resp.profile.skinModel = skin.has("variant") ? skin.get("variant").getAsString() : "classic";
        }
        
        if (response.has("capes") && response.getAsJsonArray("capes").size() > 0) {
            resp.profile.capeUrl = response.getAsJsonArray("capes").get(0).getAsJsonObject().get("url").getAsString();
        }
        
        return resp;
    }

    private void updatePlayerProfile(String username, MinecraftAuthResponse authResp) {
        // Find the player in the proxy
        Optional<Player> playerOpt = proxyServer.getAllPlayers().stream()
            .filter(p -> p.getUsername().equals(username))
            .findFirst();
        
        if (playerOpt.isPresent()) {
            Player player = playerOpt.get();
            
            // Create new game profile with premium UUID
            GameProfile newProfile = new GameProfile(
                java.util.UUID.fromString(formatUUID(authResp.profile.id)),
                authResp.profile.name
            );
            
            // Add skin textures if available
            if (authResp.profile.skinUrl != null) {
                Map<String, String> textures = new HashMap<>();
                textures.put("SKIN", authResp.profile.skinUrl);
                if (authResp.profile.capeUrl != null) {
                    textures.put("CAPE", authResp.profile.capeUrl);
                }
                newProfile.setProperties(textures);
            }
            
            logger.info("Updated profile for " + username + " with UUID: " + newProfile.getId());
        }
    }

    private String formatUUID(String id) {
        if (id.length() != 32) return id;
        return id.substring(0, 8) + "-" + 
               id.substring(8, 12) + "-" + 
               id.substring(12, 16) + "-" + 
               id.substring(16, 20) + "-" + 
               id.substring(20);
    }

    // Inner classes for API responses
    private static class DeviceCodeResponse {
        String device_code;
        String user_code;
        String verification_uri;
        int expires_in;
        int interval;
    }

    private static class TokenResponse {
        String access_token;
    }

    private static class XstsResponse {
        String token;
        String uhs;
    }

    private static class MinecraftAuthResponse {
        String accessToken;
        MinecraftProfile profile;
    }

    private static class MinecraftProfile {
        String id;
        String name;
        String skinUrl;
        String skinModel;
        String capeUrl;
    }

    private static class PlayerAuthSession {
        String username;
        DeviceCodeResponse deviceCode;
        String accessToken;

        PlayerAuthSession(String username, DeviceCodeResponse deviceCode) {
            this.username = username;
            this.deviceCode = deviceCode;
        }
    }
}
