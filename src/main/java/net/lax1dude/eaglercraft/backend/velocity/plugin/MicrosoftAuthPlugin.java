package net.lax1dude.eaglercraft.backend.velocity.plugin;

import com.google.inject.Inject;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.event.player.ServerPreLoginEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.util.GameProfile;
import org.slf4j.Logger;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.*;

@Plugin(
    id = "microsoft-auth",
    name = "Microsoft OAuth2 Authenticator",
    version = "1.0.0",
    description = "Authenticate Velocity players via Microsoft OAuth2 Device Code Flow",
    authors = {"Your Name"}
)
public class MicrosoftAuthPlugin {

    private final ProxyServer server;
    private final Logger logger;
    private final Path dataDirectory;
    private MicrosoftAuthConfig config;
    private ExecutorService authExecutor;
    private Map<String, AuthenticationSession> activeSessions = new ConcurrentHashMap<>();

    @Inject
    public MicrosoftAuthPlugin(ProxyServer server, Logger logger, @DataDirectory Path dataDirectory) {
        this.server = server;
        this.logger = logger;
        this.dataDirectory = dataDirectory;
    }

    @Subscribe
    public void onProxyInitialize(ProxyInitializeEvent event) {
        logger.info("Initializing Microsoft Auth Plugin...");
        
        try {
            Files.createDirectories(dataDirectory);
            config = MicrosoftAuthConfig.load(dataDirectory, logger);
            
            if (config.getClientId().equals("PLACEHOLDER_ID")) {
                logger.error("======================================");
                logger.error("Microsoft Auth Plugin ERROR:");
                logger.error("Client ID is not configured!");
                logger.error("Please edit: " + dataDirectory.resolve("config.yml"));
                logger.error("Set your Azure App Client ID in 'client-id' field");
                logger.error("Get one from: https://portal.azure.com");
                logger.error("======================================");
                return;
            }
            
            authExecutor = Executors.newFixedThreadPool(4);
            server.getEventManager().register(this, new LoginEventListener(this, config, logger));
            
            logger.info("✓ Microsoft Auth Plugin initialized successfully");
            logger.info("  Default username: {}", config.getTargetUsername());
            logger.info("  Polling interval: {} seconds", config.getPollingIntervalSeconds());
            
        } catch (Exception e) {
            logger.error("Failed to initialize Microsoft Auth Plugin", e);
        }
    }

    public void initiateDeviceCodeFlow(String username) {
        authExecutor.submit(() -> {
            try {
                logger.info("Starting Device Code Flow for: {}", username);
                
                DeviceCodeResponse deviceCode = MicrosoftOAuth2.requestDeviceCode(config.getClientId(), logger);
                
                if (deviceCode == null) {
                    logger.error("Failed to obtain device code for {}", username);
                    return;
                }
                
                logger.info("");
                logger.info("╔════════════════════════════════════════════════════════════╗");
                logger.info("║         MICROSOFT AUTHENTICATION REQUIRED                  ║");
                logger.info("║                                                            ║");
                logger.info("║  User Code: {}", padRight(deviceCode.getDeviceCode(), 40));
                logger.info("║                                                            ║");
                logger.info("║  Visit: https://microsoft.com/link                         ║");
                logger.info("║  and enter the code above to authenticate.                 ║");
                logger.info("║                                                            ║");
                logger.info("║  Waiting for authentication... (expires in {} seconds)", deviceCode.getExpiresIn());
                logger.info("╚════════════════════════════════════════════════════════════╝");
                logger.info("");
                
                AuthenticationSession session = new AuthenticationSession(username, deviceCode);
                activeSessions.put(username, session);
                
                pollForTokenCompletion(username, deviceCode);
                
            } catch (Exception e) {
                logger.error("Device code flow failed for {}", username, e);
            }
        });
    }

    private void pollForTokenCompletion(String username, DeviceCodeResponse deviceCode) {
        int pollCount = 0;
        int maxPolls = (deviceCode.getExpiresIn() / config.getPollingIntervalSeconds()) + 10;
        
        while (pollCount < maxPolls) {
            try {
                Thread.sleep(config.getPollingIntervalSeconds() * 1000L);
                pollCount++;
                
                TokenResponse tokenResponse = MicrosoftOAuth2.pollTokenEndpoint(
                    config.getClientId(),
                    deviceCode.getDeviceCode(),
                    logger
                );
                
                if (tokenResponse != null && tokenResponse.getAccessToken() != null) {
                    logger.info("✓ Device Code validated! Exchanging for Xbox Live token...");
                    
                    String xboxToken = MicrosoftOAuth2.getXboxLiveToken(tokenResponse.getAccessToken(), logger);
                    if (xboxToken == null) {
                        logger.error("Failed to get Xbox Live token for {}", username);
                        return;
                    }
                    
                    logger.info("✓ Xbox Live token obtained. Exchanging for XSTS token...");
                    
                    String xstsToken = MicrosoftOAuth2.getXSTSToken(xboxToken, logger);
                    if (xstsToken == null) {
                        logger.error("Failed to get XSTS token for {}", username);
                        return;
                    }
                    
                    logger.info("✓ XSTS token obtained. Getting Minecraft Access Token...");
                    
                    MinecraftTokenResponse mcToken = MicrosoftOAuth2.getMinecraftToken(xboxToken, xstsToken, logger);
                    if (mcToken == null || mcToken.getAccessToken() == null) {
                        logger.error("Failed to get Minecraft token for {}", username);
                        return;
                    }
                    
                    logger.info("✓ Minecraft Access Token acquired!");
                    logger.info("  Username: {}", mcToken.getName());
                    logger.info("  UUID: {}", mcToken.getId());
                    
                    AuthenticationSession session = activeSessions.get(username);
                    if (session != null) {
                        session.setMinecraftToken(mcToken);
                        session.setAuthenticated(true);
                        logger.info("✓ User {} is now authenticated and can join the server!", username);
                    }
                    
                    return;
                }
                
            } catch (InterruptedException e) {
                logger.warn("Token polling interrupted for {}", username);
                Thread.currentThread().interrupt();
                return;
            } catch (Exception e) {
                logger.warn("Error polling token endpoint", e);
            }
        }
        
        logger.warn("Authentication timeout for {}. Device code expired.", username);
        activeSessions.remove(username);
    }

    public AuthenticationSession getSession(String username) {
        return activeSessions.get(username);
    }

    public void removeSession(String username) {
        activeSessions.remove(username);
    }

    public MicrosoftAuthConfig getConfig() {
        return config;
    }

    private String padRight(String s, int n) {
        return String.format("%-" + n + "s", s).substring(0, Math.min(s.length() + 2, n));
    }
}
