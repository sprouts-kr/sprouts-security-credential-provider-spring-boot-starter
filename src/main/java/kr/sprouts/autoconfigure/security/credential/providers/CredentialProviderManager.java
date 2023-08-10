package kr.sprouts.autoconfigure.security.credential.providers;

import kr.sprouts.autoconfigure.security.credential.properties.CredentialProviderConfigurationProperty;
import kr.sprouts.security.credential.CredentialProvider;
import kr.sprouts.security.credential.CredentialProviderSpec;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

@Component
public class CredentialProviderManager {
    Logger log = Logger.getLogger(this.getClass().getSimpleName());
    private final Map<UUID, CredentialProvider<?>> credentialProviders;

    @Autowired
    public CredentialProviderManager(CredentialProviderConfigurationProperty credentialProviderConfigurationProperty) {
        if (credentialProviderConfigurationProperty == null
                || credentialProviderConfigurationProperty.getProviders() == null
                || credentialProviderConfigurationProperty.getProviders().isEmpty()
        ) throw new InitializeCredentialProviderException();

        credentialProviders = new HashMap<>();

        for (CredentialProviderSpec credentialProviderSpec : credentialProviderConfigurationProperty.getProviders()) {
            switch (credentialProviderSpec.getType().toUpperCase()) {
                case "API_KEY":
                    credentialProviders.put(UUID.fromString(credentialProviderSpec.getId()), ApiKeyCredentialProvider.of(credentialProviderSpec));
                    break;
                case "BEARER_TOKEN":
                    credentialProviders.put(UUID.fromString(credentialProviderSpec.getId()), BearerTokenCredentialProvider.of(credentialProviderSpec));
                    break;
                default:
                    throw new UnsupportedCredentialProviderException();
            }

            if (log.isLoggable(Level.INFO)) {
                log.info(String.format("Initialized credential provider. Id: %s, Name: %s", credentialProviderSpec.getId(), credentialProviderSpec.getName()));
            }
        }
    }

    public Optional<Collection<CredentialProvider<?>>> getValues() {
        return Optional.of(credentialProviders.values());
    }

    public Optional<CredentialProvider<?>> get(UUID providerId) {
         return Optional.of(credentialProviders.get(providerId));
    }

    private static class InitializeCredentialProviderException extends RuntimeException { }
    private static class UnsupportedCredentialProviderException extends RuntimeException { }
}
