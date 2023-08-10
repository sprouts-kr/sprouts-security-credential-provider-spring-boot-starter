package kr.sprouts.autoconfigure.security.credential.configurations;

import kr.sprouts.autoconfigure.security.credential.properties.CredentialProviderConfigurationProperty;
import kr.sprouts.autoconfigure.security.credential.providers.CredentialProviderManager;
import lombok.Getter;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

import java.util.logging.Level;
import java.util.logging.Logger;

@Configuration
@ComponentScan(basePackageClasses = { CredentialProviderManager.class })
@EnableConfigurationProperties(value = { CredentialProviderConfigurationProperty.class })
public class CredentialProviderConfiguration {
    private final Logger log = Logger.getLogger(this.getClass().getSimpleName());

    @Getter
    private final CredentialProviderConfigurationProperty credentialProviderConfigurationProperty;

    public CredentialProviderConfiguration(CredentialProviderConfigurationProperty credentialProviderConfigurationProperty) {
        this.credentialProviderConfigurationProperty = credentialProviderConfigurationProperty;

        if (log.isLoggable(Level.INFO)) {
            log.info(String.format("Initialize %s", this.getClass().getSimpleName()));
        }
    }
}
