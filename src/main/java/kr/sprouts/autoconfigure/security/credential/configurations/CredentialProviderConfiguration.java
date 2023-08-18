package kr.sprouts.autoconfigure.security.credential.configurations;

import kr.sprouts.autoconfigure.security.credential.properties.CredentialProviderConfigurationProperty;
import kr.sprouts.autoconfigure.security.credential.providers.CredentialProviderManager;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan(basePackageClasses = { CredentialProviderManager.class })
@EnableConfigurationProperties(value = { CredentialProviderConfigurationProperty.class })
@Slf4j
@Getter
public class CredentialProviderConfiguration {
    private final CredentialProviderConfigurationProperty credentialProviderConfigurationProperty;

    public CredentialProviderConfiguration(CredentialProviderConfigurationProperty credentialProviderConfigurationProperty) {
        this.credentialProviderConfigurationProperty = credentialProviderConfigurationProperty;

        if (log.isInfoEnabled()) log.info("Initialized {}", CredentialProviderConfigurationProperty.class.getSimpleName());
    }
}
