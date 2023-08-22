package kr.sprouts.framework.autoconfigure.security.credential.provider.configurations;

import kr.sprouts.framework.autoconfigure.security.credential.provider.components.CredentialProviderManager;
import kr.sprouts.framework.autoconfigure.security.credential.provider.properties.CredentialProviderConfigurationProperty;
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
