package kr.sprouts.framework.autoconfigure.security.credential.provider.properties;

import kr.sprouts.framework.library.security.credential.CredentialHeaderSpec;
import kr.sprouts.framework.library.security.credential.CredentialProviderSpec;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@ConfigurationProperties(prefix = "sprouts.security.credential")
@Getter @Setter
public class CredentialProviderConfigurationProperty {
    private CredentialHeaderSpec header;
    private List<CredentialProviderSpec> providers;
}
