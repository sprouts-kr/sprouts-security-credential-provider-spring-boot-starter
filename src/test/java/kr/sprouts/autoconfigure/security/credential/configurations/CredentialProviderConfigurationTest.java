package kr.sprouts.autoconfigure.security.credential.configurations;

import kr.sprouts.autoconfigure.security.credential.properties.CredentialProviderConfigurationProperty;
import kr.sprouts.autoconfigure.security.credential.providers.ApiKeyCredentialProvider;
import kr.sprouts.autoconfigure.security.credential.providers.ApiKeySubject;
import kr.sprouts.autoconfigure.security.credential.providers.BearerTokenCredentialProvider;
import kr.sprouts.autoconfigure.security.credential.providers.BearerTokenSubject;
import kr.sprouts.autoconfigure.security.credential.providers.CredentialProviderManager;
import kr.sprouts.security.credential.Credential;
import kr.sprouts.security.credential.CredentialHeaderSpec;
import kr.sprouts.security.credential.CredentialProvider;
import kr.sprouts.security.credential.CredentialProviderSpec;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@Slf4j
class CredentialProviderConfigurationTest {
    private final ApplicationContextRunner applicationContextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(CredentialProviderConfiguration.class));

    @Test
    void configuration() {
        String[] properties = {
                "sprouts.security.credential.header.provider-header-name=Authorization-Provider",
                "sprouts.security.credential.header.consumer-header-name=Authorization-Consumer",
                "sprouts.security.credential.header.value-header-name=Authorization",

                "sprouts.security.credential.providers[0].id=98c73526-7b15-4e0c-aacd-a47816efaedc",
                "sprouts.security.credential.providers[0].name=Provider #1",
                "sprouts.security.credential.providers[0].type=API_KEY",
                "sprouts.security.credential.providers[0].algorithm=AES128",
                "sprouts.security.credential.providers[0].codec=BASE64_URL",
                "sprouts.security.credential.providers[0].encodedSecret=ptRxQCz0a-Ug9Fiu_A2-0A==",
                "sprouts.security.credential.providers[0].targetConsumers[0].id=bcb7f865-319b-4668-9fca-4ea4440822e2",
                "sprouts.security.credential.providers[0].targetConsumers[0].name=Consumer #1",
                "sprouts.security.credential.providers[0].targetConsumers[1].id=154fa0ac-5e66-4ed0-9bcb-11f7e5d11ebd",
                "sprouts.security.credential.providers[0].targetConsumers[1].name=Consumer #2",
        };

        this.applicationContextRunner.withPropertyValues(properties).run(context-> {
            assertNotNull(CredentialProviderConfiguration.class);
            assertNotNull(CredentialProviderConfigurationProperty.class);
        });
    }

    @Test
    void property() {
        String[] properties = {
                "sprouts.security.credential.header.provider-header-name=Authorization-Provider",
                "sprouts.security.credential.header.consumer-header-name=Authorization-Consumer",
                "sprouts.security.credential.header.value-header-name=Authorization",

                "sprouts.security.credential.providers[0].id=98c73526-7b15-4e0c-aacd-a47816efaedc",
                "sprouts.security.credential.providers[0].name=Provider #1",
                "sprouts.security.credential.providers[0].type=API_KEY",
                "sprouts.security.credential.providers[0].algorithm=AES128",
                "sprouts.security.credential.providers[0].codec=BASE64_URL",
                "sprouts.security.credential.providers[0].encodedSecret=ptRxQCz0a-Ug9Fiu_A2-0A==",
                "sprouts.security.credential.providers[0].targetConsumers[0].id=bcb7f865-319b-4668-9fca-4ea4440822e2",
                "sprouts.security.credential.providers[0].targetConsumers[0].name=Consumer #1",
                "sprouts.security.credential.providers[0].targetConsumers[1].id=154fa0ac-5e66-4ed0-9bcb-11f7e5d11ebd",
                "sprouts.security.credential.providers[0].targetConsumers[1].name=Consumer #2",
        };

        this.applicationContextRunner.withPropertyValues(properties).run(
                context -> {
                    CredentialProviderSpec providerSpec = context.getBean(CredentialProviderConfiguration.class)
                            .getCredentialProviderConfigurationProperty()
                            .getProviders()
                            .stream()
                            .findFirst()
                            .orElseThrow();

                    assertEquals("98c73526-7b15-4e0c-aacd-a47816efaedc", providerSpec.getId());

                    CredentialHeaderSpec headerSpec = context.getBean(CredentialProviderConfiguration.class)
                            .getCredentialProviderConfigurationProperty()
                            .getHeader();

                    assertEquals("Authorization-Provider", headerSpec.getProviderHeaderName());
                }
        );
    }

    @Test
    void provide() {
        String[] properties = {
                "sprouts.security.credential.header.provider-header-name=Authorization-Provider",
                "sprouts.security.credential.header.consumer-header-name=Authorization-Consumer",
                "sprouts.security.credential.header.value-header-name=Authorization",

                "sprouts.security.credential.providers[0].id=98c73526-7b15-4e0c-aacd-a47816efaedc",
                "sprouts.security.credential.providers[0].name=Provider #1",
                "sprouts.security.credential.providers[0].type=API_KEY",
                "sprouts.security.credential.providers[0].algorithm=AES128",
                "sprouts.security.credential.providers[0].codec=BASE64_URL",
                "sprouts.security.credential.providers[0].encodedSecret=ptRxQCz0a-Ug9Fiu_A2-0A==",
                "sprouts.security.credential.providers[0].targetConsumers[0].id=bcb7f865-319b-4668-9fca-4ea4440822e2",
                "sprouts.security.credential.providers[0].targetConsumers[0].name=Consumer #1",
                "sprouts.security.credential.providers[0].targetConsumers[1].id=154fa0ac-5e66-4ed0-9bcb-11f7e5d11ebd",
                "sprouts.security.credential.providers[0].targetConsumers[1].name=Consumer #2",

                "sprouts.security.credential.providers[1].id=fc3ddab7-3942-4cc5-aaaa-b41772c6ebac",
                "sprouts.security.credential.providers[1].name=Provider #2",
                "sprouts.security.credential.providers[1].type=API_KEY",
                "sprouts.security.credential.providers[1].algorithm=AES256",
                "sprouts.security.credential.providers[1].codec=BASE64_URL",
                "sprouts.security.credential.providers[1].encodedSecret=VhIW0Qwfqwm9KGVk6dBfyD0iBlfJSOzCofPdoxUqABg=",
                "sprouts.security.credential.providers[1].targetConsumers[0].id=70ed75d8-bfdc-4227-904f-a9d17bb9472f",
                "sprouts.security.credential.providers[1].targetConsumers[0].name=Consumer #3",
                "sprouts.security.credential.providers[1].targetConsumers[1].id=09b7bcd0-0a2e-456e-991d-3ce178156d00",
                "sprouts.security.credential.providers[1].targetConsumers[1].name=Consumer #4",

                "sprouts.security.credential.providers[2].id=1ebf4960-f935-493c-8beb-1f26376bff54",
                "sprouts.security.credential.providers[2].name=Provider #3(JWT)",
                "sprouts.security.credential.providers[2].type=BEARER_TOKEN",
                "sprouts.security.credential.providers[2].algorithm=HS256",
                "sprouts.security.credential.providers[2].codec=BASE64_URL",
                "sprouts.security.credential.providers[2].encodedSecret=9rBJxUbKuODsQmu1b5oUw5dxc8YcgGh5RnqdLV3nsRwm21UJVrrziYq1a6MM5JLm",
                "sprouts.security.credential.providers[2].targetConsumers[0].id=013a7e72-9bb4-42c6-a908-514375b4318d",
                "sprouts.security.credential.providers[2].targetConsumers[0].name=Consumer #5",
                "sprouts.security.credential.providers[2].targetConsumers[1].id=b6b6088c-fd25-459d-80df-fe42cded290a",
                "sprouts.security.credential.providers[2].targetConsumers[1].name=Consumer #6",
        };

        this.applicationContextRunner.withPropertyValues(properties).run(context -> {
                UUID memberId = UUID.randomUUID();
                Long validityInMinutes = 60L;

                for (CredentialProvider<?> provider : context.getBean(CredentialProviderManager.class).getValues().orElseThrow()) {
                    Credential credential = null;

                    if (provider instanceof ApiKeyCredentialProvider) {
                        credential = ((ApiKeyCredentialProvider) provider).provide(ApiKeySubject.of(memberId));
                    } else if (provider instanceof BearerTokenCredentialProvider) {
                        credential = ((BearerTokenCredentialProvider) provider).provide(BearerTokenSubject.of(memberId, validityInMinutes));
                    }

                    assertNotNull(credential);
                }
        });
    }
}
