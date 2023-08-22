package kr.sprouts.framework.autoconfigure.security.credential.provider.components;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import kr.sprouts.security.credential.Credential;
import kr.sprouts.security.credential.CredentialProvider;
import kr.sprouts.security.credential.CredentialProviderSpec;
import kr.sprouts.security.credential.Principal;
import kr.sprouts.security.credential.cipher.Cipher;
import kr.sprouts.security.credential.cipher.CipherAlgorithm;
import kr.sprouts.security.credential.codec.Codec;
import kr.sprouts.security.credential.codec.CodecType;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

public class ApiKeyCredentialProvider implements CredentialProvider<ApiKeySubject> {
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final UUID id;
    private final String name;
    private final Codec codec;
    private final Cipher<?> cipher;
    private final byte[] encryptSecret;
    private final List<UUID> targetConsumerIds;

    private ApiKeyCredentialProvider(String providerId, String providerName, String codec, String algorithm, String encodedEncryptSecret, List<String> targetConsumerIds) {
        this.id = UUID.fromString(providerId);
        this.name = providerName;
        this.codec = CodecType.fromName(codec).getCodecSupplier().get();
        this.cipher = CipherAlgorithm.fromName(algorithm).getCipherSupplier().get();
        this.encryptSecret = this.codec.decode(encodedEncryptSecret);
        this.targetConsumerIds = targetConsumerIds.stream().map(UUID::fromString).collect(Collectors.toList());
    }

    static ApiKeyCredentialProvider of(CredentialProviderSpec spec) {
        return new ApiKeyCredentialProvider(
                spec.getId(),
                spec.getName(),
                spec.getCodec(),
                spec.getAlgorithm(),
                spec.getEncodedSecret(),
                spec.getTargetConsumers().stream().map(CredentialProviderSpec.TargetConsumer::getId).collect(Collectors.toList())
        );
    }

    @Override
    public UUID getId() {
        return id;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public Credential provide(ApiKeySubject subject) {
        try {
            return Credential.of(
                    id,
                    targetConsumerIds,
                    codec.encodeToString(cipher.encrypt(objectMapper.writeValueAsString(Principal.of(id, targetConsumerIds, subject)), encryptSecret))
            );
        } catch (JsonProcessingException e) {
            throw new ApiKeyCredentialProvideException(e);
        }
    }
}
