package kr.sprouts.framework.autoconfigure.security.credential.provider.components;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import kr.sprouts.framework.library.security.credential.Credential;
import kr.sprouts.framework.library.security.credential.CredentialProvider;
import kr.sprouts.framework.library.security.credential.CredentialProviderSpec;
import kr.sprouts.framework.library.security.credential.Principal;
import kr.sprouts.framework.library.security.credential.codec.Codec;
import kr.sprouts.framework.library.security.credential.codec.CodecType;
import kr.sprouts.framework.library.security.credential.jwt.Jwt;
import kr.sprouts.framework.library.security.credential.jwt.JwtAlgorithm;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

public class BearerTokenCredentialProvider implements CredentialProvider<BearerTokenSubject> {
    private final UUID id;
    private final String name;
    private final Codec codec;
    private final Jwt<?> jwt;
    private final byte[] encryptSecret;
    private final List<UUID> targetConsumerIds;

    private BearerTokenCredentialProvider(String providerId, String providerName, String codec, String algorithm, String encodedEncryptSecret, List<String> targetConsumerIds) {
        this.id = UUID.fromString(providerId);
        this.name = providerName;
        this.codec = CodecType.fromName(codec).getCodecSupplier().get();
        this.jwt = JwtAlgorithm.fromName(algorithm).getJwtSupplier().get();
        this.encryptSecret = this.codec.decode(encodedEncryptSecret);
        this.targetConsumerIds = targetConsumerIds.stream().map(UUID::fromString).toList();
    }

    static BearerTokenCredentialProvider of(CredentialProviderSpec spec) {
        return new BearerTokenCredentialProvider(
                spec.getId(),
                spec.getName(),
                spec.getCodec(),
                spec.getAlgorithm(),
                spec.getEncodedSecret(),
                spec.getTargetConsumers().stream().map(CredentialProviderSpec.TargetConsumer::getId).toList()
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
    public Credential provide(BearerTokenSubject subject) {
        try {
            return Credential.of(
                    id,
                    targetConsumerIds,
                    jwt.createClaimsJws(claims(Principal.of(id, targetConsumerIds, subject)), encryptSecret)
            );
        } catch (JsonProcessingException e) {
            throw new BearerTokenCredentialProvideException(e);
        }
    }

    private Claims claims(Principal<BearerTokenSubject> principal) throws JsonProcessingException {
        LocalDateTime currentDateTime = LocalDateTime.now();

        return Jwts.claims()
                .issuer(principal.getProviderId().toString())
                .subject(principal.getSubject().getMemberId().toString())
                .audience().add(principal.getTargetConsumers().stream().map(UUID::toString).toList()).and()
                .issuedAt(Timestamp.valueOf(currentDateTime))
                .notBefore(Timestamp.valueOf(currentDateTime))
                .expiration(Timestamp.valueOf(currentDateTime.plusMinutes(principal.getSubject().getValidityInMinutes())))
                .build();
    }
}
