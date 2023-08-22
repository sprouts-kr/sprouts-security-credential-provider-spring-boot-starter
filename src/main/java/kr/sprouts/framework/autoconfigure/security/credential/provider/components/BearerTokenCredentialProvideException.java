package kr.sprouts.framework.autoconfigure.security.credential.provider.components;

public class BearerTokenCredentialProvideException extends RuntimeException {
    public BearerTokenCredentialProvideException(Throwable cause) {
        super(cause);
    }
}
