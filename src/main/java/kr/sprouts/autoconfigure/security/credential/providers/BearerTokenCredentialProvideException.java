package kr.sprouts.autoconfigure.security.credential.providers;

public class BearerTokenCredentialProvideException extends RuntimeException {
    public BearerTokenCredentialProvideException(Throwable cause) {
        super(cause);
    }
}
