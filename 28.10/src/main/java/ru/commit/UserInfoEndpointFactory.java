package ru.commit;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;
import org.keycloak.protocol.oidc.TokenManager;
import ru.commit.spi.impl.UserInfoEndpointLoggingDecorator;

public class UserInfoEndpointFactory implements RealmResourceProviderFactory {

    @Override
    public String getId() {
        return "user-info-endpoint";
    }

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        TokenManager tokenManager = new TokenManager();
        UserInfoEndpointLoggingDecorator userInfoEndpoint = new UserInfoEndpointLoggingDecorator(session, tokenManager);
        return new UserInfoEndpointResource(session, userInfoEndpoint);
    }

    @Override
    public void init(org.keycloak.Config.Scope config) {
    }

    @Override
    public void postInit(org.keycloak.models.KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }
}