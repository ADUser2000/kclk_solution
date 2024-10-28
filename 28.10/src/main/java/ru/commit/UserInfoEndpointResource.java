package ru.commit;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;
import ru.commit.spi.impl.UserInfoEndpointLoggingDecorator;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Response;
import org.keycloak.utils.MediaType;

public class UserInfoEndpointResource implements RealmResourceProvider {

    private final KeycloakSession session;
    private final UserInfoEndpointLoggingDecorator userInfoEndpoint;

    public UserInfoEndpointResource(KeycloakSession session, UserInfoEndpointLoggingDecorator userInfoEndpoint) {
        this.session = session;
        this.userInfoEndpoint = userInfoEndpoint;
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Path("/")
    @GET
    @Produces({MediaType.APPLICATION_JSON, MediaType.APPLICATION_JWT})
    public Response issueUserInfoGet() {
        return userInfoEndpoint.issueUserInfoGet();
    }

    @Path("/")
    @POST
    @Produces({MediaType.APPLICATION_JSON, MediaType.APPLICATION_JWT})
    public Response issueUserInfoPost() {
        return userInfoEndpoint.issueUserInfoPost();
    }

    @Override
    public void close() {
    }
}