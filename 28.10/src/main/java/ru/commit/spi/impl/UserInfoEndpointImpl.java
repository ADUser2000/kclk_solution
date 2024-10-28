package ru.commit.spi.impl;



import jakarta.ws.rs.core.Response;
import ru.commit.spi.UserInfoEndpointSpi;


public class UserInfoEndpointImpl implements UserInfoEndpointSpi {

    @Override
    public Response issueUserInfoPreflight() {

        return Response.ok().build();
    }

    @Override
    public Response issueUserInfoGet() {

        return Response.ok().build();
    }

    @Override
    public Response issueUserInfoPost() {

        return Response.ok().build();
    }
}