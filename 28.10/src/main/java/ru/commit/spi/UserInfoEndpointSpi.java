package ru.commit.spi;


import jakarta.ws.rs.core.Response;

public interface UserInfoEndpointSpi {
    Response issueUserInfoPreflight();
    Response issueUserInfoGet();
    Response issueUserInfoPost();
}