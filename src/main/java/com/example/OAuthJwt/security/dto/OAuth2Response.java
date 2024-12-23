package com.example.OAuthJwt.security.dto;

public interface OAuth2Response {
    String getProvider();

    String getProviderId();

    String getEmail();

    String getName();

    String getMobile();
}
