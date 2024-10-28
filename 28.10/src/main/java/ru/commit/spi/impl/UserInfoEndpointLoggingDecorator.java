package ru.commit.spi.impl;

import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.TokenCategory;
import org.keycloak.TokenVerifier;
import org.keycloak.common.Profile;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.ContentEncryptionProvider;
import org.keycloak.crypto.CekManagementProvider;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.jose.jwe.JWEException;
import org.keycloak.jose.jwe.alg.JWEAlgorithmProvider;
import org.keycloak.jose.jwe.enc.JWEEncryptionProvider;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.keys.loader.PublicKeyStorageManager;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.TokenManager.NotBeforeCheck;
import org.keycloak.protocol.oidc.endpoints.UserInfoEndpoint;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.dpop.DPoP;
import org.keycloak.services.Urls;
import org.keycloak.services.clientpolicy.ClientPolicyException;
import org.keycloak.services.clientpolicy.context.UserInfoRequestContext;
import org.keycloak.services.cors.Cors;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.util.DPoPUtil;
import org.keycloak.services.util.DefaultClientSessionContext;
import org.keycloak.services.util.MtlsHoKTokenUtil;
import org.keycloak.services.util.UserSessionUtil;
import org.keycloak.util.JsonSerialization;
import org.keycloak.util.TokenUtil;
import org.keycloak.utils.MediaType;
import org.keycloak.utils.OAuth2Error;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.MultivaluedMap;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Map;

public class UserInfoEndpointLoggingDecorator {

    private static final Logger logger = Logger.getLogger(UserInfoEndpointLoggingDecorator.class);
    private static final String LOGGER_PREFIX = "DecoratorCustomLog: ";
    private final UserInfoEndpoint delegate;
    private final KeycloakSession session;
    private final TokenManager tokenManager;
    private final AppAuthManager appAuthManager;
    private final RealmModel realm;
    private final OAuth2Error error;
    private Cors cors;
    private final TokenForUserInfo tokenForUserInfo = new TokenForUserInfo();

    public UserInfoEndpointLoggingDecorator(KeycloakSession session, TokenManager tokenManager) {
        this.session = session;
        this.tokenManager = tokenManager;
        this.delegate = new UserInfoEndpoint(session, tokenManager);
        this.appAuthManager = new AppAuthManager();
        this.realm = session.getContext().getRealm();
        this.error = new OAuth2Error().json(false).realm(realm);
    }

    public Response issueUserInfoGet() {
        logger.info(LOGGER_PREFIX + "Entering issueUserInfoGet");
        setupCors();

        HttpHeaders headers = session.getContext().getHttpRequest().getHttpHeaders();
        logger.info(LOGGER_PREFIX + "Request headers: " + headers);

        String accessToken = AppAuthManager.extractAuthorizationHeaderTokenOrReturnNull(headers);
        logger.info(LOGGER_PREFIX + "Extracted access token: " + accessToken);

        authorization(accessToken);
        logger.info(LOGGER_PREFIX + "Authorization completed");

        Response response = issueUserInfo();
        logger.info(LOGGER_PREFIX + "Exiting issueUserInfoGet");
        return response;
    }

    public Response issueUserInfoPost() {
        logger.info(LOGGER_PREFIX + "Entering issueUserInfoPost");
        setupCors();


        HttpHeaders headers = session.getContext().getHttpRequest().getHttpHeaders();
        logger.info(LOGGER_PREFIX + "Request headers: " + headers);


        String accessToken = AppAuthManager.extractAuthorizationHeaderTokenOrReturnNull(headers);
        logger.info(LOGGER_PREFIX + "Extracted access token from Authorization header: " + accessToken);

        authorization(accessToken);
        logger.info(LOGGER_PREFIX + "Authorization completed");

        try {
            String contentType = headers.getHeaderString(HttpHeaders.CONTENT_TYPE);
            logger.info(LOGGER_PREFIX + "Content-Type: " + contentType);

            jakarta.ws.rs.core.MediaType mediaType = jakarta.ws.rs.core.MediaType.valueOf(contentType);

            if (jakarta.ws.rs.core.MediaType.APPLICATION_FORM_URLENCODED_TYPE.isCompatible(mediaType)) {
                logger.info(LOGGER_PREFIX + "Content-Type is application/x-www-form-urlencoded");

                MultivaluedMap<String, String> formParams = session.getContext().getHttpRequest().getDecodedFormParameters();
                logger.info(LOGGER_PREFIX + "Form parameters: " + formParams);

                checkAccessTokenDuplicated(formParams);
                logger.info(LOGGER_PREFIX + "Access token duplication check completed");

                accessToken = formParams.getFirst(OAuth2Constants.ACCESS_TOKEN);
                logger.info(LOGGER_PREFIX + "Extracted access token from form parameters: " + accessToken);

                authorization(accessToken);
                logger.info(LOGGER_PREFIX + "Authorization completed");
            } else {
                logger.info(LOGGER_PREFIX + "Content-Type is not application/x-www-form-urlencoded");
            }
        } catch (IllegalArgumentException e) {
            logger.warn(LOGGER_PREFIX + "Invalid Content-Type: " + e.getMessage());
        }

        Response response = issueUserInfo();
        logger.info(LOGGER_PREFIX + "Exiting issueUserInfoPost");
        return response;
    }

    @SuppressWarnings("deprecation")
    public Response issueUserInfo() {
        logger.info(LOGGER_PREFIX + "Entering issueUserInfo");

        cors.allowAllOrigins();

        try {
            session.clientPolicy().triggerOnEvent(new UserInfoRequestContext(tokenForUserInfo));
        } catch (ClientPolicyException cpe) {
            logger.error(LOGGER_PREFIX + "ClientPolicyException: " + cpe.getMessage());
            throw error.error(cpe.getError()).errorDescription(cpe.getErrorDetail()).status(cpe.getErrorStatus()).build();
        }

        EventBuilder event = new EventBuilder(realm, session, session.getContext().getConnection())
                .event(EventType.USER_INFO_REQUEST)
                .detail(Details.AUTH_METHOD, Details.VALIDATE_ACCESS_TOKEN);

        if (tokenForUserInfo.getToken() == null) {
            logger.warn(LOGGER_PREFIX + "Missing token");
            event.detail(Details.REASON, "Missing token");
            event.error(Errors.INVALID_TOKEN);
            throw error.unauthorized();
        }

        AccessToken token;
        ClientModel clientModel = null;
        try {
            TokenVerifier<AccessToken> verifier = TokenVerifier.create(tokenForUserInfo.getToken(), AccessToken.class).withDefaultChecks()
                    .realmUrl(Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));

            SignatureVerifierContext verifierContext = session.getProvider(SignatureProvider.class, verifier.getHeader().getAlgorithm().name()).verifier(verifier.getHeader().getKeyId());
            verifier.verifierContext(verifierContext);

            token = verifier.verify().getToken();

            if (!TokenUtil.hasScope(token.getScope(), OAuth2Constants.SCOPE_OPENID)) {
                String errorMessage = "Missing openid scope";
                logger.warn(LOGGER_PREFIX + errorMessage);
                event.detail(Details.REASON, errorMessage);
                event.error(Errors.ACCESS_DENIED);
                throw error.insufficientScope(errorMessage);
            }

            clientModel = realm.getClientByClientId(token.getIssuedFor());
            if (clientModel == null) {
                logger.warn(LOGGER_PREFIX + "Client not found");
                event.error(Errors.CLIENT_NOT_FOUND);
                throw error.invalidToken("Client not found");
            }

            cors.allowedOrigins(session, clientModel);

            TokenVerifier.createWithoutSignature(token)
                    .withChecks(NotBeforeCheck.forModel(clientModel), new TokenManager.TokenRevocationCheck(session))
                    .verify();
        } catch (VerificationException e) {
            if (clientModel == null) {
                cors.allowAllOrigins();
            }
            logger.error(LOGGER_PREFIX + "Token verification failed: " + e.getMessage());
            event.detail(Details.REASON, e.getMessage());
            event.error(Errors.INVALID_TOKEN);
            throw error.invalidToken("Token verification failed");
        }

        if (!clientModel.getProtocol().equals(OIDCLoginProtocol.LOGIN_PROTOCOL)) {
            String errorMessage = "Wrong client protocol";
            logger.warn(LOGGER_PREFIX + errorMessage);
            event.detail(Details.REASON, errorMessage);
            event.error(Errors.INVALID_CLIENT);
            throw error.invalidToken(errorMessage);
        }

        session.getContext().setClient(clientModel);

        event.client(clientModel);

        if (!clientModel.isEnabled()) {
            logger.warn(LOGGER_PREFIX + "Client disabled");
            event.error(Errors.CLIENT_DISABLED);
            throw error.invalidToken("Client disabled");
        }

        UserSessionModel userSession = UserSessionUtil.findValidSession(session, realm, token, event, clientModel, error);
        if (userSession == null ) {
            logger.warn(LOGGER_PREFIX + "User session is not active for user: " + token.getPreferredUsername());
            throw error.invalidToken(LOGGER_PREFIX + "User session or user invalid");
        }

        UserModel userModel = userSession.getUser();
        if (userModel == null) {
            logger.warn(LOGGER_PREFIX + "User is not active");
            event.detail(Details.REASON, "User is not active");
            logger.info(LOGGER_PREFIX + "Checking reasons for inactive session for user: " + token.getPreferredUsername());
            tokenIsExpired(token, event);

            throw error.invalidToken("User not found");
        }

        event.user(userModel)
                .detail(Details.USERNAME, userModel.getUsername());

        if (!userModel.isEnabled()) {
            logger.warn(LOGGER_PREFIX + "User disabled");
            event.error(Errors.USER_DISABLED);
            throw error.invalidToken("User disabled");
        }

        // KEYCLOAK-6771 Certificate Bound Token
        // https://tools.ietf.org/html/draft-ietf-oauth-mtls-08#section-3
        if (OIDCAdvancedConfigWrapper.fromClientModel(clientModel).isUseMtlsHokToken()) {
            if (!MtlsHoKTokenUtil.verifyTokenBindingWithClientCertificate(token, session.getContext().getHttpRequest(), session)) {
                String errorMessage = "Client certificate missing, or its thumbprint and one in the refresh token did NOT match";
                logger.warn(LOGGER_PREFIX + errorMessage);
                event.detail(Details.REASON, errorMessage);
                event.error(Errors.NOT_ALLOWED);
                throw error.invalidToken(errorMessage);
            }
        }

        if (Profile.isFeatureEnabled(Profile.Feature.DPOP)) {
            if (OIDCAdvancedConfigWrapper.fromClientModel(clientModel).isUseDPoP() || DPoPUtil.DPOP_TOKEN_TYPE.equals(token.getType())) {
                try {
                    DPoP dPoP = new DPoPUtil.Validator(session).request(session.getContext().getHttpRequest()).uriInfo(session.getContext().getUri()).validate();
                    DPoPUtil.validateBinding(token, dPoP);
                } catch (VerificationException ex) {
                    String errorMessage = "DPoP proof and token binding verification failed";
                    logger.warn(LOGGER_PREFIX + errorMessage + ": " + ex.getMessage());
                    event.detail(Details.REASON, errorMessage + ": " + ex.getMessage());
                    event.error(Errors.NOT_ALLOWED);
                    throw error.invalidToken(errorMessage);
                }
            }
        }


        AuthenticatedClientSessionModel clientSession = userSession.getAuthenticatedClientSessionByClient(clientModel.getId());


        ClientSessionContext clientSessionCtx = DefaultClientSessionContext.fromClientSessionAndScopeParameter(clientSession, token.getScope(), session);

        AccessToken userInfo = new AccessToken();

        userInfo = tokenManager.transformUserInfoAccessToken(session, userInfo, userSession, clientSessionCtx);
        Map<String, Object> claims = tokenManager.generateUserInfoClaims(userInfo, userModel);

        Response.ResponseBuilder responseBuilder;
        OIDCAdvancedConfigWrapper cfg = OIDCAdvancedConfigWrapper.fromClientModel(clientModel);

        if (cfg.isUserInfoSignatureRequired()) {
            String issuerUrl = Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName());
            String audience = clientModel.getClientId();
            claims.put("iss", issuerUrl);
            claims.put("aud", audience);

            String signatureAlgorithm = session.tokens().signatureAlgorithm(TokenCategory.USERINFO);

            SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, signatureAlgorithm);
            SignatureSignerContext signer = signatureProvider.signer();

            String signedUserInfo = new JWSBuilder().type("JWT").jsonContent(claims).sign(signer);

            try {
                responseBuilder = Response.ok(cfg.isUserInfoEncryptionRequired() ? jweFromContent(signedUserInfo, "JWT") :
                        signedUserInfo).header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JWT);
            } catch (RuntimeException re) {
                logger.error(LOGGER_PREFIX + "Internal server error: " + re.getMessage());
                throw error.status(Response.Status.INTERNAL_SERVER_ERROR).build();
            }
            event.detail(Details.SIGNATURE_REQUIRED, "true");
            event.detail(Details.SIGNATURE_ALGORITHM, cfg.getUserInfoSignedResponseAlg());
        } else if (cfg.isUserInfoEncryptionRequired()) {
            try {
                responseBuilder = Response.ok(jweFromContent(JsonSerialization.writeValueAsString(claims), null))
                        .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JWT);
            } catch (RuntimeException | IOException ex) {
                logger.error(LOGGER_PREFIX + "Internal server error: " + ex.getMessage());
                throw error.status(Response.Status.INTERNAL_SERVER_ERROR).build();
            }

            event.detail(Details.SIGNATURE_REQUIRED, "false");
        } else {
            responseBuilder = Response.ok(claims).header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON);

            event.detail(Details.SIGNATURE_REQUIRED, "false");
        }

        event.success();

        logger.info(LOGGER_PREFIX + "Exiting issueUserInfo");

        return cors.builder(responseBuilder).build();
    }

    private String jweFromContent(String content, String jweContentType) {
        logger.info(LOGGER_PREFIX + "Entering jweFromContent with content: " + content + " and jweContentType: " + jweContentType);
        String encryptedToken;

        String algAlgorithm = session.tokens().cekManagementAlgorithm(TokenCategory.USERINFO);
        String encAlgorithm = session.tokens().encryptAlgorithm(TokenCategory.USERINFO);

        CekManagementProvider cekManagementProvider = session.getProvider(CekManagementProvider.class, algAlgorithm);
        JWEAlgorithmProvider jweAlgorithmProvider = cekManagementProvider.jweAlgorithmProvider();

        ContentEncryptionProvider contentEncryptionProvider = session.getProvider(ContentEncryptionProvider.class, encAlgorithm);
        JWEEncryptionProvider jweEncryptionProvider = contentEncryptionProvider.jweEncryptionProvider();

        ClientModel client = session.getContext().getClient();

        KeyWrapper keyWrapper = PublicKeyStorageManager.getClientPublicKeyWrapper(session, client, JWK.Use.ENCRYPTION, algAlgorithm);
        if (keyWrapper == null) {
            logger.error(LOGGER_PREFIX + "Can not get encryption KEK");
            throw new RuntimeException("Can not get encryption KEK");
        }
        Key encryptionKek = keyWrapper.getPublicKey();
        String encryptionKekId = keyWrapper.getKid();
        try {
            encryptedToken = TokenUtil.jweKeyEncryptionEncode(encryptionKek, content.getBytes(StandardCharsets.UTF_8), algAlgorithm,
                    encAlgorithm, encryptionKekId, jweAlgorithmProvider, jweEncryptionProvider, jweContentType);
        } catch (JWEException e) {
            logger.error(LOGGER_PREFIX + "Error during JWE encryption: " + e.getMessage());
            throw new RuntimeException(e);
        }
        logger.info(LOGGER_PREFIX + "Exiting jweFromContent with encryptedToken: " + encryptedToken);
        return encryptedToken;
    }

    private void checkAccessTokenDuplicated(MultivaluedMap<String, String> formParams) {
        logger.info(LOGGER_PREFIX + "Entering checkAccessTokenDuplicated with formParams: " + formParams);
        if (formParams.containsKey(OAuth2Constants.ACCESS_TOKEN) && formParams.get(OAuth2Constants.ACCESS_TOKEN).size() != 1) {
            logger.error(LOGGER_PREFIX + "Duplicate access token parameter detected");
            throw error.invalidRequest("Duplicate parameter");
        }
        logger.info(LOGGER_PREFIX + "Exiting checkAccessTokenDuplicated");
    }

    private void setupCors() {
        logger.info(LOGGER_PREFIX + "Entering setupCors");
        cors = Cors.add(session.getContext().getHttpRequest());
        cors.auth()
                .allowedMethods(session.getContext().getHttpRequest().getHttpMethod())
                .exposedHeaders(Cors.ACCESS_CONTROL_ALLOW_METHODS);
        error.cors(cors);
        logger.info(LOGGER_PREFIX + "Exiting setupCors");
    }

    private void authorization(String accessToken) {
        logger.info(LOGGER_PREFIX + "Entering authorization with accessToken: " + accessToken);
        if (accessToken != null) {
            if (tokenForUserInfo.getToken() == null) {
                tokenForUserInfo.setToken(accessToken);
                logger.info(LOGGER_PREFIX + "Access token set: " + accessToken);
            } else {
                logger.error(LOGGER_PREFIX + "More than one method used for including an access token");
                throw error.cors(cors.allowAllOrigins()).invalidRequest("More than one method used for including an access token");
            }
        }
        logger.info(LOGGER_PREFIX + "Exiting authorization");
    }

    public void tokenIsExpired(AccessToken accessToken, EventBuilder event) {
        long now = System.nanoTime() / 1000;
        if (accessToken.getExp() <= now) {
            logger.info(LOGGER_PREFIX + "User token is expired");
            event.error(Errors.SESSION_EXPIRED);
        }
    }

    public static class TokenForUserInfo extends UserInfoEndpoint.TokenForUserInfo {

        private String token;

        public String getToken() {
            return token;
        }

        public void setToken(String token) {
            this.token = token;
        }
    }
}