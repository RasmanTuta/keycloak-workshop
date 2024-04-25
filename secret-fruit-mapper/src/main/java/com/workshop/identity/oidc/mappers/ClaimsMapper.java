package com.workshop.identity.oidc.mappers;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class ClaimsMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper {
    static Logger LOGGER = LoggerFactory.getLogger(ClaimsMapper.class);
    static Random rand = new Random();

    public static final String PROVIDER_ID = "Secret-Fruit-Mapper";
    private static final List<String> secretFruits = List.of("Strawberry", "Mango", "Dragon Fruit");

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "Secret Fruit Mapper";
    }

    @Override
    public String getHelpText() {
        return "Custom mapper adding a random secret fruit to the access token";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Collections.emptyList();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public AccessToken transformAccessToken(AccessToken token, ProtocolMapperModel mappingModel, KeycloakSession session, UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        token.getOtherClaims().put("secret-fruit", secretFruits.get(rand.nextInt(secretFruits.size())));

        setClaim(token, mappingModel, userSession, session, clientSessionCtx);
        return token;
    }

    public static ProtocolMapperModel create(String name,
                                             boolean accessToken, boolean idToken, boolean userInfo) {
        ProtocolMapperModel mapper = new ProtocolMapperModel();
        mapper.setName(name);
        mapper.setProtocolMapper(PROVIDER_ID);
        mapper.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        Map<String, String> config = new HashMap<String, String>();
        config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true");
        config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "false");
        mapper.setConfig(config);
        return mapper;
    }


}
