package ru.commit.session;

import org.jboss.logging.Logger;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserSessionModel;

public class UserSessionEventListenerProvider implements EventListenerProvider {
    private static final Logger logger = Logger.getLogger(UserSessionEventListenerProvider.class);
    private static final String PREFIX = "UserSessionEventListener: ";
    private final KeycloakSession session;

    public UserSessionEventListenerProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void onEvent(Event event) {
        var type = event.getType();
        if (type == EventType.LOGIN || type == EventType.LOGOUT) {
            logger.info(PREFIX + "RECEIVED USER %s EVENT".formatted(event.getType()));
            UserSessionModel sessionModel = session.sessions().getUserSession(session.realms().getRealm(event.getRealmId()), event.getSessionId());
            if (sessionModel != null) {
                logger.info(PREFIX + "UserSessionModel state: " + sessionModel.getState());
                logger.info(PREFIX + "Session id: " + sessionModel.getId());
                logger.info(PREFIX + "User id: " + sessionModel.getUser().getId());
                if (!event.getDetails().isEmpty()) {
                    logger.info(PREFIX + "Event details:");
                    for (var entry : event.getDetails().entrySet()) {
                        logger.info(PREFIX + entry.getKey() + " : " + entry.getValue());
                    }
                }
                logger.info(PREFIX + "EXITING USER %s EVENT".formatted(event.getType()));
            }
        }
    }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
        var isSessionEvent = event.getResourceType() == ResourceType.USER_SESSION;
        if (isSessionEvent) {
            var sessionId = event.getResourcePath().replace("sessions/", "");
            UserSessionModel sessionModel = session.sessions().getUserSession(session.realms().getRealm(event.getRealmId()), sessionId);

            logger.info(PREFIX + "RECEIVED ADMIN EVENT");
            logger.info(PREFIX + "Event type: " + event.getResourceType());
            logger.info(PREFIX + "Resource path: " + event.getResourcePath());
            logger.info(PREFIX + "Operation type: " + event.getOperationType());
            logger.info(PREFIX + "Session id: " + sessionId);

            if (sessionModel != null) {
                logger.info(PREFIX + "UserSessionModel state: " + sessionModel.getState());
                logger.info(PREFIX + "User id: " + sessionModel.getUser().getId());
            }
            if (event.getError() != null) {
                logger.info(PREFIX + "Error: " + event.getError());
            }
            logger.info(PREFIX + "EXITING ADMIN EVENT");
        }
    }

    @Override
    public void close() {
    }
}
