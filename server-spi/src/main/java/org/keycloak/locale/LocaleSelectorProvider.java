package org.keycloak.locale;


import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.Provider;

import java.util.Locale;

public interface LocaleSelectorProvider extends Provider {
    /**
     * Resolve the locale which should be used for the request
     * @param user
     * @return
     */
    Locale resolveLocale(RealmModel realm, UserModel user);
}
