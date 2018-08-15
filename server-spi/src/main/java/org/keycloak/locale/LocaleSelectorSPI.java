package org.keycloak.locale;

import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

public class LocaleSelectorSPI implements Spi {

    @Override
    public boolean isInternal() {
        return false;
    }

    @Override
    public String getName() {
        return "localeSelector";
    }

    @Override
    public Class<? extends Provider> getProviderClass() {
        return LocaleSelectorProvider.class;
    }

    @Override
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return LocaleSelectorProviderFactory.class;
    }

}
