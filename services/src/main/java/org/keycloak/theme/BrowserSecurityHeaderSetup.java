/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.theme;

import org.keycloak.common.util.Base64;
import org.keycloak.models.BrowserSecurityHeaders;
import org.keycloak.models.RealmModel;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.util.Arrays.asList;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class BrowserSecurityHeaderSetup {
    private static final SecureRandom secureRandom = new SecureRandom();

    private static final int NONCE_LENGTH_BYTES = 18;

    private static final String CSP_REQUEST_HEADER_NAME = "Content-Security-Policy";
    private static final String CSP_NONE_VALUE = "'none'";

    private static final Predicate<String> NOT_EMPTY = v -> !v.isEmpty();
    private static final Set<String> CSP_DIRECTIVES_WITH_NONCE_SUPPORT = new HashSet<>(asList(
            "base-uri-src",
            "connect-src",
            "default-src",
            "font-src",
            "form-action",
            "frame-src",
            "img-src",
            "manifest-src",
            "media-src",
            "object-src",
            "script-src",
            "style-src",
            "worker-src"
    ));

    private final String cspNonce;

    private BrowserSecurityHeaderSetup(String cspNonce) {
        this.cspNonce = cspNonce;
    }

    public static BrowserSecurityHeaderSetup withCspNonce() {
        return new BrowserSecurityHeaderSetup(generateCspNonce());
    }

    public static BrowserSecurityHeaderSetup withoutCspNonce() {
        return new BrowserSecurityHeaderSetup(null);
    }

    public void injectCspNonce(MultivaluedMap<String, Object> headers) {
        if (cspNonce == null) {
            return;
        }
        final List<Object> cspHeaders = headers.get(CSP_REQUEST_HEADER_NAME);
        if (cspHeaders != null && cspHeaders.size() > 0) {
            final String firstCSPHeader = String.valueOf(cspHeaders.get(0));
            cspHeaders.set(0, injectCspNonce(firstCSPHeader));
        }
    }

    public Response.ResponseBuilder headers(Response.ResponseBuilder builder, RealmModel realm) {
        return headers(builder, realm.getBrowserSecurityHeaders());
    }

    public Response.ResponseBuilder headers(Response.ResponseBuilder builder, Map<String, String> headers) {
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            String headerName = BrowserSecurityHeaders.headerAttributeMap.get(entry.getKey());
            if (headerName != null && entry.getValue() != null && entry.getValue().length() > 0) {
                if (CSP_REQUEST_HEADER_NAME.equals(headerName) && cspNonce != null) {
                    builder.header(headerName, injectCspNonce(entry.getValue()));
                } else {
                    builder.header(headerName, entry.getValue());
                }
            }
        }
        return builder;
    }

    public String getCspNonce() {
        return cspNonce;
    }

    private String injectCspNonce(String originalCspHeader) {
        return Stream.of(originalCspHeader.split(";"))
                .map(String::trim)
                .filter(NOT_EMPTY)
                .map(v -> v.split(" ", 2))
                .map(v -> {
                    final String cspDirective = v[0].trim();
                    final String cspDirectiveValue = v[1].trim();
                    if (!CSP_DIRECTIVES_WITH_NONCE_SUPPORT.contains(cspDirective)) {
                        return cspDirective + " " + cspDirectiveValue;
                    } else if (CSP_NONE_VALUE.equals(cspDirectiveValue)) {
                        return cspDirective + " 'nonce-" + cspNonce + "'";
                    } else {
                        return cspDirective + " 'nonce-" + cspNonce + "' " + cspDirectiveValue;
                    }
                })
                .collect(Collectors.joining("; "));
    }

    private static String generateCspNonce() {
        final byte[] randomNonceBytes = new byte[NONCE_LENGTH_BYTES];
        secureRandom.nextBytes(randomNonceBytes);
        return Base64.encodeBytes(randomNonceBytes);
    }
}
