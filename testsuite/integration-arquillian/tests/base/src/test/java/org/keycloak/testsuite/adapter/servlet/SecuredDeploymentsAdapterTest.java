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

package org.keycloak.testsuite.adapter.servlet;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.graphene.page.Page;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Test;
import org.keycloak.testsuite.adapter.AbstractServletsAdapterTest;
import org.keycloak.testsuite.adapter.filter.AdapterActionsFilter;
import org.keycloak.testsuite.adapter.page.CustomerDb;
import org.keycloak.testsuite.adapter.page.CustomerPortalSubsystem;
import org.keycloak.testsuite.adapter.page.ProductPortalSubsystem;
import org.keycloak.testsuite.arquillian.annotation.AppServerContainer;
import org.keycloak.testsuite.arquillian.containers.ContainerConstants;

import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertThat;
import static org.keycloak.testsuite.util.URLAssert.assertCurrentUrlEquals;
import static org.keycloak.testsuite.util.URLAssert.assertCurrentUrlStartsWithLoginUrlOf;

@AppServerContainer(ContainerConstants.APP_SERVER_WILDFLY)
@AppServerContainer(ContainerConstants.APP_SERVER_EAP)
@AppServerContainer(ContainerConstants.APP_SERVER_EAP6)
public class SecuredDeploymentsAdapterTest extends AbstractServletsAdapterTest {

    @Page
    private CustomerPortalSubsystem customerPortalSubsystem;

    @Page
    private ProductPortalSubsystem productPortalSubsystem;

    @Deployment(name = CustomerPortalSubsystem.DEPLOYMENT_NAME)
    protected static WebArchive customerPortalSubsystem() {
        return servletDeployment(CustomerPortalSubsystem.DEPLOYMENT_NAME, CustomerServlet.class, ErrorServlet.class, ServletTestUtils.class);
    }

    @Deployment(name = ProductPortalSubsystem.DEPLOYMENT_NAME)
    protected static WebArchive productPortalSubsystem() {
        return servletDeployment(ProductPortalSubsystem.DEPLOYMENT_NAME, ProductServlet.class);
    }

    @Deployment(name = CustomerDb.DEPLOYMENT_NAME)
    protected static WebArchive customerDb() {
        return servletDeployment(CustomerDb.DEPLOYMENT_NAME, AdapterActionsFilter.class, CustomerDatabaseServlet.class);
    }

    @Test
    public void testSecuredDeployments() {
        customerPortalSubsystem.navigateTo();
        assertCurrentUrlStartsWithLoginUrlOf(testRealmPage);
        testRealmLoginPage.form().login("bburke@redhat.com", "password");
        assertPageContains("Bill Burke");
        assertPageContains("Stian Thorgersen");

        productPortalSubsystem.navigateTo();
        assertCurrentUrlEquals(productPortalSubsystem);
        assertPageContains("iPhone");
        assertPageContains("iPad");
    }

    private void assertPageContains(String string) {
        String pageSource = driver.getPageSource();
        assertThat(pageSource, containsString(string));
    }
}
