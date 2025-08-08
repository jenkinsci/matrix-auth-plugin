package org.jenkinsci.plugins.matrixauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.security.GlobalMatrixAuthorizationStrategy;
import jenkins.model.Jenkins;
import org.htmlunit.html.HtmlPage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class Jenkins57313Test {

    private JenkinsRule j;

    @BeforeEach
    void setUp(JenkinsRule rule) {
        j = rule;
    }

    @Test
    @Issue("JENKINS-57313")
    void testFormValidation() throws Exception {
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        GlobalMatrixAuthorizationStrategy authorizationStrategy = new GlobalMatrixAuthorizationStrategy();
        authorizationStrategy.add(Jenkins.ADMINISTER, "anonymous");
        j.jenkins.setAuthorizationStrategy(authorizationStrategy);
        HtmlPage page = j.createWebClient()
                .goTo(authorizationStrategy.getDescriptor().getDescriptorUrl() + "/checkName?value=[USER:alice]");
        assertEquals(200, page.getWebResponse().getStatusCode());
        String responseText = page.getWebResponse().getContentAsString();
        assertTrue(responseText.contains("alice"));
        assertTrue(responseText.contains("User"));
    }
}
