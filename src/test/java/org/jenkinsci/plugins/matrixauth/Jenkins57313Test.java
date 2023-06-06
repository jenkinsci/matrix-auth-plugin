package org.jenkinsci.plugins.matrixauth;

import hudson.security.GlobalMatrixAuthorizationStrategy;
import jenkins.model.Jenkins;
import org.htmlunit.html.HtmlPage;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;

public class Jenkins57313Test {
    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Test
    @Issue("JENKINS-57313")
    public void testFormValidation() throws Exception {
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        GlobalMatrixAuthorizationStrategy authorizationStrategy = new GlobalMatrixAuthorizationStrategy();
        authorizationStrategy.add(Jenkins.ADMINISTER, "anonymous");
        j.jenkins.setAuthorizationStrategy(authorizationStrategy);
        HtmlPage page = j.createWebClient()
                .goTo(authorizationStrategy.getDescriptor().getDescriptorUrl() + "/checkName?value=[USER:alice]");
        Assert.assertEquals(200, page.getWebResponse().getStatusCode());
        String responseText = page.getWebResponse().getContentAsString();
        Assert.assertTrue(responseText.contains("alice"));
        Assert.assertTrue(responseText.contains("person"));
    }
}
