package org.jenkinsci.plugins.matrixauth;

import com.gargoylesoftware.htmlunit.html.HtmlPage;
import hudson.model.User;
import hudson.security.ACL;
import hudson.security.ACLContext;
import hudson.security.GlobalMatrixAuthorizationStrategy;
import hudson.security.HudsonPrivateSecurityRealm;
import hudson.security.pages.SignupPage;
import jenkins.model.Jenkins;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runners.model.Statement;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.RestartableJenkinsRule;

public class PermissionAdderTest {

    @Rule
    public RestartableJenkinsRule r = new RestartableJenkinsRule();

    @Test
    @Issue("JENKINS-20520")
    public void ensureSavingAfterInitialUser() {
        r.addStep(new Statement() {
            @Override
            public void evaluate() throws Throwable {
                r.j.jenkins.setSecurityRealm(new HudsonPrivateSecurityRealm(true));
                r.j.jenkins.setAuthorizationStrategy(new GlobalMatrixAuthorizationStrategy());
                r.j.jenkins.save();

                JenkinsRule.WebClient wc = r.j.createWebClient();
                SignupPage signup = new SignupPage(wc.goTo("signup"));
                signup.enterUsername("alice");
                signup.enterPassword("alice");
                signup.enterFullName("Alice User");
                HtmlPage success = signup.submit(r.j);

                Assert.assertTrue(r.j.jenkins.getACL().hasPermission(User.get("alice").impersonate(), Jenkins.ADMINISTER));
            }
        });
        r.addStep(new Statement() {
            @Override
            public void evaluate() throws Throwable {
                Assert.assertTrue(r.j.jenkins.getACL().hasPermission(User.get("alice").impersonate(), Jenkins.ADMINISTER));
            }
        });
    }
}
