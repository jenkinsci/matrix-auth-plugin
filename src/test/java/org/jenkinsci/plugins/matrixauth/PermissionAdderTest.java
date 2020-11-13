package org.jenkinsci.plugins.matrixauth;

import hudson.model.User;
import hudson.security.GlobalMatrixAuthorizationStrategy;
import hudson.security.HudsonPrivateSecurityRealm;
import hudson.security.pages.SignupPage;
import jenkins.model.Jenkins;

import java.util.Collections;

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
                r.j.jenkins.setSecurityRealm(new HudsonPrivateSecurityRealm(true, false, null));
                r.j.jenkins.setAuthorizationStrategy(new GlobalMatrixAuthorizationStrategy());
                r.j.jenkins.save();

                JenkinsRule.WebClient wc = r.j.createWebClient();
                SignupPage signup = new SignupPage(wc.goTo("signup"));
                signup.enterUsername("alice");
                signup.enterPassword("alice");
                signup.enterFullName("Alice User");
                signup.enterEmail("alice@nowhere.net");
                signup.submit(r.j);
                User alice = User.get("alice", false, Collections.emptyMap());
                Assert.assertNotNull(alice);
                Assert.assertTrue(r.j.jenkins.getACL().hasPermission(alice.impersonate(), Jenkins.ADMINISTER));
            }
        });
        r.addStep(new Statement() {
            @Override
            public void evaluate() throws Throwable {
                Assert.assertTrue(r.j.jenkins.getACL().hasPermission(User.get("alice", false, Collections.emptyMap()).impersonate(), Jenkins.ADMINISTER));
            }
        });
    }
}
