package org.jenkinsci.plugins.matrixauth;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import hudson.model.User;
import hudson.security.GlobalMatrixAuthorizationStrategy;
import hudson.security.HudsonPrivateSecurityRealm;
import hudson.security.pages.SignupPage;
import java.util.Collections;
import java.util.Objects;
import jenkins.model.Jenkins;
import org.htmlunit.ElementNotFoundException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.JenkinsSessionExtension;

class PermissionAdderTest {

    @RegisterExtension
    private final JenkinsSessionExtension sessions = new JenkinsSessionExtension();

    @Test
    @Issue("JENKINS-20520")
    void ensureSavingAfterInitialUser() throws Throwable {
        sessions.then(j -> {
            j.jenkins.setSecurityRealm(new HudsonPrivateSecurityRealm(true, false, null));
            j.jenkins.setAuthorizationStrategy(new GlobalMatrixAuthorizationStrategy());
            j.jenkins.save();

            JenkinsRule.WebClient wc = j.createWebClient();
            SignupPage signup = new SignupPage(wc.goTo("signup"));
            signup.enterUsername("alice");
            signup.enterPassword("alice");
            signup.enterFullName("Alice User");
            try {
                signup.enterEmail("alice@nowhere.net");
            } catch (ElementNotFoundException x) {
                // mailer plugin not installed, fine
            }
            signup.submit(j);
            User alice = User.get("alice", false, Collections.emptyMap());
            assertNotNull(alice);
            assertTrue(j.jenkins.getACL().hasPermission2(alice.impersonate2(), Jenkins.ADMINISTER));
        });
        sessions.then(j -> assertTrue(j.jenkins
                .getACL()
                .hasPermission2(
                        Objects.requireNonNull(User.get("alice", false, Collections.emptyMap()))
                                .impersonate2(),
                        Jenkins.ADMINISTER)));
    }
}
