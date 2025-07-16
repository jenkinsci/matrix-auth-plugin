package com.cloudbees.hudson.plugins.folder.properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import hudson.model.FreeStyleProject;
import hudson.model.Hudson;
import hudson.model.Item;
import hudson.security.HudsonPrivateSecurityRealm;
import hudson.security.ProjectMatrixAuthorizationStrategy;
import jenkins.model.IdStrategy;
import org.htmlunit.FailingHttpStatusCodeException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class IdStrategyTest {

    private static final IdStrategy.CaseSensitive CASE_SENSITIVE = new IdStrategy.CaseSensitive();

    private JenkinsRule j;

    @BeforeEach
    void setUp(JenkinsRule rule) {
        j = rule;
    }

    private static class CaseInsensitiveSecurityRealm extends HudsonPrivateSecurityRealm {
        CaseInsensitiveSecurityRealm() {
            super(false, false, null);
        }

        @Override
        public IdStrategy getUserIdStrategy() {
            return IdStrategy.CASE_INSENSITIVE;
        }

        @Override
        public IdStrategy getGroupIdStrategy() {
            return IdStrategy.CASE_INSENSITIVE;
        }
    }

    private static class CaseSensitiveSecurityRealm extends HudsonPrivateSecurityRealm {
        CaseSensitiveSecurityRealm() {
            super(false, false, null);
        }

        @Override
        public IdStrategy getUserIdStrategy() {
            return CASE_SENSITIVE;
        }

        @Override
        public IdStrategy getGroupIdStrategy() {
            return CASE_SENSITIVE;
        }
    }

    @Test
    void insensitive() throws Exception {
        HudsonPrivateSecurityRealm realm = new CaseInsensitiveSecurityRealm();
        realm.createAccount("alice", "alice");
        j.jenkins.setSecurityRealm(realm);

        ProjectMatrixAuthorizationStrategy as = new ProjectMatrixAuthorizationStrategy();
        j.jenkins.setAuthorizationStrategy(as);
        as.add(Hudson.READ, "authenticated");
        as.add(Item.READ, "alicE");
        as.add(Item.BUILD, "aLice");

        final FreeStyleProject foo = j.createProject(FreeStyleProject.class, "foo");

        JenkinsRule.WebClient wc = j.createWebClient().login("alice");
        wc.getPage(foo); // this should succeed

        // and build permission should be set, too
        wc.executeOnServer(() -> {
            foo.checkPermission(Item.BUILD);
            try {
                foo.checkPermission(Item.DELETE);
                fail("access should be denied");
            } catch (RuntimeException x) {
                assertEquals(
                        hudson.security.Messages.AccessDeniedException2_MissingPermission("alice", "Job/Delete"),
                        x.getMessage());
            }
            return null;
        });

        FailingHttpStatusCodeException e = assertThrows(
                FailingHttpStatusCodeException.class, () -> j.createWebClient().login("AliCe"));
        assertEquals(401, e.getStatusCode());

        // now logging with the username case incorrect should still authenticate as the password is a match
        wc = j.createWebClient().login("AliCe", "alice");
        wc.getPage(foo); // this should succeed

        // and build permission should be set, too
        wc.executeOnServer(() -> {
            foo.checkPermission(Item.BUILD);
            try {
                foo.checkPermission(Item.DELETE);
                fail("access should be denied");
            } catch (RuntimeException x) {
                assertEquals(
                        hudson.security.Messages.AccessDeniedException2_MissingPermission("alice", "Job/Delete"),
                        x.getMessage());
            }
            return null;
        });
    }

    @Test
    void sensitive() throws Exception {
        HudsonPrivateSecurityRealm realm = new CaseSensitiveSecurityRealm();
        realm.createAccount("alice", "alice");
        j.jenkins.setSecurityRealm(realm);

        ProjectMatrixAuthorizationStrategy as = new ProjectMatrixAuthorizationStrategy();
        j.jenkins.setAuthorizationStrategy(as);
        as.add(Hudson.READ, "authenticated");
        as.add(Item.READ, "alice");
        as.add(Item.BUILD, "alice");

        final FreeStyleProject foo = j.createProject(FreeStyleProject.class, "foo");
        JenkinsRule.WebClient wc = j.createWebClient().login("alice", "alice");
        wc.getPage(foo); // this should succeed

        // and build permission should be set, too
        wc.executeOnServer(() -> {
            foo.checkPermission(Item.BUILD);
            RuntimeException x = assertThrows(
                    RuntimeException.class, () -> foo.checkPermission(Item.DELETE), "access should be denied");
            assertEquals(
                    hudson.security.Messages.AccessDeniedException2_MissingPermission("alice", "Job/Delete"),
                    x.getMessage());
            return null;
        });

        FailingHttpStatusCodeException e = assertThrows(
                FailingHttpStatusCodeException.class, () -> j.createWebClient().login("Alice", "alice"));
        assertEquals(401, e.getStatusCode());
    }
}
