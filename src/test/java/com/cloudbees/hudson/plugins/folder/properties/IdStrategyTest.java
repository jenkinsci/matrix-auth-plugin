package com.cloudbees.hudson.plugins.folder.properties;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import hudson.model.FreeStyleProject;
import hudson.model.Hudson;
import hudson.model.Item;
import hudson.security.HudsonPrivateSecurityRealm;
import hudson.security.ProjectMatrixAuthorizationStrategy;
import jenkins.model.IdStrategy;
import org.htmlunit.FailingHttpStatusCodeException;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

public class IdStrategyTest {
    private static final IdStrategy.CaseSensitive CASE_SENSITIVE = new IdStrategy.CaseSensitive();

    @Rule
    public JenkinsRule r = new JenkinsRule();

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
    public void insensitive() throws Exception {
        HudsonPrivateSecurityRealm realm = new CaseInsensitiveSecurityRealm();
        realm.createAccount("alice", "alice");
        r.jenkins.setSecurityRealm(realm);

        ProjectMatrixAuthorizationStrategy as = new ProjectMatrixAuthorizationStrategy();
        r.jenkins.setAuthorizationStrategy(as);
        as.add(Hudson.READ, "authenticated");
        as.add(Item.READ, "alicE");
        as.add(Item.BUILD, "aLice");

        final FreeStyleProject foo = r.createProject(FreeStyleProject.class, "foo");

        JenkinsRule.WebClient wc = r.createWebClient().login("alice");
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

        try {
            r.createWebClient().login("AliCe");
            fail();
        } catch (FailingHttpStatusCodeException e) {
            assertEquals(401, e.getStatusCode());
        }

        // now logging with the username case incorrect should still authenticate as the password is a match
        wc = r.createWebClient().login("AliCe", "alice");
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
    public void sensitive() throws Exception {
        HudsonPrivateSecurityRealm realm = new CaseSensitiveSecurityRealm();
        realm.createAccount("alice", "alice");
        r.jenkins.setSecurityRealm(realm);

        ProjectMatrixAuthorizationStrategy as = new ProjectMatrixAuthorizationStrategy();
        r.jenkins.setAuthorizationStrategy(as);
        as.add(Hudson.READ, "authenticated");
        as.add(Item.READ, "alice");
        as.add(Item.BUILD, "alice");

        final FreeStyleProject foo = r.createProject(FreeStyleProject.class, "foo");
        JenkinsRule.WebClient wc = r.createWebClient().login("alice", "alice");
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

        try {
            r.createWebClient().login("Alice", "alice");
            fail();
        } catch (FailingHttpStatusCodeException e) {
            assertEquals(401, e.getStatusCode());
        }
    }
}
