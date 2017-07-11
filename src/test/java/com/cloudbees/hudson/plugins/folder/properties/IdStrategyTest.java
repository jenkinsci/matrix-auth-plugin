package com.cloudbees.hudson.plugins.folder.properties;

import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import hudson.model.FreeStyleProject;
import hudson.model.Hudson;
import hudson.model.Item;
import hudson.security.HudsonPrivateSecurityRealm;
import hudson.security.ProjectMatrixAuthorizationStrategy;
import java.util.concurrent.Callable;
import jenkins.model.IdStrategy;
import org.acegisecurity.AccessDeniedException;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class IdStrategyTest {
    private static final IdStrategy.CaseSensitive CASE_SENSITIVE = new IdStrategy.CaseSensitive();
    @Rule
    public JenkinsRule r = new JenkinsRule();

    @Test
    public void insensitive() throws Exception {
        HudsonPrivateSecurityRealm realm = new HudsonPrivateSecurityRealm(false, false, null) {
            @Override
            public IdStrategy getUserIdStrategy() {
                return IdStrategy.CASE_INSENSITIVE;
            }

            @Override
            public IdStrategy getGroupIdStrategy() {
                return IdStrategy.CASE_INSENSITIVE;
            }
        };
        realm.createAccount("alice", "alice");
        r.jenkins.setSecurityRealm(realm);

        ProjectMatrixAuthorizationStrategy as = new ProjectMatrixAuthorizationStrategy();
        r.jenkins.setAuthorizationStrategy(as);
        as.add(Hudson.READ, "authenticated");
        as.add(Item.READ, "alicE");
        as.add(Item.BUILD, "aLice");

        final FreeStyleProject foo = r.createProject(FreeStyleProject.class, "foo");

        JenkinsRule.WebClient wc = r.createWebClient().login("alice");
        wc.getPage(foo);    // this should succeed

        // and build permission should be set, too
        wc.executeOnServer(new Callable<Object>() {
            public Object call() throws Exception {
                foo.checkPermission(Item.BUILD);
                try {
                    foo.checkPermission(Item.DELETE);
                    fail("acecss should be denied");
                } catch (AccessDeniedException e) {
                    // expected
                }
                return null;
            }
        });

        try {
            r.createWebClient().login("AliCe");
            fail();
        } catch (FailingHttpStatusCodeException e) {
            assertEquals(401, e.getStatusCode());
        }

        // now logging with the username case incorrect should still authenticate as the password is a match
        wc = r.createWebClient().login("AliCe", "alice");
        wc.getPage(foo);    // this should succeed

        // and build permission should be set, too
        wc.executeOnServer(new Callable<Object>() {
            public Object call() throws Exception {
                foo.checkPermission(Item.BUILD);
                try {
                    foo.checkPermission(Item.DELETE);
                    fail("acecss should be denied");
                } catch (AccessDeniedException e) {
                    // expected
                }
                return null;
            }
        });
    }

    @Test
    public void sensitive() throws Exception {
        HudsonPrivateSecurityRealm realm = new HudsonPrivateSecurityRealm(false, false, null) {
            @Override
            public IdStrategy getUserIdStrategy() {
                return CASE_SENSITIVE;
            }

            @Override
            public IdStrategy getGroupIdStrategy() {
                return CASE_SENSITIVE;
            }
        };
        realm.createAccount("alice", "alice");
        r.jenkins.setSecurityRealm(realm);

        ProjectMatrixAuthorizationStrategy as = new ProjectMatrixAuthorizationStrategy();
        r.jenkins.setAuthorizationStrategy(as);
        as.add(Hudson.READ, "authenticated");
        as.add(Item.READ, "alice");
        as.add(Item.BUILD, "alice");

        final FreeStyleProject foo = r.createProject(FreeStyleProject.class, "foo");
        JenkinsRule.WebClient wc = r.createWebClient().login("alice", "alice");
        wc.getPage(foo);    // this should succeed

        // and build permission should be set, too
        wc.executeOnServer(new Callable<Object>() {
            public Object call() throws Exception {
                foo.checkPermission(Item.BUILD);
                try {
                    foo.checkPermission(Item.DELETE);
                    fail("acecss should be denied");
                } catch (AccessDeniedException e) {
                    // expected
                }
                return null;
            }
        });

        try {
            r.createWebClient().login("Alice", "alice");
            fail();
        } catch (FailingHttpStatusCodeException e) {
            assertEquals(401, e.getStatusCode());
        }
    }

}
