/*
 * The MIT License
 *
 * Copyright 2013 CloudBees.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package com.cloudbees.hudson.plugins.folder.properties;

import static org.junit.jupiter.api.Assertions.*;

import com.cloudbees.hudson.plugins.folder.Folder;
import hudson.model.FreeStyleProject;
import hudson.model.Hudson;
import hudson.model.Item;
import hudson.model.User;
import hudson.security.ACL;
import hudson.security.ACLContext;
import hudson.security.HudsonPrivateSecurityRealm;
import hudson.security.ProjectMatrixAuthorizationStrategy;
import java.util.Collections;
import java.util.Objects;
import java.util.logging.Level;
import jenkins.model.Jenkins;
import org.htmlunit.FailingHttpStatusCodeException;
import org.jenkinsci.plugins.matrixauth.AuthorizationContainer;
import org.jenkinsci.plugins.matrixauth.PermissionEntry;
import org.jenkinsci.plugins.matrixauth.inheritance.InheritParentStrategy;
import org.jenkinsci.plugins.matrixauth.inheritance.NonInheritingStrategy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.LogRecorder;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class AuthorizationMatrixPropertyTest {

    private final LogRecorder l = new LogRecorder();

    private JenkinsRule j;

    @BeforeEach
    void setUp(JenkinsRule rule) {
        j = rule;
    }

    @Test
    void ensureCreatorHasPermissions() throws Exception {
        HudsonPrivateSecurityRealm realm = new HudsonPrivateSecurityRealm(false, false, null);
        realm.createAccount("alice", "alice");
        realm.createAccount("bob", "bob");
        j.jenkins.setSecurityRealm(realm);

        ProjectMatrixAuthorizationStrategy authorizationStrategy = new ProjectMatrixAuthorizationStrategy();
        authorizationStrategy.add(Item.CREATE, PermissionEntry.user("alice"));
        authorizationStrategy.add(Jenkins.READ, PermissionEntry.user("alice"));
        j.jenkins.setAuthorizationStrategy(authorizationStrategy);

        Folder job;
        try (ACLContext ignored = ACL.as(User.get("alice", false, Collections.emptyMap()))) {
            job = j.createProject(Folder.class);
        }

        assertNotNull(job.getProperties().get(AuthorizationMatrixProperty.class));
        assertTrue(job.getACL()
                .hasPermission2(
                        Objects.requireNonNull(User.get("alice", false, Collections.emptyMap()))
                                .impersonate2(),
                        Item.READ));
        assertFalse(job.getACL()
                .hasPermission2(
                        Objects.requireNonNull(User.get("bob", false, Collections.emptyMap()))
                                .impersonate2(),
                        Item.READ));
        assertTrue(job.getACL()
                .hasPermission2(
                        Objects.requireNonNull(User.get("alice", false, Collections.emptyMap()))
                                .impersonate2(),
                        Item.CONFIGURE));
    }

    @Test
    void basics1() throws Exception {
        HudsonPrivateSecurityRealm realm = new HudsonPrivateSecurityRealm(false, false, null);
        realm.createAccount("alice", "alice");
        realm.createAccount("bob", "bob");
        j.jenkins.setSecurityRealm(realm);

        ProjectMatrixAuthorizationStrategy as = new ProjectMatrixAuthorizationStrategy();
        j.jenkins.setAuthorizationStrategy(as);
        as.add(Hudson.READ, PermissionEntry.group("authenticated"));

        Folder f = j.jenkins.createProject(Folder.class, "d");
        AuthorizationMatrixProperty amp = new AuthorizationMatrixProperty();

        assertInstanceOf(InheritParentStrategy.class, amp.getInheritanceStrategy());

        amp.add(Item.READ, PermissionEntry.user("alice"));
        amp.add(Item.BUILD, PermissionEntry.user("alice"));
        f.getProperties().add(amp);

        final FreeStyleProject foo = f.createProject(FreeStyleProject.class, "foo");

        FailingHttpStatusCodeException e = assertThrows(
                FailingHttpStatusCodeException.class,
                () -> j.createWebClient().login("bob").getPage(foo));
        assertEquals(404, e.getStatusCode());

        JenkinsRule.WebClient wc = j.createWebClient().login("alice");
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
    }

    @Test
    void disabling_permission_inheritance_removes_global_permissions() throws Exception {
        HudsonPrivateSecurityRealm realm = new HudsonPrivateSecurityRealm(false, false, null);
        realm.createAccount("alice", "alice");
        realm.createAccount("bob", "bob");
        j.jenkins.setSecurityRealm(realm);

        ProjectMatrixAuthorizationStrategy as = new ProjectMatrixAuthorizationStrategy();
        j.jenkins.setAuthorizationStrategy(as);
        as.add(Hudson.READ, PermissionEntry.group("authenticated"));

        Folder f = j.jenkins.createProject(Folder.class, "d");
        AuthorizationMatrixProperty amp = new AuthorizationMatrixProperty();
        amp.setInheritanceStrategy(new NonInheritingStrategy());
        amp.add(Item.READ, PermissionEntry.user("alice"));
        f.getProperties().add(amp);

        final FreeStyleProject foo = f.createProject(FreeStyleProject.class, "foo");

        FailingHttpStatusCodeException e = assertThrows(
                FailingHttpStatusCodeException.class,
                () -> j.createWebClient().login("bob").getPage(foo));
        assertEquals(404, e.getStatusCode());

        JenkinsRule.WebClient wc = j.createWebClient().login("alice");
        wc.getPage(foo); // this should succeed
    }

    @Test
    void inapplicablePermissionIsSkipped() {
        AuthorizationMatrixProperty property = new AuthorizationMatrixProperty();
        l.record(AuthorizationContainer.class, Level.WARNING).capture(5);
        property.add("hudson.model.Hudson.Administer:alice");
        assertTrue(property.getGrantedPermissionEntries().isEmpty());
        assertTrue(l.getMessages().stream().anyMatch(m -> m.contains("Tried to add inapplicable permission")));
        assertTrue(l.getMessages().stream().anyMatch(m -> m.contains("Administer")));
        assertTrue(l.getMessages().stream().anyMatch(m -> m.contains("alice")));
    }

    @Test
    void inapplicablePermissionIsSkipped2() {
        AuthorizationMatrixProperty property = new AuthorizationMatrixProperty();
        l.record(AuthorizationContainer.class, Level.WARNING).capture(5);
        property.add("USER:hudson.model.Hudson.Administer:alice");
        assertTrue(property.getGrantedPermissionEntries().isEmpty());
        assertTrue(l.getMessages().stream().anyMatch(m -> m.contains("Tried to add inapplicable permission")));
        assertTrue(l.getMessages().stream().anyMatch(m -> m.contains("Administer")));
        assertTrue(l.getMessages().stream().anyMatch(m -> m.contains("alice")));
    }
}
