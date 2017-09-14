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

import com.cloudbees.hudson.plugins.folder.Folder;
import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import hudson.model.FreeStyleProject;
import hudson.model.Hudson;
import hudson.model.Item;
import hudson.model.User;
import hudson.security.ACL;
import hudson.security.ACLContext;
import hudson.security.HudsonPrivateSecurityRealm;
import hudson.security.ProjectMatrixAuthorizationStrategy;
import java.util.concurrent.Callable;

import jenkins.model.Jenkins;
import org.acegisecurity.AccessDeniedException;
import static org.junit.Assert.*;

import org.junit.Assert;
import org.jenkinsci.plugins.matrixauth.inheritance.InheritParentStrategy;
import org.jenkinsci.plugins.matrixauth.inheritance.NonInheritingStrategy;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

public class AuthorizationMatrixPropertyTest {

    @Rule public JenkinsRule r = new JenkinsRule();

    @Test
    public void ensureCreatorHasPermissions() throws Exception {
        HudsonPrivateSecurityRealm realm = new HudsonPrivateSecurityRealm(false);
        realm.createAccount("alice","alice");
        realm.createAccount("bob","bob");
        r.jenkins.setSecurityRealm(realm);

        ProjectMatrixAuthorizationStrategy authorizationStrategy = new ProjectMatrixAuthorizationStrategy();
        authorizationStrategy.add(Item.CREATE, "alice");
        authorizationStrategy.add(Jenkins.READ, "alice");
        r.jenkins.setAuthorizationStrategy(authorizationStrategy);
        
        Folder job;
        try (ACLContext _ = ACL.as(User.get("alice"))) {
            job = r.createProject(Folder.class);
        }

        Assert.assertNotNull(job.getProperties().get(AuthorizationMatrixProperty.class));
        Assert.assertTrue(job.getACL().hasPermission(User.get("alice").impersonate(), Item.READ));
        Assert.assertFalse(job.getACL().hasPermission(User.get("bob").impersonate(), Item.READ));
        Assert.assertTrue(job.getACL().hasPermission(User.get("alice").impersonate(), Item.CONFIGURE));
    }

    @Test public void basics1() throws Exception {
        HudsonPrivateSecurityRealm realm = new HudsonPrivateSecurityRealm(false);
        realm.createAccount("alice","alice");
        realm.createAccount("bob","bob");
        r.jenkins.setSecurityRealm(realm);

        ProjectMatrixAuthorizationStrategy as = new ProjectMatrixAuthorizationStrategy();
        r.jenkins.setAuthorizationStrategy(as);
        as.add(Hudson.READ,"authenticated");

        Folder f = r.jenkins.createProject(Folder.class, "d");
        AuthorizationMatrixProperty amp = new AuthorizationMatrixProperty();

        assertTrue(amp.getInheritanceStrategy() instanceof InheritParentStrategy);

        amp.add(Item.READ,"alice");
        amp.add(Item.BUILD,"alice");
        f.getProperties().add(amp);

        final FreeStyleProject foo = f.createProject(FreeStyleProject.class, "foo");

        JenkinsRule.WebClient wc = r.createWebClient().login("bob");
        try {
            wc.getPage(foo);
            fail();
        } catch (FailingHttpStatusCodeException e) {
            assertEquals(404, e.getStatusCode());
        }

        wc = r.createWebClient().login("alice");
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

    @Test public void disabling_permission_inheritance_removes_global_permissions() throws Exception {
        HudsonPrivateSecurityRealm realm = new HudsonPrivateSecurityRealm(false);
        realm.createAccount("alice","alice");
        realm.createAccount("bob","bob");
        r.jenkins.setSecurityRealm(realm);

        ProjectMatrixAuthorizationStrategy as = new ProjectMatrixAuthorizationStrategy();
        r.jenkins.setAuthorizationStrategy(as);
        as.add(Hudson.READ,"authenticated");

        Folder f = r.jenkins.createProject(Folder.class, "d");
        AuthorizationMatrixProperty amp = new AuthorizationMatrixProperty();
        amp.setInheritanceStrategy(new NonInheritingStrategy());
        amp.add(Item.READ,"alice");
        f.getProperties().add(amp);

        final FreeStyleProject foo = f.createProject(FreeStyleProject.class, "foo");

        JenkinsRule.WebClient wc = r.createWebClient().login("bob");
        try {
            wc.getPage(foo);
            fail();
        } catch (FailingHttpStatusCodeException e) {
            assertEquals(404, e.getStatusCode());
        }

        wc = r.createWebClient().login("alice");
        wc.getPage(foo);    // this should succeed
    }
}
