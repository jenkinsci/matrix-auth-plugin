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
import hudson.security.HudsonPrivateSecurityRealm;
import hudson.security.ProjectMatrixAuthorizationStrategy;
import java.util.concurrent.Callable;
import org.acegisecurity.AccessDeniedException;
import static org.junit.Assert.*;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

public class AuthorizationMatrixPropertyTest {

    @Rule public JenkinsRule r = new JenkinsRule();

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
    
    /**
     * Tests if folders can be configured not to inherit from their parent folder
     * so that users can be granted read access to a folder, without getting access
     * to all subfolders
     * 
     * @throws Exception 
     */
    @Test public void blocksInheritParent1() throws Exception {
        HudsonPrivateSecurityRealm realm = new HudsonPrivateSecurityRealm(false);
        realm.createAccount("alice","alice");
        realm.createAccount("bob","bob");
        r.jenkins.setSecurityRealm(realm);

        ProjectMatrixAuthorizationStrategy as = new ProjectMatrixAuthorizationStrategy();
        r.jenkins.setAuthorizationStrategy(as);
        as.add(Hudson.READ,"authenticated");

        Folder f = r.jenkins.createProject(Folder.class, "a");
        AuthorizationMatrixProperty amp = new AuthorizationMatrixProperty();
        amp.add(Item.READ,"alice");
        amp.add(Item.READ,"bob");
        amp.add(Item.BUILD,"alice");
        f.getProperties().add(amp);
        
        Folder fb1 = f.createProject(Folder.class, "b1");
        AuthorizationMatrixProperty ampb1 = new AuthorizationMatrixProperty();
        ampb1.setBlocksParentInheritance(true);
        ampb1.add(Item.READ,"alice");
        ampb1.add(Item.BUILD,"alice");
        fb1.getProperties().add(ampb1);
        
        Folder fb2 = f.createProject(Folder.class, "b2");
        AuthorizationMatrixProperty ampb2 = new AuthorizationMatrixProperty();
        fb1.getProperties().add(ampb2);

        final FreeStyleProject foo1 = fb1.createProject(FreeStyleProject.class, "foo1");
        final FreeStyleProject foo2 = fb2.createProject(FreeStyleProject.class, "foo2");

        JenkinsRule.WebClient wc = r.createWebClient().login("bob");
        try {
            wc.getPage(foo1);
            fail();
        } catch (FailingHttpStatusCodeException e) {
            assertEquals(404, e.getStatusCode());
        }
        
        wc.getPage(foo2);    // this should succeed

        wc = r.createWebClient().login("alice");
        wc.getPage(foo1);    // this should succeed
        wc.getPage(foo2);    // this should succeed

        // and build permission should be set, too
        wc.executeOnServer(new Callable<Object>() {
            public Object call() throws Exception {
                foo1.checkPermission(Item.BUILD);
                foo2.checkPermission(Item.BUILD);
                try {
                    foo1.checkPermission(Item.DELETE);
                    fail("acecss should be denied");
                } catch (AccessDeniedException e) {
                    // expected
                }
                try {
                    foo2.checkPermission(Item.DELETE);
                    fail("acecss should be denied");
                } catch (AccessDeniedException e) {
                    // expected
                }
                return null;
            }
        });
    }
}
