/*
 * The MIT License
 *
 * Copyright 2017 Daniel Beck
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

package org.jenkinsci.plugins.matrixauth;

import hudson.model.Computer;
import hudson.model.Node;
import hudson.model.User;
import hudson.security.ACL;
import hudson.security.ACLContext;
import hudson.security.HudsonPrivateSecurityRealm;
import hudson.security.ProjectMatrixAuthorizationStrategy;
import java.util.Collections;
import java.util.Objects;
import jenkins.model.Jenkins;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

public class AuthorizationMatrixNodePropertyTest {

    @Rule
    public JenkinsRule r = new JenkinsRule();

    @Test
    public void ensureCreatorHasPermissions() throws Exception {
        HudsonPrivateSecurityRealm realm = new HudsonPrivateSecurityRealm(false, false, null);
        realm.createAccount("alice", "alice");
        realm.createAccount("bob", "bob");
        r.jenkins.setSecurityRealm(realm);

        ProjectMatrixAuthorizationStrategy authorizationStrategy = new ProjectMatrixAuthorizationStrategy();
        authorizationStrategy.add(Computer.CREATE, PermissionEntry.user("alice"));
        authorizationStrategy.add(Jenkins.READ, PermissionEntry.user("alice"));

        addRunScriptsPermission(authorizationStrategy);
        r.jenkins.setAuthorizationStrategy(authorizationStrategy);

        Node node;
        try (ACLContext ignored = ACL.as(User.get("alice", false, Collections.emptyMap()))) {
            node = r.createSlave();
        }

        Assert.assertNotNull(node.getNodeProperty(AuthorizationMatrixNodeProperty.class));
        Assert.assertTrue(node.getACL()
                .hasPermission2(
                        Objects.requireNonNull(User.get("alice", false, Collections.emptyMap()))
                                .impersonate2(),
                        Computer.CONFIGURE));
        Assert.assertFalse(node.getACL()
                .hasPermission2(
                        Objects.requireNonNull(User.get("bob", false, Collections.emptyMap()))
                                .impersonate2(),
                        Computer.CONFIGURE));
    }

    // createSlave uses CommandLauncher, which requires RUN_SCRIPTS since 2.73.2
    @SuppressWarnings("deprecation")
    private void addRunScriptsPermission(ProjectMatrixAuthorizationStrategy authorizationStrategy) {
        authorizationStrategy.add(Jenkins.RUN_SCRIPTS, PermissionEntry.user("alice"));
    }
}
