package org.jenkinsci.plugins.matrixauth;

import hudson.model.Item;
import hudson.model.Run;
import hudson.security.GlobalMatrixAuthorizationStrategy;
import hudson.util.VersionNumber;
import jenkins.model.Jenkins;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

public class AuthorizationContainerDescriptorTest {

    @Rule
    public JenkinsRule r = new JenkinsRule(); // Needed to check the jenkins version

    @Test
    public void testImpliedNotes() {
        { // no message on Administer
            String description = new GlobalMatrixAuthorizationStrategy.DescriptorImpl().getDescription(Jenkins.ADMINISTER);
            Assert.assertFalse(description.contains(Messages.GlobalMatrixAuthorizationStrategy_PermissionNotImpliedBy()));
            Assert.assertFalse(description.contains(Messages.GlobalMatrixAuthorizationStrategy_PermissionImpliedBy(Jenkins.PERMISSIONS.title.toString(), Jenkins.ADMINISTER.name)));
        }

        { // Run.ARTIFACTS is not implied by other permissions
            String description = new GlobalMatrixAuthorizationStrategy.DescriptorImpl().getDescription(Run.ARTIFACTS);
            Assert.assertTrue(description.contains(Messages.GlobalMatrixAuthorizationStrategy_PermissionNotImpliedBy()));
            Assert.assertFalse(description.contains(Messages.GlobalMatrixAuthorizationStrategy_PermissionImpliedBy(Jenkins.PERMISSIONS.title.toString(), Jenkins.ADMINISTER.name)));
        }

        { // Item.CANCEL is implied by Item.BUILD until 2.119. From 2.120 is implied by Permission.UPDATE, so the description changes.
            String description = new GlobalMatrixAuthorizationStrategy.DescriptorImpl().getDescription(Item.CANCEL);
            Assert.assertFalse(description.contains(Messages.GlobalMatrixAuthorizationStrategy_PermissionNotImpliedBy()));
            Assert.assertEquals(Jenkins.getVersion().isOlderThan(new VersionNumber("2.120")), description.contains(Messages.GlobalMatrixAuthorizationStrategy_PermissionImpliedBy(Item.PERMISSIONS.title.toString(), Item.BUILD.name)));
        }
    }
}
