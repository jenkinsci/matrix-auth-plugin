package org.jenkinsci.plugins.matrixauth;

import hudson.security.GlobalMatrixAuthorizationStrategy;
import jenkins.model.Jenkins;
import org.junit.Assert;
import org.junit.Test;

public class AuthorizationContainerDescriptorTest {
    @Test
    public void overallAdministerDescriptionHasNoImpliedNote() {
        String description = new GlobalMatrixAuthorizationStrategy.DescriptorImpl().getDescription(Jenkins.ADMINISTER);
        Assert.assertFalse(description.contains(Messages.GlobalMatrixAuthorizationStrategy_PermissionNotImpliedBy()));
        Assert.assertFalse(description.contains(Messages.GlobalMatrixAuthorizationStrategy_PermissionImpliedBy(Jenkins.PERMISSIONS.title.toString(), Jenkins.ADMINISTER.name)));
    }
}
