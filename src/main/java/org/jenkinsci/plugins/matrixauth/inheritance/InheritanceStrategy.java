package org.jenkinsci.plugins.matrixauth.inheritance;

import hudson.ExtensionPoint;
import hudson.model.AbstractDescribableImpl;
import hudson.security.ACL;
import hudson.security.AccessControlled;

public abstract class InheritanceStrategy extends AbstractDescribableImpl<InheritanceStrategy> implements ExtensionPoint {
    @Override
    public InheritanceStrategyDescriptor getDescriptor() {
        return (InheritanceStrategyDescriptor) super.getDescriptor();
    }

    public abstract ACL getEffectiveACL(ACL acl, AccessControlled subject);
}
