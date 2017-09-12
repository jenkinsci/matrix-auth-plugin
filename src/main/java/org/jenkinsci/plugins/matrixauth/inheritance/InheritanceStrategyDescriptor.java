package org.jenkinsci.plugins.matrixauth.inheritance;

import hudson.DescriptorExtensionList;
import hudson.model.Descriptor;
import jenkins.model.Jenkins;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.List;

public abstract class InheritanceStrategyDescriptor extends Descriptor<InheritanceStrategy> {

    public static DescriptorExtensionList<InheritanceStrategy, InheritanceStrategyDescriptor> all() {
        return Jenkins.getInstance().getDescriptorList(InheritanceStrategy.class);
    }

    public static List<InheritanceStrategyDescriptor> getApplicableDescriptors(Class<?> clazz) {
        List<InheritanceStrategyDescriptor> result = new ArrayList<>();
        List<InheritanceStrategyDescriptor> list = all();
        for (InheritanceStrategyDescriptor isd : list) {
            if (isd.isApplicable(clazz)) {
                result.add(isd);
            }
        }
        return result;
    }
    
    public abstract boolean isApplicable(Class<?> clazz);

    @Nonnull
    @Override
    public String getDisplayName() {
        return super.getDisplayName();
    }
}
