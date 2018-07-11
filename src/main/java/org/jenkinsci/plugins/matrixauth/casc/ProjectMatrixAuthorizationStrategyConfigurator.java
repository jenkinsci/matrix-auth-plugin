package org.jenkinsci.plugins.matrixauth.casc;

import hudson.Extension;
import hudson.security.ProjectMatrixAuthorizationStrategy;
import org.jenkinsci.plugins.casc.ConfiguratorException;
import org.jenkinsci.plugins.casc.model.CNode;
import org.jenkinsci.plugins.casc.model.Mapping;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

import javax.annotation.CheckForNull;

@Extension(optional = true, ordinal = 1)
@Restricted(NoExternalUse.class)
public class ProjectMatrixAuthorizationStrategyConfigurator extends MatrixAuthorizationStrategyConfigurator<ProjectMatrixAuthorizationStrategy> {

    @Override
    public String getName() {
        return "projectMatrix";
    }

    @Override
    public Class<ProjectMatrixAuthorizationStrategy> getTarget() {
        return ProjectMatrixAuthorizationStrategy.class;
    }

    public ProjectMatrixAuthorizationStrategy instance(Mapping mapping) throws ConfiguratorException {
        return new ProjectMatrixAuthorizationStrategy();
    }

    @CheckForNull
    @Override
    public CNode describe(ProjectMatrixAuthorizationStrategy instance) throws Exception {
        return compare(instance, new ProjectMatrixAuthorizationStrategy());
    }

}
