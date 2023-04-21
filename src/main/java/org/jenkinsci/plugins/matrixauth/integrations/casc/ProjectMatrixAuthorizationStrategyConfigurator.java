package org.jenkinsci.plugins.matrixauth.integrations.casc;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.security.ProjectMatrixAuthorizationStrategy;
import io.jenkins.plugins.casc.ConfigurationContext;
import io.jenkins.plugins.casc.model.CNode;
import io.jenkins.plugins.casc.model.Mapping;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

@Extension(optional = true, ordinal = 2)
@Restricted(NoExternalUse.class)
public class ProjectMatrixAuthorizationStrategyConfigurator
        extends MatrixAuthorizationStrategyConfigurator<ProjectMatrixAuthorizationStrategy> {

    @Override
    @NonNull
    public String getName() {
        return "projectMatrix";
    }

    @Override
    public Class<ProjectMatrixAuthorizationStrategy> getTarget() {
        return ProjectMatrixAuthorizationStrategy.class;
    }

    @Override
    public ProjectMatrixAuthorizationStrategy instance(Mapping mapping, ConfigurationContext context) {
        return new ProjectMatrixAuthorizationStrategy();
    }

    @CheckForNull
    @Override
    public CNode describe(ProjectMatrixAuthorizationStrategy instance, ConfigurationContext context) throws Exception {
        return compare(instance, new ProjectMatrixAuthorizationStrategy(), context);
    }
}
