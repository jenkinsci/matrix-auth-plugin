package org.jenkinsci.plugins.matrixauth.integrations.casc;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.security.GlobalMatrixAuthorizationStrategy;
import io.jenkins.plugins.casc.ConfigurationContext;
import io.jenkins.plugins.casc.model.CNode;
import io.jenkins.plugins.casc.model.Mapping;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

@Extension(optional = true, ordinal = 2)
@Restricted(NoExternalUse.class)
public class GlobalMatrixAuthorizationStrategyConfigurator
        extends MatrixAuthorizationStrategyConfigurator<GlobalMatrixAuthorizationStrategy> {

    @Override
    @NonNull
    public String getName() {
        return "globalMatrix";
    }

    @Override
    public Class<GlobalMatrixAuthorizationStrategy> getTarget() {
        return GlobalMatrixAuthorizationStrategy.class;
    }

    @Override
    public GlobalMatrixAuthorizationStrategy instance(Mapping mapping, ConfigurationContext context) {
        return new GlobalMatrixAuthorizationStrategy();
    }

    @CheckForNull
    @Override
    public CNode describe(GlobalMatrixAuthorizationStrategy instance, ConfigurationContext context) throws Exception {
        return compare(instance, new GlobalMatrixAuthorizationStrategy(), context);
    }
}
