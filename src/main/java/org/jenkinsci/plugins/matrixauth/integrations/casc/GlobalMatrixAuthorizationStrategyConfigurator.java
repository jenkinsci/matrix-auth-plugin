package org.jenkinsci.plugins.matrixauth.integrations.casc;

import hudson.Extension;
import hudson.security.GlobalMatrixAuthorizationStrategy;
import io.jenkins.plugins.casc.ConfigurationContext;
import io.jenkins.plugins.casc.model.CNode;
import io.jenkins.plugins.casc.model.Mapping;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;

@Extension(optional = true, ordinal = 2)
@Restricted(NoExternalUse.class)
public class GlobalMatrixAuthorizationStrategyConfigurator extends MatrixAuthorizationStrategyConfigurator<GlobalMatrixAuthorizationStrategy> {

    @Override
    @Nonnull
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
