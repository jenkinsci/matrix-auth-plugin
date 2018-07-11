package org.jenkinsci.plugins.matrixauth.casc;

import hudson.Extension;
import hudson.security.GlobalMatrixAuthorizationStrategy;
import org.jenkinsci.plugins.casc.ConfiguratorException;
import org.jenkinsci.plugins.casc.model.CNode;
import org.jenkinsci.plugins.casc.model.Mapping;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

import javax.annotation.CheckForNull;

/**
 * @author Mads Nielsen
 * @since TODO
 */
@Extension(optional = true, ordinal = 1)
@Restricted(NoExternalUse.class)
public class GlobalMatrixAuthorizationStrategyConfigurator extends MatrixAuthorizationStrategyConfigurator<GlobalMatrixAuthorizationStrategy> {

    @Override
    public String getName() {
        return "globalMatrix";
    }

    @Override
    public Class<GlobalMatrixAuthorizationStrategy> getTarget() {
        return GlobalMatrixAuthorizationStrategy.class;
    }

    public GlobalMatrixAuthorizationStrategy instance(Mapping mapping) throws ConfiguratorException {
        return new GlobalMatrixAuthorizationStrategy();
    }

    @CheckForNull
    @Override
    public CNode describe(GlobalMatrixAuthorizationStrategy instance) throws Exception {
        return compare(instance, new GlobalMatrixAuthorizationStrategy());
    }
}
