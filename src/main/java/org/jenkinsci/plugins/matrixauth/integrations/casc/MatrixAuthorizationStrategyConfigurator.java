package org.jenkinsci.plugins.matrixauth.integrations.casc;

import hudson.security.AuthorizationStrategy;
import io.jenkins.plugins.casc.Attribute;
import io.jenkins.plugins.casc.BaseConfigurator;
import io.jenkins.plugins.casc.impl.attributes.MultivaluedAttribute;
import org.jenkinsci.plugins.matrixauth.AuthorizationContainer;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

import javax.annotation.Nonnull;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

@Restricted(NoExternalUse.class)
public abstract class MatrixAuthorizationStrategyConfigurator<T extends AuthorizationContainer> extends BaseConfigurator<T> {

    @Nonnull
    @Override
    public Class<?> getImplementedAPI() {
        return AuthorizationStrategy.class;
    }


    @Override
    @Nonnull
    public Set<Attribute<T, ?>> describe() {
        return new HashSet<>(Arrays.asList(
                new MultivaluedAttribute<T, String>("permissions", String.class)
                        .getter(MatrixAuthorizationStrategyConfigurator::getPermissions)
                        .setter(MatrixAuthorizationStrategyConfigurator::setPermissions),

                // support old style configuration options
                new MultivaluedAttribute<T, String>("grantedPermissions", String.class)
                        .getter(unused -> null)
                        .setter(MatrixAuthorizationStrategyConfigurator::setPermissionsDeprecated)
        ));
    }

    /**
     * Extract container's permissions as a List of "TYPE:PERMISSION:sid"
     */
    public static Collection<String> getPermissions(AuthorizationContainer container) {
        return container.getGrantedPermissionEntries().entrySet().stream()
                .flatMap( e -> e.getValue().stream()
                        .map(v -> v.getType().toPrefix() + e.getKey().group.getId() + "/" + e.getKey().name + ":" + v.getSid()))
                .sorted()
                .collect(Collectors.toList());
    }

    /**
     * Configure container's permissions from a List of "PERMISSION:sid" or "TYPE:PERMISSION:sid"
     */
    public static void setPermissions(AuthorizationContainer container, Collection<String> permissions) {
        permissions.forEach(container::add);
    }

    /**
     * Like {@link #setPermissions(AuthorizationContainer, Collection)} but logs a deprecation warning
     */
    public static void setPermissionsDeprecated(AuthorizationContainer container, Collection<String> permissions) {
        LOGGER.log(Level.WARNING, "Loading deprecated attribute 'grantedPermissions' for instance of '" + container.getClass().getName() +"'. Use 'permissions' instead.");
        setPermissions(container, permissions);
    }

    private static final Logger LOGGER = Logger.getLogger(MatrixAuthorizationStrategyConfigurator.class.getName());
}
