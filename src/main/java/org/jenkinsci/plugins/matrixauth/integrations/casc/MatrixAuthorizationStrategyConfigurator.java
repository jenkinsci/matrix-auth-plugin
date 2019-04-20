package org.jenkinsci.plugins.matrixauth.integrations.casc;

import hudson.security.AuthorizationStrategy;
import hudson.security.Permission;
import io.jenkins.plugins.casc.Attribute;
import io.jenkins.plugins.casc.BaseConfigurator;
import io.jenkins.plugins.casc.impl.attributes.MultivaluedAttribute;
import org.jenkinsci.plugins.matrixauth.AuthorizationContainer;
import org.jenkinsci.plugins.matrixauth.integrations.PermissionFinder;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

import javax.annotation.Nonnull;
import java.util.Collection;
import java.util.Collections;
import java.util.Locale;
import java.util.Set;
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
        return Collections.singleton(
                new MultivaluedAttribute<T, String>("grantedPermissions", String.class)
                        .getter(MatrixAuthorizationStrategyConfigurator::getGrantedPermissions)
                        .setter(MatrixAuthorizationStrategyConfigurator::setGrantedPermissions)
        );
    }

    /**
     * Extract container's permissions as a List of "PERMISSION:sid"
     */
    public static Collection<String> getGrantedPermissions(AuthorizationContainer container) {
        return container.getGrantedPermissions().entrySet().stream()
                .flatMap( e -> e.getValue().stream()
                        .map(v -> e.getKey().group.title.toString(Locale.US)+"/"+e.getKey().name+":"+v))
                .collect(Collectors.toList());
    }

    /**
     * Configure container's permissions from a List of "PERMISSION:sid"
     */
    public static void setGrantedPermissions(AuthorizationContainer container, Collection<String> permissions) {
        permissions.forEach(p -> {
            final int i = p.indexOf(':');
            final Permission permission = PermissionFinder.findPermission(p.substring(0, i));
            container.add(permission, p.substring(i+1));
        });
    }
}
