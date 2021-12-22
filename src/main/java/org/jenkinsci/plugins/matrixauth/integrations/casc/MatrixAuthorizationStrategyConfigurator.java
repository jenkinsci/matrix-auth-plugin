package org.jenkinsci.plugins.matrixauth.integrations.casc;

import hudson.security.AuthorizationStrategy;
import hudson.security.Permission;
import io.jenkins.plugins.casc.Attribute;
import io.jenkins.plugins.casc.BaseConfigurator;
import io.jenkins.plugins.casc.impl.attributes.MultivaluedAttribute;
import java.util.Collections;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.plugins.matrixauth.AuthorizationContainer;
import org.jenkinsci.plugins.matrixauth.AuthorizationContainerDescriptor;
import org.jenkinsci.plugins.matrixauth.AuthorizationType;
import org.jenkinsci.plugins.matrixauth.PermissionEntry;
import org.jenkinsci.plugins.matrixauth.integrations.PermissionFinder;
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
import org.kohsuke.stapler.DataBoundConstructor;

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
        return new HashSet<>(Collections.singletonList(
                new MultivaluedAttribute<T, PermissionEntryForCasc>("permissions", PermissionEntryForCasc.class)
                        .getter(MatrixAuthorizationStrategyConfigurator::getPermissions)
                        .setter(MatrixAuthorizationStrategyConfigurator::setPermissions)
        ));
    }

    /**
     * Extract container's permissions as a List of "TYPE:PERMISSION:sid"
     */
    public static Collection<PermissionEntryForCasc> getPermissions(AuthorizationContainer container) {
        return container.getGrantedPermissionEntries().entrySet().stream()
                .flatMap( e -> e.getValue().stream()
                        .map(v -> {
                            PermissionEntryForCasc entry = new PermissionEntryForCasc(e.getKey().group.getId() + "/" + e.getKey().name);
                            if (v.getType().equals(AuthorizationType.USER)) {
                                entry.setUser(v.getSid());
                                return entry;
                            } else if (v.getType().equals(AuthorizationType.GROUP)) {
                                entry.setGroup(v.getSid());
                                return entry;
                            } else {
                                entry.setAmbiguous(v.getSid());
                                return entry;
                            }
                        }))
                .sorted()
                .collect(Collectors.toList());
    }

    /**
     * Configure container's permissions from a List of "PERMISSION:sid" or "TYPE:PERMISSION:sid"
     */
    public static void setPermissions(AuthorizationContainer container, Collection<PermissionEntryForCasc> permissions) {
        permissions.forEach(container::add);
    }
}
