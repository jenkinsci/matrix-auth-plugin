package org.jenkinsci.plugins.matrixauth.integrations.casc;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.security.AuthorizationStrategy;
import hudson.security.Permission;
import io.jenkins.plugins.casc.Attribute;
import io.jenkins.plugins.casc.BaseConfigurator;
import io.jenkins.plugins.casc.impl.attributes.MultivaluedAttribute;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import org.jenkinsci.plugins.matrixauth.AuthorizationContainer;
import org.jenkinsci.plugins.matrixauth.PermissionEntry;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

@Restricted(NoExternalUse.class)
public abstract class MatrixAuthorizationStrategyConfigurator<T extends AuthorizationContainer>
        extends BaseConfigurator<T> {

    @NonNull
    @Override
    public Class<?> getImplementedAPI() {
        return AuthorizationStrategy.class;
    }

    @Override
    @NonNull
    public Set<Attribute<T, ?>> describe() {
        return new HashSet<>(Arrays.asList(
                new MultivaluedAttribute<T, DefinitionEntry>("entries", DefinitionEntry.class)
                        .getter(MatrixAuthorizationStrategyConfigurator::getEntries)
                        .setter(MatrixAuthorizationStrategyConfigurator::setEntries),

                // support old style configuration options
                new MultivaluedAttribute<T, String>("permissions", String.class)
                        .getter(unused -> null)
                        .setter(MatrixAuthorizationStrategyConfigurator::setLegacyPermissions),
                new MultivaluedAttribute<T, String>("grantedPermissions", String.class)
                        .getter(unused -> null)
                        .setter(MatrixAuthorizationStrategyConfigurator::setPermissionsDeprecated)));
    }

    private static class PermissionAssignment {
        private final PermissionDefinition permission;
        private final PermissionEntry entry;

        private PermissionAssignment(PermissionDefinition permission, PermissionEntry entry) {
            this.permission = permission;
            this.entry = entry;
        }

        public PermissionDefinition getPermission() {
            return permission;
        }

        public PermissionEntry getEntry() {
            return entry;
        }
    }

    /**
     * Maps an {@link AuthorizationContainer} to a collection (list) of {@link DefinitionEntry}, its serialized form.
     *
     * @param container the container
     * @return
     */
    public static Collection<DefinitionEntry> getEntries(AuthorizationContainer container) {
        // Contain has: Map from Permission to List of PermissionEntries (sid and type)
        final Map<Permission, Set<PermissionEntry>> entries = container.getGrantedPermissionEntries();

        final HashMap<PermissionEntry, List<PermissionDefinition>> intermediate = entries.entrySet().stream()
                .map(entry -> Map.entry(PermissionDefinition.forPermission(entry.getKey()), entry.getValue()))
                .flatMap(entry -> entry.getValue().stream().map(p -> new PermissionAssignment(entry.getKey(), p)))
                .collect(
                        HashMap::new,
                        (c, e) -> c.computeIfAbsent(e.getEntry(), f -> new ArrayList<>())
                                .add(e.getPermission()),
                        (c1, c2) -> {
                            /* unused */
                        });
        final Set<DefinitionEntry> result = intermediate.entrySet().stream()
                .map(entry -> new DefinitionEntry(entry.getKey(), entry.getValue()))
                .collect(Collectors.toSet());
        return result;
    }

    public static void setEntries(AuthorizationContainer container, Collection<DefinitionEntry> entries) {
        entries.forEach(e -> {
            e.getPermissions().stream().map(PermissionDefinition::getPermission).forEach(p -> {
                container.add(p, e.getPermissionEntry());
            });
        });
    }

    /**
     * Extract container's permissions as a List of "TYPE:PERMISSION:sid"
     */
    public static Collection<String> getLegacyPermissions(AuthorizationContainer container) {
        return container.getGrantedPermissionEntries().entrySet().stream()
                .flatMap(e -> e.getValue().stream()
                        .map(v -> v.getType().toPrefix() + e.getKey().group.getId() + "/" + e.getKey().name + ":"
                                + v.getSid()))
                .sorted()
                .collect(Collectors.toList());
    }

    /**
     * Configure container's permissions from a List of "PERMISSION:sid" or "TYPE:PERMISSION:sid"
     */
    public static void setLegacyPermissions(AuthorizationContainer container, Collection<String> permissions) {
        LOGGER.log(
                Level.WARNING,
                "Loading deprecated attribute 'permissions' for instance of '"
                        + container.getClass().getName() + "'. Use 'entries' instead.");
        permissions.forEach(container::add);
    }

    /**
     * Like {@link #setLegacyPermissions(AuthorizationContainer, Collection)} but logs a deprecation warning
     */
    public static void setPermissionsDeprecated(AuthorizationContainer container, Collection<String> permissions) {
        LOGGER.log(
                Level.WARNING,
                "Loading deprecated attribute 'grantedPermissions' for instance of '"
                        + container.getClass().getName() + "'. Use 'permissions' instead.");
        setLegacyPermissions(container, permissions);
    }

    private static final Logger LOGGER = Logger.getLogger(MatrixAuthorizationStrategyConfigurator.class.getName());
}
