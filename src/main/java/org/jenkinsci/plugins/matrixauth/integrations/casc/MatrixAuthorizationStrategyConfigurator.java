/*
 * The MIT License
 *
 * Copyright (c) 2018-2023 CloudBees, Inc., Nicolas De Loof, Daniel Beck
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
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
import java.util.Comparator;
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
        final List<DefinitionEntry> result = intermediate.entrySet().stream()
                .map(entry -> new DefinitionEntry(
                        entry.getKey().getType(),
                        new DefinitionEntry.Child(entry.getKey().getSid(), entry.getValue())))
                .sorted(Comparator.comparing(DefinitionEntry::permissionEntry))
                .collect(Collectors.toList());
        return result;
    }

    public static void setEntries(AuthorizationContainer container, Collection<DefinitionEntry> entries) {
        entries.forEach(e -> {
            e.child().getPermissions().stream()
                    .map(PermissionDefinition::getPermission)
                    .forEach(p -> {
                        container.add(p, e.permissionEntry());
                    });
        });
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
