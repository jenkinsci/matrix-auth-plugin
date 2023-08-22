/*
 * The MIT License
 *
 * Copyright (c) 2004-2017 Sun Microsystems, Inc., Kohsuke Kawaguchi, Yahoo! Inc., Peter Hayes, Tom Huybrechts, Daniel Beck
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
package org.jenkinsci.plugins.matrixauth;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Describable;
import hudson.model.Descriptor;
import hudson.security.Permission;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.stream.Collectors;
import jenkins.model.Jenkins;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.matrixauth.inheritance.InheritGlobalStrategy;
import org.jenkinsci.plugins.matrixauth.inheritance.InheritanceStrategy;
import org.jenkinsci.plugins.matrixauth.inheritance.NonInheritingStrategy;
import org.jenkinsci.plugins.matrixauth.integrations.PermissionFinder;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.DoNotUse;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.DataBoundConstructor;

@Restricted(NoExternalUse.class)
public interface AuthorizationProperty extends AuthorizationContainer {

    void setInheritanceStrategy(InheritanceStrategy inheritanceStrategy);

    InheritanceStrategy getInheritanceStrategy();

    /**
     * Sets the flag to block inheritance.
     *
     * Since the introduction of inheritance strategies, set the inheritance
     * strategy roughly matching the previous behavior, i.e. {@code false} will
     * set the {@link NonInheritingStrategy}, {@code true} will set the
     * {@link InheritGlobalStrategy}.
     *
     * Note that for items nested inside folders, this will change behavior significantly.
     *
     * @since 2.0
     * @deprecated Use {@link InheritanceStrategy} instead.
     */
    @Deprecated
    default void setBlocksInheritance(boolean blocksInheritance) {
        if (blocksInheritance) {
            setInheritanceStrategy(new NonInheritingStrategy());
        } else {
            setInheritanceStrategy(new InheritGlobalStrategy());
        }
    }

    /**
     * Returns true if the authorization matrix is configured to block
     * inheritance from the parent.
     *
     * Since the introduction of inheritance strategies, returns {@code true}
     * if and only if the selected inheritance strategy is {@link NonInheritingStrategy}.
     *
     * @since 2.0
     * @deprecated Use {@link #getInheritanceStrategy()} instead.
     */
    @Deprecated
    default boolean isBlocksInheritance() {
        return getInheritanceStrategy() instanceof NonInheritingStrategy;
    }

    /**
     * Set entries from DSL in Job DSL or Pipeline plugins.
     *
     * @param entries list of entries to use for permission assignment
     */
    @Restricted(DoNotUse.class)
    default void setEntries(List<DslEntry> entries) {
        for (DslEntry entry : entries) {
            entry.addPermission(this);
        }
    }

    /**
     * Getter supporting nicer DSL syntax for Job DSL and Pipeline job property definitions.
     * @return a list of {@link DslEntry}
     */
    default List<DslEntry> getEntries() {
        final Map<PermissionEntry, SortedSet<String>> mapping = new HashMap<>();
        getGrantedPermissionEntries()
                .forEach((permission, value) ->
                        value.forEach(sid -> mapping.computeIfAbsent(sid, unused -> new TreeSet<>())
                                .add(permission.group.getId() + "/" + permission.name)));
        return mapping.entrySet().stream()
                .map(e -> {
                    final PermissionEntry key = e.getKey();
                    if (key.getType() == AuthorizationType.USER) {
                        return new DslUser(key.getSid(), new ArrayList<>(e.getValue()));
                    }
                    if (key.getType() == AuthorizationType.GROUP) {
                        return new DslGroup(key.getSid(), new ArrayList<>(e.getValue()));
                    }
                    if (key.getType() == AuthorizationType.EITHER) {
                        return new DslUserOrGroup(key.getSid(), new ArrayList<>(e.getValue()));
                    }
                    throw new IllegalStateException("Got unexpected key type in: " + key);
                })
                .distinct()
                .sorted()
                .collect(Collectors.toList());
    }

    /**
     * Common superclass for {@link DslUser}, {@link DslGroup}, and {@link DslUserOrGroup}, supporting nicer DSLs
     * for Job DSL and Pipeline Job definitions/reconfigurations.
     * Job DSL and Pipeline use this for {@link hudson.security.AuthorizationMatrixProperty}.
     * Job DSL additionally uses this for {@link com.cloudbees.hudson.plugins.folder.properties.AuthorizationMatrixProperty}.
     */
    @Restricted(NoExternalUse.class)
    abstract class DslEntry implements Describable<DslEntry>, Comparable<DslEntry> {
        private final String name;
        private final List<String> permissions;

        /**
         *
         * @param name the sid of the DSL entity
         * @param permissions the list of string-typed permissions
         */
        public DslEntry(String name, List<String> permissions) {
            this.name = name;
            this.permissions = permissions;
        }

        public String getName() {
            return name;
        }

        public List<String> getPermissions() {
            return permissions;
        }

        @Override
        public Descriptor<DslEntry> getDescriptor() {
            return Jenkins.get().getDescriptorOrDie(getClass());
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            DslEntry that = (DslEntry) o;
            return Objects.equals(name, that.name) && Objects.equals(permissions, that.permissions);
        }

        @Override
        public int hashCode() {
            return Objects.hash(name, permissions, getClass());
        }

        @Override
        public int compareTo(@NonNull DslEntry that) {
            if (this.getClass() != that.getClass()) {
                return this.getClass().getName().compareTo(that.getClass().getName());
            }
            if (!this.name.equals(that.name)) {
                return this.name.compareTo(that.name);
            }
            return this.permissions.size() - that.permissions.size();
        }

        public abstract void addPermission(AuthorizationProperty authorizationProperty);

        protected static Permission findPermission(String value) {
            final Permission permission = Permission.fromId(value);
            if (permission != null) {
                return permission;
            }
            return PermissionFinder.findPermission(value);
        }
    }

    /**
     * Represents a user being assigned permissions.
     */
    @Restricted(NoExternalUse.class)
    class DslUser extends DslEntry {
        @DataBoundConstructor
        public DslUser(String name, List<String> permissions) {
            super(name, permissions);
        }

        @Override
        public void addPermission(AuthorizationProperty authorizationProperty) {
            getPermissions()
                    .forEach(permission ->
                            authorizationProperty.add(findPermission(permission), PermissionEntry.user(getName())));
        }

        @Extension
        @Symbol("user")
        public static class DescriptorImpl extends Descriptor<DslEntry> {}
    }

    /**
     * Represents a group being assigned permissions.
     */
    @Restricted(NoExternalUse.class)
    class DslGroup extends DslEntry {
        @DataBoundConstructor
        public DslGroup(String name, List<String> permissions) {
            super(name, permissions);
        }

        @Override
        public void addPermission(AuthorizationProperty authorizationProperty) {
            getPermissions()
                    .forEach(permission ->
                            authorizationProperty.add(findPermission(permission), PermissionEntry.group(getName())));
        }

        @Extension
        @Symbol("group")
        public static class DescriptorImpl extends Descriptor<DslEntry> {}
    }

    /**
     * Represents a user or group being assigned permissions.
     * Generally discouraged "ambiguous" permission assignments.
     */
    @Restricted(NoExternalUse.class)
    class DslUserOrGroup extends DslEntry {
        @DataBoundConstructor
        public DslUserOrGroup(String name, List<String> permissions) {
            super(name, permissions);
        }

        @Override
        public void addPermission(AuthorizationProperty authorizationProperty) {
            getPermissions()
                    .forEach(permission -> authorizationProperty.add(
                            findPermission(permission), new PermissionEntry(AuthorizationType.EITHER, getName())));
        }

        @Extension
        @Symbol("userOrGroup")
        public static class DescriptorImpl extends Descriptor<DslEntry> {}
    }
}
