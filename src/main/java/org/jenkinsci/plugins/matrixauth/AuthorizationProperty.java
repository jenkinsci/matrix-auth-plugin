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

import hudson.Extension;
import hudson.model.Describable;
import hudson.model.Descriptor;
import hudson.security.Permission;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import jenkins.model.Jenkins;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.matrixauth.inheritance.InheritGlobalStrategy;
import org.jenkinsci.plugins.matrixauth.inheritance.InheritanceStrategy;
import org.jenkinsci.plugins.matrixauth.inheritance.NonInheritingStrategy;
import org.kohsuke.accmod.Restricted;
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

    default void setEntries(List<PropertyEntry> entries) {
        for (PropertyEntry entry : entries) {
            if (entry instanceof JobDslGroup) {
                entry.getPermissions()
                        .forEach(permission -> add(
                                getPermission(permission, permission, entry.getName()),
                                PermissionEntry.group(entry.getName())));
            } else if (entry instanceof JobDslUser) {
                entry.getPermissions()
                        .forEach(permission -> add(
                                getPermission(permission, permission, entry.getName()),
                                PermissionEntry.user(entry.getName())));
            } else {
                entry.getPermissions()
                        .forEach(permission -> add(
                                getPermission(permission, permission, entry.getName()),
                                new PermissionEntry(AuthorizationType.EITHER, entry.getName())));
            }
        }
    }

    default List<PropertyEntry> getEntries() {
        final Map<PermissionEntry, List<String>> mapping = new HashMap<>();
        getGrantedPermissionEntries().forEach((permission, value) -> value.forEach(sid -> {
            switch (sid.getType()) {
                case USER:
                case GROUP:
                    mapping.computeIfAbsent(sid, unused -> new ArrayList<>()).add(permission.getId());
                    break;
                default:
                    // TODO Figure out what to do with this. New type for ambiguous permissions?
            }
        }));
        return mapping.entrySet().stream().map(e -> {
            final PermissionEntry key = e.getKey();
            if (key.getType() == AuthorizationType.USER) {
                return new JobDslUser(key.getSid(), e.getValue());
            }
            if (key.getType() == AuthorizationType.GROUP) {
                return new JobDslGroup(key.getSid(), e.getValue());
            }
            return null;
        }).filter(Objects::nonNull).collect(Collectors.toList());
    }

    abstract class PropertyEntry implements Describable<PropertyEntry> {
        private final String name;
        private final List<String> permissions;

        public PropertyEntry(String name, List<String> permissions) {
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
        public Descriptor<PropertyEntry> getDescriptor() {
            return Jenkins.get().getDescriptorOrDie(getClass());
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            PropertyEntry that = (PropertyEntry) o;
            return Objects.equals(name, that.name) && Objects.equals(permissions, that.permissions);
        }

        @Override
        public int hashCode() {
            return Objects.hash(name, permissions, getClass());
        }
    }

    class JobDslUser extends PropertyEntry {
        @DataBoundConstructor
        public JobDslUser(String name, List<String> permissions) {
            super(name, permissions);
        }

        @Extension
        @Symbol("user")
        public static class DescriptorImpl extends Descriptor<PropertyEntry> {}
    }

    class JobDslGroup extends PropertyEntry {
        @DataBoundConstructor
        public JobDslGroup(String name, List<String> permissions) {
            super(name, permissions);
        }
        @Extension
        @Symbol("group")
        public static class DescriptorImpl extends Descriptor<PropertyEntry> {}
    }
}
