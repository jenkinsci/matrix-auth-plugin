/*
 * The MIT License
 *
 * Copyright (c) 2023 Daniel Beck
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

import java.util.List;
import java.util.stream.Collectors;
import org.jenkinsci.plugins.matrixauth.AuthorizationType;
import org.jenkinsci.plugins.matrixauth.PermissionEntry;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

/**
 * Entry for type-safe permission definitions in JCasC YAML.
 */
@Restricted(NoExternalUse.class)
public class DefinitionEntry {
    private AuthorizationType type;
    private Child child;

    @DataBoundConstructor
    public DefinitionEntry() {}

    public DefinitionEntry(AuthorizationType type, Child child) {
        this.child = child;
        this.type = type;
    }

    @DataBoundSetter
    public void setUserOrGroup(Child child) {
        setNew(AuthorizationType.EITHER, child);
    }

    public Child getUserOrGroup() {
        return type == AuthorizationType.EITHER ? child : null;
    }

    @DataBoundSetter
    public void setUser(Child child) {
        setNew(AuthorizationType.USER, child);
    }

    public Child getUser() {
        return type == AuthorizationType.USER ? child : null;
    }

    @DataBoundSetter
    public void setGroup(Child child) {
        setNew(AuthorizationType.GROUP, child);
    }

    private void setNew(AuthorizationType type, Child child) {
        if (this.type != null) {
            throw new IllegalStateException(
                    "Can only configure one of: 'user', 'group', 'userOrGroup', but attempted to redefine to '"
                            + authorizationTypeToKey(type) + "' with name '" + child.name + "' after '"
                            + authorizationTypeToKey(this.type) + "' was already set to '"
                            + this.child.name + "'");
        }
        this.type = type;
        this.child = child;
    }

    public Child getGroup() {
        return type == AuthorizationType.GROUP ? child : null;
    }

    public Child child() {
        return child;
    }

    public PermissionEntry permissionEntry() {
        return new PermissionEntry(type, child.name);
    }

    private static String authorizationTypeToKey(AuthorizationType type) {
        if (type == null) {
            throw new NullPointerException("Received null 'type'");
        }
        if (type == AuthorizationType.USER) {
            return "user";
        }
        if (type == AuthorizationType.GROUP) {
            return "group";
        }
        if (type == AuthorizationType.EITHER) {
            return "userOrGroup";
        }
        throw new IllegalStateException("Unexpected 'type': " + type);
    }

    @Restricted(NoExternalUse.class)
    public static class Child {
        final List<PermissionDefinition> permissions;
        final String name;

        @DataBoundConstructor
        public Child(String name, List<PermissionDefinition> permissions) {
            this.name = name;
            this.permissions = permissions;
        }

        public List<PermissionDefinition> getPermissions() {
            return permissions.stream().sorted().collect(Collectors.toList());
        }

        public String getName() {
            return name;
        }
    }
}
