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
