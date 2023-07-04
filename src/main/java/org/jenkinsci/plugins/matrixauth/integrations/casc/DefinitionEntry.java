package org.jenkinsci.plugins.matrixauth.integrations.casc;

import java.util.List;
import org.jenkinsci.plugins.matrixauth.AuthorizationType;
import org.jenkinsci.plugins.matrixauth.PermissionEntry;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

/**
 * Entry for type-safe permission definitions in JCasC YAML.
 */
public class DefinitionEntry {
    private final List<PermissionDefinition> permissions;
    private PermissionEntry permissionEntry;

    @DataBoundConstructor
    public DefinitionEntry(List<PermissionDefinition> permissions) {
        this.permissions = permissions;
    }

    public DefinitionEntry(PermissionEntry entry, List<PermissionDefinition> permissions) {
        this.permissionEntry = entry;
        this.permissions = permissions;
    }

    public List<PermissionDefinition> getPermissions() {
        return permissions;
    }

    public PermissionEntry getPermissionEntry() {
        return permissionEntry;
    }

    @DataBoundSetter
    public void setUserOrGroup(String userOrGroup) {
        requireNoPermissionType();
        this.permissionEntry = new PermissionEntry(AuthorizationType.EITHER, userOrGroup);
    }

    public String getUserOrGroup() {
        return permissionEntry == null
                ? null
                : permissionEntry.getType() == AuthorizationType.EITHER ? permissionEntry.getSid() : null;
    }

    @DataBoundSetter
    public void setUser(String user) {
        requireNoPermissionType();
        this.permissionEntry = PermissionEntry.user(user);
    }

    public String getUser() {
        return permissionEntry == null
                ? null
                : permissionEntry.getType() == AuthorizationType.USER ? permissionEntry.getSid() : null;
    }

    @DataBoundSetter
    public void setGroup(String group) {
        requireNoPermissionType();
        this.permissionEntry = PermissionEntry.group(group);
    }

    public String getGroup() {
        return permissionEntry == null
                ? null
                : permissionEntry.getType() == AuthorizationType.GROUP ? permissionEntry.getSid() : null;
    }

    private void requireNoPermissionType() {
        if (permissionEntry != null) {
            throw new IllegalStateException(
                    "Can only configure one of: 'user', 'group', 'userOrGroup', but redefine after '"
                            + authorizationTypeToKey(permissionEntry.getType()) + "' was already set to '"
                            + permissionEntry.getSid() + "'");
        }
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
}
