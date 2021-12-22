package org.jenkinsci.plugins.matrixauth.integrations.casc;

import java.util.Objects;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.plugins.matrixauth.PermissionEntry;
import org.kohsuke.stapler.DataBoundConstructor;

public class PermissionEntryForCasc implements Comparable<PermissionEntryForCasc> {
    private String user;
    private String group;
    private String permission;

    @DataBoundConstructor
    public PermissionEntryForCasc(String permission) {
        this.permission = permission;
    }

    public String getPermission() {
        return permission;
    }

    public String getUser() {
        return user;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public String getGroup() {
        return group;
    }

    public void setGroup(String group) {
        this.group = group;
    }

    public PermissionEntry retrieveEntry() {
        if (StringUtils.isNotBlank(user)) {
            return PermissionEntry.user(user);
        }

        if (StringUtils.isNotBlank(group)) {
            return PermissionEntry.group(group);
        }
        throw new IllegalStateException("One of 'group' or 'user' must be set, permission was: " + permission);
    }

    @Override
    public int compareTo(PermissionEntryForCasc obj) {
        return permission.compareTo(obj.permission);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PermissionEntryForCasc that = (PermissionEntryForCasc) o;
        return Objects.equals(user, that.user) && Objects.equals(group, that.group) && permission.equals(that.permission);
    }

    @Override
    public int hashCode() {
        return Objects.hash(user, group, permission);
    }
}
