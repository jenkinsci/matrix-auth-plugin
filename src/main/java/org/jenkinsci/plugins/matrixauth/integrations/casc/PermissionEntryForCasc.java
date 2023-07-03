package org.jenkinsci.plugins.matrixauth.integrations.casc;

import java.util.Objects;
import java.util.logging.Logger;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.plugins.matrixauth.AuthorizationType;
import org.jenkinsci.plugins.matrixauth.PermissionEntry;
import org.kohsuke.stapler.DataBoundConstructor;

public class PermissionEntryForCasc implements Comparable<PermissionEntryForCasc> {

    private static final Logger LOGGER = Logger.getLogger(PermissionEntryForCasc.class.getName());

    private String user;
    private String group;
    private String ambiguous;
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

    public String getAmbiguous() {
        return ambiguous;
    }

    public void setAmbiguous(String ambiguous) {
        LOGGER.warning(String.format(
                "Setting deprecated attribute 'ambiguous' for '%s' use 'user' or 'group' instead", ambiguous));
        this.ambiguous = ambiguous;
    }

    public PermissionEntry retrieveEntry() {
        if (StringUtils.isNotBlank(user)) {
            return PermissionEntry.user(user);
        }

        if (StringUtils.isNotBlank(group)) {
            return PermissionEntry.group(group);
        }

        return new PermissionEntry(AuthorizationType.EITHER, ambiguous);
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
        return Objects.equals(user, that.user)
                && Objects.equals(group, that.group)
                && permission.equals(that.permission);
    }

    @Override
    public int hashCode() {
        return Objects.hash(user, group, permission);
    }
}
