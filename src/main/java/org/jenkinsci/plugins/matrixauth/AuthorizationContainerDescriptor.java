package org.jenkinsci.plugins.matrixauth;

import static org.jenkinsci.plugins.matrixauth.ValidationUtil.formatNonExistentUserGroupValidationResponse;
import static org.jenkinsci.plugins.matrixauth.ValidationUtil.formatUserGroupValidationResponse;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Functions;
import hudson.security.AccessControlled;
import hudson.security.GlobalMatrixAuthorizationStrategy;
import hudson.security.Permission;
import hudson.security.PermissionGroup;
import hudson.security.PermissionScope;
import hudson.security.SecurityRealm;
import hudson.util.FormValidation;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import jenkins.model.Jenkins;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.DoNotUse;
import org.kohsuke.accmod.restrictions.NoExternalUse;

/**
 * Interface methods common to descriptors of authorization strategy and the various properties.
 *
 * Mostly some methods used from the similar configuration UI for these (reuse there).
 *
 */
@Restricted(NoExternalUse.class)
public interface AuthorizationContainerDescriptor {

    PermissionScope getPermissionScope();

    @Restricted(DoNotUse.class) // Called from Jelly view to show fancy tool tips
    default String getDescription(Permission p) {
        String description = p.description == null ? "" : p.description.toString();
        Permission impliedBy = p.impliedBy;
        while (impliedBy != null && impliedBy.group == PermissionGroup.get(Permission.class)) {
            if (impliedBy.impliedBy == null) {
                break;
            }
            impliedBy = impliedBy.impliedBy;
        }
        if (p != Jenkins.ADMINISTER) {
            // only annotate permissions that aren't Administer
            if (impliedBy == null) {
                // this permission is not implied by anything else, this is notable
                if (description.length() > 0) {
                    description += "<br/><br/>";
                }
                description += Messages.GlobalMatrixAuthorizationStrategy_PermissionNotImpliedBy();
            } else if (impliedBy != Jenkins.ADMINISTER) {
                // this is implied by a permission other than Administer
                if (description.length() > 0) {
                    description += "<br/><br/>";
                }
                description += Messages.GlobalMatrixAuthorizationStrategy_PermissionImpliedBy(
                        impliedBy.group.title, impliedBy.name);
            }
        }

        return description;
    }

    @Restricted(DoNotUse.class) // Called from Jelly view
    default List<PermissionGroup> getAllGroups() {
        List<PermissionGroup> groups = new ArrayList<>();
        for (PermissionGroup group : PermissionGroup.getAll()) {
            if (group == PermissionGroup.get(Permission.class)) {
                continue;
            }
            if (!group.hasPermissionContainedBy(getPermissionScope())) {
                continue;
            }
            for (Permission p : group.getPermissions()) {
                if (p.getEnabled()) {
                    groups.add(group);
                    break;
                }
            }
        }
        return groups;
    }

    @Restricted(NoExternalUse.class)
    @SuppressWarnings("unused") // Used from Jelly
    default String impliedByList(Permission p) {
        List<Permission> impliedBys = new ArrayList<>();
        while (p.impliedBy != null) {
            p = p.impliedBy;
            impliedBys.add(p);
        }
        return StringUtils.join(impliedBys.stream().map(Permission::getId).collect(Collectors.toList()), " ");
    }

    @Restricted(DoNotUse.class) // Called from Jelly view
    default boolean showPermission(Permission p) {
        if (!p.getEnabled()) {
            // Permission is disabled, so don't show it
            return false;
        }

        // ensure the permission is defined in the correct permission scope
        if (!p.isContainedBy(getPermissionScope())) {
            return false;
        }

        // do not allow dangerous permissions to be set explicitly
        return !GlobalMatrixAuthorizationStrategy.DANGEROUS_PERMISSIONS.contains(p);
    }

    @Restricted(DoNotUse.class) // Jelly only
    default boolean hasAmbiguousEntries(AuthorizationContainer container) {
        if (container == null) {
            return false;
        }
        return container.getAllPermissionEntries().stream().anyMatch(e -> e.getType() == AuthorizationType.EITHER);
    }

    @Restricted(DoNotUse.class) // Jelly only
    default PermissionEntry entryFor(String type, String sid) {
        if (type == null) {
            return null; // template row only
        }
        return new PermissionEntry(AuthorizationType.valueOf(type), sid);
    }

    @Restricted(DoNotUse.class) // Jelly only; cf. UpdateCenter#getCategoryDisplayName in core
    default String getTypeLabel(String type)
            throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        if (type == null) {
            return "__TYPE__"; // placeholder
        }
        return Messages.class.getMethod("TypeLabel_" + type).invoke(null).toString();
    }

    // Not used directly by Stapler due to the trailing _ (this prevented method confusion around 1.415).
    @Restricted(NoExternalUse.class)
    default FormValidation doCheckName_(
            @NonNull String value, @NonNull AccessControlled subject, @NonNull Permission permission) {

        final String unbracketedValue = value.substring(1, value.length() - 1); // remove leading [ and trailing ]

        final int splitIndex = unbracketedValue.indexOf(':');
        if (splitIndex < 0) {
            return FormValidation.error("No type prefix: " + unbracketedValue);
        }
        final String typeString = unbracketedValue.substring(0, splitIndex);
        final AuthorizationType type;
        try {
            type = AuthorizationType.valueOf(typeString);
        } catch (Exception ex) {
            return FormValidation.error("Invalid type prefix: " + unbracketedValue);
        }
        String sid = unbracketedValue.substring(splitIndex + 1);

        String escapedSid = Functions.escape(sid);

        if (!subject.hasPermission(permission)) {
            // Lacking permissions, so respond based on input only
            if (type == AuthorizationType.USER) {
                return FormValidation.okWithMarkup(
                        formatUserGroupValidationResponse("person", escapedSid, "User may or may not exist"));
            }
            if (type == AuthorizationType.GROUP) {
                return FormValidation.okWithMarkup(
                        formatUserGroupValidationResponse("user", escapedSid, "Group may or may not exist"));
            }
            return FormValidation.warningWithMarkup(formatUserGroupValidationResponse(
                    null, escapedSid, "Permissions would be granted to a user or group of this name"));
        }

        SecurityRealm sr = Jenkins.get().getSecurityRealm();

        if (sid.equals("authenticated") && type == AuthorizationType.EITHER) {
            // system reserved group
            return FormValidation.warningWithMarkup(formatUserGroupValidationResponse(
                    "user",
                    escapedSid,
                    "Internal group found; but permissions would also be granted to a user of this name"));
        }

        if (sid.equals("anonymous") && type == AuthorizationType.EITHER) {
            // system reserved user
            return FormValidation.warningWithMarkup(formatUserGroupValidationResponse(
                    "person",
                    escapedSid,
                    "Internal user found; but permissions would also be granted to a group of this name"));
        }

        try {
            FormValidation groupValidation;
            FormValidation userValidation;
            switch (type) {
                case GROUP:
                    groupValidation = ValidationUtil.validateGroup(sid, sr, false);
                    if (groupValidation != null) {
                        return groupValidation;
                    }
                    return FormValidation.errorWithMarkup(formatNonExistentUserGroupValidationResponse(
                            escapedSid, "Group not found")); // TODO i18n (after 3.0)
                case USER:
                    userValidation = ValidationUtil.validateUser(sid, sr, false);
                    if (userValidation != null) {
                        return userValidation;
                    }
                    return FormValidation.errorWithMarkup(formatNonExistentUserGroupValidationResponse(
                            escapedSid, "User not found")); // TODO i18n (after 3.0)
                case EITHER:
                    userValidation = ValidationUtil.validateUser(sid, sr, true);
                    if (userValidation != null) {
                        return userValidation;
                    }
                    groupValidation = ValidationUtil.validateGroup(sid, sr, true);
                    if (groupValidation != null) {
                        return groupValidation;
                    }
                    return FormValidation.errorWithMarkup(formatNonExistentUserGroupValidationResponse(
                            escapedSid, "User or group not found")); // TODO i18n (after 3.0)
                default:
                    return FormValidation.error("Unexpected type: " + type);
            }
        } catch (Exception e) {
            // if the check fails miserably, we still want the user to be able to see the name of the user,
            // so use 'escapedSid' as the message
            return FormValidation.error(e, escapedSid);
        }
    }
}
