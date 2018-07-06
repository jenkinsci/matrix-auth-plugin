package org.jenkinsci.plugins.matrixauth;

import hudson.Functions;
import hudson.Util;
import hudson.model.User;
import hudson.security.AccessControlled;
import hudson.security.AuthorizationStrategy;
import hudson.security.GlobalMatrixAuthorizationStrategy;
import hudson.security.Permission;
import hudson.security.PermissionGroup;
import hudson.security.PermissionScope;
import hudson.security.SecurityRealm;
import hudson.security.UserMayOrMayNotExistException;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.DoNotUse;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.springframework.dao.DataAccessException;

import javax.annotation.Nonnull;

import java.util.ArrayList;
import java.util.List;

import static org.jenkinsci.plugins.matrixauth.ValidationUtil.formatNonExistentUserGroupValidationResponse;
import static org.jenkinsci.plugins.matrixauth.ValidationUtil.formatUserGroupValidationResponse;

/**
 * Interface methods common to descriptors of authorization strategy and the various properties.
 *
 * Mostly some methods used from the similar configuration UI for these (reuse there).
 *
 */
@Restricted(NoExternalUse.class)
public interface AuthorizationContainerDescriptor<T extends AuthorizationContainer> {

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
                description += Messages.GlobalMatrixAuthorizationStrategy_PermissionImpliedBy(impliedBy.group.title, impliedBy.name);
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

        if (GlobalMatrixAuthorizationStrategy.ENABLE_DANGEROUS_PERMISSIONS || !GlobalMatrixAuthorizationStrategy.DANGEROUS_PERMISSIONS.contains(p)) {
            // we allow assignment of dangerous permissions, or it's a safe permission, so show it
            return true;
        }

        // if we grant any dangerous permission, show them all
        AuthorizationStrategy strategy = Jenkins.getInstance().getAuthorizationStrategy();
        if (strategy instanceof GlobalMatrixAuthorizationStrategy) {
            GlobalMatrixAuthorizationStrategy globalMatrixAuthorizationStrategy = (GlobalMatrixAuthorizationStrategy) strategy;
            return globalMatrixAuthorizationStrategy.isAnyRelevantDangerousPermissionExplicitlyGranted();
        }

        // don't show by default, i.e. when initially configuring the authorization strategy
        return false;
    }


    // Not used directly by Stapler due to the trailing _ (this prevented method confusion around 1.415).
    @Restricted(NoExternalUse.class)
    default FormValidation doCheckName_(@Nonnull String value, @Nonnull AccessControlled subject, @Nonnull Permission permission) {

        final String v = value.substring(1,value.length()-1);
        String ev = Functions.escape(v);

        if(!subject.hasPermission(permission))  return FormValidation.ok(ev); // can't check

        SecurityRealm sr = Jenkins.getInstance().getSecurityRealm();

        if(v.equals("authenticated"))
            // system reserved group
            return FormValidation.respond(FormValidation.Kind.OK, formatUserGroupValidationResponse("user.png", ev, "Group", false));

        try {
            try {
                sr.loadUserByUsername(v);
                User u = User.get(v);
                if (ev.equals(u.getFullName())) {
                    return FormValidation.respond(FormValidation.Kind.OK, formatUserGroupValidationResponse("person.png", ev, "User", false));
                }
                return FormValidation.respond(FormValidation.Kind.OK, formatUserGroupValidationResponse("person.png", Util.escape(StringUtils.abbreviate(u.getFullName(), 50)), "User " + ev, false));
            } catch (UserMayOrMayNotExistException e) {
                // undecidable, meaning the user may exist
                return FormValidation.respond(FormValidation.Kind.OK, ev);
            } catch (UsernameNotFoundException |DataAccessException e) {
                // fall through next
            } catch (AuthenticationException e) {
                // other seemingly unexpected error.
                return FormValidation.error(e,"Failed to test the validity of the user name "+v);
            }

            try {
                sr.loadGroupByGroupname(v);
                return FormValidation.respond(FormValidation.Kind.OK, formatUserGroupValidationResponse("user.png", ev, "Group", false));
            } catch (UserMayOrMayNotExistException e) {
                // undecidable, meaning the group may exist
                return FormValidation.respond(FormValidation.Kind.OK, ev);
            } catch (UsernameNotFoundException|DataAccessException e) {
                // fall through next
            } catch (AuthenticationException e) {
                // other seemingly unexpected error.
                return FormValidation.error(e,"Failed to test the validity of the group name "+v);
            }

            // couldn't find it. it doesn't exist
            return FormValidation.respond(FormValidation.Kind.ERROR, formatNonExistentUserGroupValidationResponse(ev, "User or group not found")); // TODO i18n
        } catch (Exception e) {
            // if the check fails miserably, we still want the user to be able to see the name of the user,
            // so use 'ev' as the message
            return FormValidation.error(e,ev);
        }
    }

}
