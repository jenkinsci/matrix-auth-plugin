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

import hudson.Functions;
import hudson.Util;
import hudson.model.User;
import hudson.security.SecurityRealm;
import hudson.security.UserMayOrMayNotExistException;
import hudson.util.FormValidation;
import hudson.util.VersionNumber;
import jenkins.model.Jenkins;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.Stapler;
import org.springframework.dao.DataAccessException;

@Restricted(NoExternalUse.class)
class ValidationUtil {
    private ValidationUtil() {
        // do not use
    }

    private static final VersionNumber jenkinsVersion = Jenkins.getVersion();

    static String formatNonExistentUserGroupValidationResponse(String user, String tooltip) {
        return formatUserGroupValidationResponse("user-disabled.svg", "<span style='text-decoration: line-through;'>" + tooltip + ": " + user + "</span>", tooltip, true);
    }

    static String formatUserGroupValidationResponse(String img, String label, String tooltip, boolean inPlugin) {
        if (img == null) {
            return String.format("<span title='%s'>%s</span>", tooltip, label);
        }
        if (inPlugin) {
            return String.format("<span title='%s'><img src='%s/plugin/matrix-auth/images/%s' style='margin-right:0.2em'>%s</span>", tooltip, Stapler.getCurrentRequest().getContextPath(), img, label);
        } else {
            if (jenkinsVersion.isOlderThan(new VersionNumber("2.308"))) {
                return String.format("<span title='%s'><img src='%s%s/images/16x16/%s.png' style='margin-right:0.2em'>%s</span>", tooltip, Stapler.getCurrentRequest().getContextPath(), Jenkins.RESOURCE_PATH, img, label);
            } else {
                return String.format("<span title='%s'><img src='%s%s/images/svgs/%s.svg' width='16' style='margin-right:0.2em'>%s</span>", tooltip, Stapler.getCurrentRequest().getContextPath(), Jenkins.RESOURCE_PATH, img, label);
            }
        }
    }

    static FormValidation validateGroup(String groupName, SecurityRealm sr, boolean ambiguous) {
        String escapedSid = Functions.escape(groupName);
        try {
            sr.loadGroupByGroupname(groupName);
            if (ambiguous) {
                return FormValidation.warningWithMarkup(formatUserGroupValidationResponse("user", escapedSid, "Group found; but permissions would also be granted to a user of this name", false));
            } else {
                return FormValidation.okWithMarkup(formatUserGroupValidationResponse("user", escapedSid, "Group", false));
            }
        } catch (UserMayOrMayNotExistException e) {
            // undecidable, meaning the group may exist
            if (ambiguous) {
                return FormValidation.warningWithMarkup(formatUserGroupValidationResponse("user", escapedSid, "Permissions would also be granted to a user or group of this name", false));
            } else {
                return FormValidation.ok(groupName);
            }
        } catch (UsernameNotFoundException | DataAccessException e) {
            // fall through next
        } catch (AuthenticationException e) {
            // other seemingly unexpected error.
            return FormValidation.error(e,"Failed to test the validity of the group name " + groupName);
        }
        return null;
    }

    static FormValidation validateUser(String userName, SecurityRealm sr, boolean ambiguous) {
        String escapedSid = Functions.escape(userName);
        try {
            sr.loadUserByUsername(userName);
            User u = User.get(userName); // TODO fix deprecated call while not loading users for this form validation (after 3.0)
            if (userName.equals(u.getFullName())) {
                // Sid and full name are identical, no need for tooltip
                if (ambiguous) {
                    return FormValidation.warningWithMarkup(formatUserGroupValidationResponse("person", escapedSid, "User found; but permissions would also be granted to a group of this name", false));
                } else {
                    return FormValidation.okWithMarkup(formatUserGroupValidationResponse("person", escapedSid, "User", false));
                }
            }
            if (ambiguous) {
                return FormValidation.warningWithMarkup(formatUserGroupValidationResponse("person", Util.escape(StringUtils.abbreviate(u.getFullName(), 50)), "User " + escapedSid + " found, but permissions would also be granted to a group of this name", false));
            } else {
                return FormValidation.okWithMarkup(formatUserGroupValidationResponse("person", Util.escape(StringUtils.abbreviate(u.getFullName(), 50)), "User " + escapedSid, false));
            }
        } catch (UserMayOrMayNotExistException e) {
            // undecidable, meaning the user may exist
            if (ambiguous) {
                return FormValidation.warningWithMarkup(formatUserGroupValidationResponse("person", escapedSid, "Permissions would also be granted to a user or group of this name", false));
            } else {
                return FormValidation.ok(userName);
            }
        } catch (UsernameNotFoundException |DataAccessException e) {
            // fall through next
        } catch (AuthenticationException e) {
            // other seemingly unexpected error.
            return FormValidation.error(e,"Failed to test the validity of the user name " + userName);
        }
        return null;
    }
}
