/*
 * The MIT License
 *
 * Copyright (c) 2018 Configuration as Code Plugin Developers
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
package org.jenkinsci.plugins.matrixauth.integrations;

import hudson.security.Permission;
import hudson.security.PermissionGroup;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

import javax.annotation.CheckForNull;


/**
 * Implements lookup for {@link Permission}s.
 */
// Imported from https://github.com/jenkinsci/configuration-as-code-plugin/blob/727c976d137461f146b301f302d1552ca81de75e/plugin/src/main/java/io/jenkins/plugins/casc/util/PermissionFinder.java
@Restricted(NoExternalUse.class)
public class PermissionFinder {

    /** For Matrix Auth - Title/Permission **/
    private static final Pattern PERMISSION_PATTERN = Pattern.compile("^([^/]+)/(.+)$");

    /**
     * Attempt to match a given permission to what is defined in the UI.
     * @param id String of the form "Title/Permission" (Look in the UI) for a particular permission
     * @return a matched permission
     */
    @CheckForNull
    public static Permission findPermission(String id) {
        final String resolvedId = findPermissionId(id);
        return resolvedId != null ? Permission.fromId(resolvedId) : null;
    }

    /**
     * Attempt to match a given permission to what is defined in the UI.
     * @param id String of the form "Title/Permission" (Look in the UI) for a particular permission
     * @return a matched permission ID
     */
    @CheckForNull
    public static String findPermissionId(String id) {
        List<PermissionGroup> pgs = PermissionGroup.getAll();
        Matcher m = PERMISSION_PATTERN.matcher(id);
        if(m.matches()) {
            String owner = m.group(1);
            String name = m.group(2);
            for(PermissionGroup pg : pgs) {
                if(pg.owner.equals(Permission.class)) {
                    continue;
                }
                if(pg.getId().equals(owner)) {
                    return pg.owner.getName() + "." + name;
                }
            }
        }
        return null;
    }
}