/*
 * The MIT License
 *
 * Copyright (c) 2017 CloudBees, Inc.
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
package hudson.security;

import hudson.Extension;
import hudson.model.AdministrativeMonitor;
import hudson.util.HttpResponses;
import jenkins.model.Jenkins;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.interceptor.RequirePOST;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Administrative monitor that shows up when 'dangerous' permissions are granted to non-admin users.
 * Those are permissions that could be used to grant themselves administer permissions.
 *
 * See also https://jenkins.io/security/advisory/2017-04-10/#matrix-authorization-strategy-plugin-allowed-configuring-dangerous-permissions
 */
@Extension
@Restricted(NoExternalUse.class)
public class DangerousMatrixPermissionsAdministrativeMonitor extends AdministrativeMonitor {
    @Override
    public boolean isActivated() {
        return !GlobalMatrixAuthorizationStrategy.ENABLE_DANGEROUS_PERMISSIONS && !getSidsWithDangerousPermissions().isEmpty();
    }

    @RequirePOST
    public HttpResponse doAct(@QueryParameter String yes) {
        if (yes != null) {
            return HttpResponses.redirectViaContextPath("configureSecurity");
        }
        return HttpResponses.redirectToDot();
    }

    public List<String> getSidsWithDangerousPermissions() {
        Jenkins j = Jenkins.getInstance();

        if (!(j.getAuthorizationStrategy() instanceof GlobalMatrixAuthorizationStrategy)) {
            return Collections.emptyList();
        }

        List<String> sids = new ArrayList<>();

        GlobalMatrixAuthorizationStrategy strategy = (GlobalMatrixAuthorizationStrategy) j.getAuthorizationStrategy();

        List<String> allSidsPlusAnon = new ArrayList<>(strategy.getAllSIDs());
        allSidsPlusAnon.add("anonymous");

        for (String sid : allSidsPlusAnon) {
            if (!strategy.hasPermission(sid, Jenkins.ADMINISTER) && strategy.isAnyRelevantDangerousPermissionExplicitlyGranted(sid)) {
                sids.add(sid);
            }
        }
        return sids;
    }

    @Override
    public String getDisplayName() {
        return "Matrix Authorization: Dangerous Permissions";
    }
}
