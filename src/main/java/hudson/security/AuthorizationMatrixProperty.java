/*
 * The MIT License
 * 
 * Copyright (c) 2004-2010, Sun Microsystems, Inc., Kohsuke Kawaguchi, Yahoo! Inc., Peter Hayes, Tom Huybrechts
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

import hudson.diagnosis.OldDataMonitor;
import hudson.model.Item;
import hudson.model.Job;
import hudson.model.JobProperty;
import hudson.model.JobPropertyDescriptor;
import jenkins.model.Jenkins;
import hudson.Extension;
import hudson.util.FormValidation;
import hudson.util.RobustReflectionConverter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Collections;
import java.util.Map.Entry;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.io.IOException;

import net.sf.json.JSONObject;

import org.acegisecurity.acls.sid.Sid;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.AncestorInPath;

import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import javax.annotation.CheckForNull;

import javax.servlet.ServletException;

/**
 * {@link JobProperty} to associate ACL for each project.
 *
 * <p>
 * Once created (and initialized), this object becomes immutable.
 */
public class AuthorizationMatrixProperty extends JobProperty<Job<?, ?>> {

	private transient SidACL acl = new AclImpl();

	/**
	 * List up all permissions that are granted.
	 * 
	 * Strings are either the granted authority or the principal, which is not
	 * distinguished.
	 */
	private final Map<Permission, Set<String>> grantedPermissions = new HashMap<Permission, Set<String>>();

	private Set<String> sids = new HashSet<String>();

    private boolean blocksInheritance = false;

    private AuthorizationMatrixProperty() {
    }

    public AuthorizationMatrixProperty(Map<Permission, Set<String>> grantedPermissions) {
        // do a deep copy to be safe
        for (Entry<Permission,Set<String>> e : grantedPermissions.entrySet())
            this.grantedPermissions.put(e.getKey(),new HashSet<String>(e.getValue()));
    }

	public Set<String> getGroups() {
		return sids;
	}

	/**
	 * Returns all SIDs configured in this matrix, minus "anonymous"
	 * 
	 * @return Always non-null.
	 */
	public List<String> getAllSIDs() {
		Set<String> r = new HashSet<String>();
		for (Set<String> set : grantedPermissions.values())
			r.addAll(set);
		r.remove("anonymous");

		String[] data = r.toArray(new String[r.size()]);
		Arrays.sort(data);
		return Arrays.asList(data);
	}

    /**
     * Returns all the (Permission,sid) pairs that are granted, in the multi-map form.
     *
     * @return
     *      read-only. never null.
     */
    public Map<Permission,Set<String>> getGrantedPermissions() {
        return Collections.unmodifiableMap(grantedPermissions);
    }

    /**
	 * Adds to {@link #grantedPermissions}. Use of this method should be limited
	 * during construction, as this object itself is considered immutable once
	 * populated.
	 */
	protected void add(Permission p, String sid) {
		Set<String> set = grantedPermissions.get(p);
		if (set == null)
			grantedPermissions.put(p, set = new HashSet<String>());
		set.add(sid);
		sids.add(sid);
	}

    @Extension
    public static class DescriptorImpl extends JobPropertyDescriptor {
		@Override
		public JobProperty<?> newInstance(StaplerRequest req, JSONObject formData) throws FormException {
            formData = formData.getJSONObject("useProjectSecurity");
            if (formData.isNullObject())
                return null;

            AuthorizationMatrixProperty amp = new AuthorizationMatrixProperty();

            // Disable inheritance, if so configured
            amp.setBlocksInheritance(!formData.getJSONObject("blocksInheritance").isNullObject());

            Map<String,Object> data = formData.getJSONObject("data");
            for (Map.Entry<String, Object> r : data.entrySet()) {
                String sid = r.getKey();
                if (!(r.getValue() instanceof JSONObject)) {
                    throw new FormException("not an object: " + formData, "data");
                }
                Map<String,Object> value = (JSONObject) r.getValue();
                for (Map.Entry<String,Object> e : value.entrySet()) {
                    if (!(e.getValue() instanceof Boolean)) {
                        throw new FormException("not a boolean: " + formData, "data");
                    }
                    if ((Boolean) e.getValue()) {
                        Permission p = Permission.fromId(e.getKey());
                        amp.add(p, sid);
                    }
                }
            }
			return amp;
		}

		@Override
		public boolean isApplicable(Class<? extends Job> jobType) {
            // only applicable when ProjectMatrixAuthorizationStrategy is in charge
            return Jenkins.getInstance().getAuthorizationStrategy() instanceof ProjectMatrixAuthorizationStrategy;
		}

		@Override
		public String getDisplayName() {
			return "Authorization Matrix";
		}

		public List<PermissionGroup> getAllGroups() {
            List<PermissionGroup> r = new ArrayList<PermissionGroup>();
            for (PermissionGroup pg : PermissionGroup.getAll()) {
                if (pg.hasPermissionContainedBy(PermissionScope.ITEM))
                    r.add(pg);
            }
            return r;
		}

        public boolean showPermission(Permission p) {
            return p.getEnabled() && p.isContainedBy(PermissionScope.ITEM);
        }

        public FormValidation doCheckName(@AncestorInPath Item project, @QueryParameter String value) throws IOException, ServletException {
            return GlobalMatrixAuthorizationStrategy.DESCRIPTOR.doCheckName_(value, project, Item.CONFIGURE);
        }
    }

	private final class AclImpl extends SidACL {
                @CheckForNull
                @SuppressFBWarnings(value = "NP_BOOLEAN_RETURN_NULL", 
                        justification = "As designed, implements a third state for the ternary logic")
		protected Boolean hasPermission(Sid sid, Permission p) {
			if (AuthorizationMatrixProperty.this.hasPermission(toString(sid),p)) {
				return true;
                        }
			return null;
		}
	}

	public SidACL getACL() {
		return acl;
	}

	/**
	 * Sets the flag to block inheritance
	 *
	 * @param blocksInheritance
	 */
	private void setBlocksInheritance(boolean blocksInheritance) {
		this.blocksInheritance = blocksInheritance;
	}

	/**
	 * Returns true if the authorization matrix is configured to block
	 * inheritance from the parent.
	 *
	 * @return
	 */
	public boolean isBlocksInheritance() {
		return this.blocksInheritance;
	}

	/**
	 * Checks if the given SID has the given permission.
	 */
	public boolean hasPermission(String sid, Permission p) {
		for (; p != null; p = p.impliedBy) {
			Set<String> set = grantedPermissions.get(p);
			if (set != null && set.contains(sid))
				return true;
		}
		return false;
	}

    /**
     * Checks if the permission is explicitly given, instead of implied through {@link Permission#impliedBy}.
     */
    public boolean hasExplicitPermission(String sid, Permission p) {
        Set<String> set = grantedPermissions.get(p);
        return set != null && set.contains(sid);
    }
    
    /**
     * Works like {@link #add(Permission, String)} but takes both parameters
     * from a single string of the form <tt>PERMISSIONID:sid</tt>
     */
    private void add(String shortForm) {
        int idx = shortForm.indexOf(':');
        Permission p = Permission.fromId(shortForm.substring(0, idx));
        if (p==null)
            throw new IllegalArgumentException("Failed to parse '"+shortForm+"' --- no such permission");
        add(p, shortForm.substring(idx + 1));
    }

	/**
	 * Persist {@link ProjectMatrixAuthorizationStrategy} as a list of IDs that
	 * represent {@link ProjectMatrixAuthorizationStrategy#grantedPermissions}.
	 */
	public static final class ConverterImpl implements Converter {
		public boolean canConvert(Class type) {
			return type == AuthorizationMatrixProperty.class;
		}

		public void marshal(Object source, HierarchicalStreamWriter writer,
				MarshallingContext context) {
			AuthorizationMatrixProperty amp = (AuthorizationMatrixProperty) source;

            if (amp.isBlocksInheritance()) {
                writer.startNode("blocksInheritance");
                writer.setValue("true");
                writer.endNode();
            }

            for (Entry<Permission, Set<String>> e : amp.grantedPermissions
					.entrySet()) {
				String p = e.getKey().getId();
				for (String sid : e.getValue()) {
					writer.startNode("permission");
					writer.setValue(p + ':' + sid);
					writer.endNode();
				}
			}
		}

		public Object unmarshal(HierarchicalStreamReader reader,
				final UnmarshallingContext context) {
			AuthorizationMatrixProperty as = new AuthorizationMatrixProperty();

			String prop = reader.peekNextChild();

			if (prop!=null && prop.equals("useProjectSecurity")) {
				reader.moveDown();
				reader.getValue(); // we used to use this but not any more.
				reader.moveUp();
				prop = reader.peekNextChild(); // We check the next field
			}
			if ("blocksInheritance".equals(prop)) {
			    reader.moveDown();
			    as.setBlocksInheritance("true".equals(reader.getValue()));
			    reader.moveUp();
			}

			while (reader.hasMoreChildren()) {
                reader.moveDown();
                try {
                    as.add(reader.getValue());
                } catch (IllegalArgumentException ex) {
                     Logger.getLogger(AuthorizationMatrixProperty.class.getName())
                           .log(Level.WARNING,"Skipping a non-existent permission",ex);
                     RobustReflectionConverter.addErrorInContext(context, ex);
                }
                reader.moveUp();
            }

            if (GlobalMatrixAuthorizationStrategy.migrateHudson2324(as.grantedPermissions))
                OldDataMonitor.report(context, "1.301");

            return as;
        }
    }
}
