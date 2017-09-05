package hudson.security;

import hudson.model.Descriptor;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.StaplerRequest;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

public interface AuthorizationMatrixPropertyDescriptor<T extends AuthorizationProperty> {

    T createProperty();

    PermissionScope getPermissionScope();

    default T createNewInstance(StaplerRequest req, JSONObject formData) throws Descriptor.FormException {
        formData = formData.getJSONObject("useProjectSecurity");
        if (formData.isNullObject())
            return null;

        T amnp = createProperty();

        // Disable inheritance, if so configured
        amnp.setBlocksInheritance(!formData.getJSONObject("blocksInheritance").isNullObject());

        for (Map.Entry<String, Object> r : (Set<Map.Entry<String, Object>>) formData.getJSONObject("data").entrySet()) {
            String sid = r.getKey();
            if (r.getValue() instanceof JSONObject) {
                for (Map.Entry<String, Boolean> e : (Set<Map.Entry<String, Boolean>>) ((JSONObject) r
                        .getValue()).entrySet()) {
                    if (e.getValue()) {
                        Permission p = Permission.fromId(e.getKey());
                        amnp.add(p, sid);
                    }
                }
            }
        }
        return amnp;
    }

    default boolean isApplicable() {
        // only applicable when ProjectMatrixAuthorizationStrategy is in charge
        try {
            return Jenkins.getInstance().getAuthorizationStrategy() instanceof ProjectMatrixAuthorizationStrategy;
        } catch (NoClassDefFoundError x) { // after matrix-auth split?
            return false;
        }
    }

    default String getDisplayName() {
        return "Authorization Matrix";
    }

    default List<PermissionGroup> getAllGroups() {
        List<PermissionGroup> groups = new ArrayList<PermissionGroup>();
        for (PermissionGroup g : PermissionGroup.getAll()) {
            if (g.hasPermissionContainedBy(getPermissionScope())) {
                groups.add(g);
            }
        }
        return groups;
    }

    default boolean showPermission(Permission p) {
        return p.getEnabled() && p.isContainedBy(getPermissionScope());
    }
}
