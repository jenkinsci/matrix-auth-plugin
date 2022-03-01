package hudson.security.AuthorizationMatrixProperty

import hudson.model.Item
import lib.FormTagLib
import org.jenkinsci.plugins.matrixauth.inheritance.InheritanceStrategyDescriptor

def f = namespace(FormTagLib)
def st = namespace("jelly:stapler")

f.optionalBlock(name: 'useProjectSecurity', checked: instance != null, title: _("Enable project-based security")) {
    f.nested {
        div {
            // It is unclear whether we can expect every Item to be an AbstractItem. While I've been unsuccessful finding one in a quick search, better be safe here and just offer fewer options if necessary.
            f.dropdownDescriptorSelector(title: _("Inheritance Strategy"), descriptors: InheritanceStrategyDescriptor.getApplicableDescriptors(my?.class?: Item.class), field: 'inheritanceStrategy')
            st.include(class: "hudson.security.GlobalMatrixAuthorizationStrategy", page: "config")
        }
    }
}