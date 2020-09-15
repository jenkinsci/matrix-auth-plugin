package org.jenkinsci.plugins.matrixauth.AuthorizationMatrixNodeProperty

import lib.FormTagLib
import org.jenkinsci.plugins.matrixauth.inheritance.InheritanceStrategyDescriptor

def f = namespace(FormTagLib)
def c = namespace("/lib/matrixauth")
def st = namespace("jelly:stapler")

f.nested {
    c.blockWrapper {
        f.dropdownDescriptorSelector(title: _("Inheritance Strategy"), descriptors: InheritanceStrategyDescriptor.getApplicableDescriptors(my?.class?:hudson.model.Node.class), field: 'inheritanceStrategy')
        st.include(class: "hudson.security.GlobalMatrixAuthorizationStrategy", page: "config")
    }
}
