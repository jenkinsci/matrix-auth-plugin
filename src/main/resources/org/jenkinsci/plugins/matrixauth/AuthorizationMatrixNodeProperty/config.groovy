package org.jenkinsci.plugins.matrixauth.AuthorizationMatrixNodeProperty

import lib.FormTagLib
import org.jenkinsci.plugins.matrixauth.inheritance.InheritanceStrategyDescriptor

def f = namespace(FormTagLib)
def st = namespace("jelly:stapler")

f.nested {
    table(style: "width: 100%") {
        f.dropdownDescriptorSelector(title: _("Inheritance Strategy"), descriptors: InheritanceStrategyDescriptor.getApplicableDescriptors(my.class), field: 'inheritanceStrategy')
//        f.optionalBlock(field: "blocksInheritance", title:_("Block inheritance of global authorization matrix"))
        st.include(class: "hudson.security.GlobalMatrixAuthorizationStrategy", page: "config")
    }
}
