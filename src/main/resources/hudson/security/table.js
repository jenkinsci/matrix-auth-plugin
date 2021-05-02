Behaviour.specify(".matrix-auth-add-user-button", 'GlobalMatrixAuthorizationStrategy', 0, function(e) {
  makeButton(e, function (e) {
    var dataReference = e.target;
    var master = document.getElementById(dataReference.getAttribute('data-table-id'));
    var table = master.parentNode;

    // when 'add' is clicked...
    var name = prompt(dataReference.getAttribute('data-message-prompt'));
    if (name == null) {
      return;
    }
    if(name=="") {
      alert(dataReference.getAttribute('data-message-empty'));
      return;
    }
    if(findElementsBySelector(table,"TR").find(function(n){return n.getAttribute("name")=='['+name+']';})!=null) {
      alert(dataReference.getAttribute('data-message-error'));
      return;
    }

    if(document.importNode!=null)
      copy = document.importNode(master,true);
    else
      copy = master.cloneNode(true); // for IE
    copy.removeAttribute("id");
    copy.removeAttribute("style");
    copy.firstChild.innerHTML = YAHOO.lang.escapeHTML(name); // TODO consider setting innerText
    copy.setAttribute("name",'['+name+']');

    for(var child = copy.firstChild; child !== null; child = child.nextSibling) {
      if (child.hasAttribute('data-permission-id')) {
        child.setAttribute("data-tooltip-enabled", child.getAttribute("data-tooltip-enabled").replace("__SID__", name));
        child.setAttribute("data-tooltip-disabled", child.getAttribute("data-tooltip-disabled").replace("__SID__", name));
      }
    }
    findElementsBySelector(copy, ".stop img").each(function(item) {
      item.setAttribute("title", item.getAttribute("title").replace("__SID__", name));
    });
    findElementsBySelector(copy, "input[type=checkbox]").each(function(item) {
      item.setAttribute("title", item.getAttribute("title").replace("__SID__", name));
    });
    table.appendChild(copy);
    Behaviour.applySubtree(findAncestor(table,"TABLE"),true);
  });
});

Behaviour.specify(".global-matrix-authorization-strategy-table TD.stop A.remove", 'GlobalMatrixAuthorizationStrategy', 0, function(e) {
  e.onclick = function() {
    var tr = findAncestor(this,"TR");
    tr.parentNode.removeChild(tr);
    return false;
  }
  e = null; // avoid memory leak
});

Behaviour.specify(".global-matrix-authorization-strategy-table TD.stop A.selectall", 'GlobalMatrixAuthorizationStrategy', 0, function(e) {
  e.onclick = function() {
    var tr = findAncestor(this,"TR");
    var inputs = tr.getElementsByTagName("INPUT");
    for(var i=0; i < inputs.length; i++){
        if(inputs[i].type == "checkbox") inputs[i].checked = true;
    }
    Behaviour.applySubtree(findAncestor(this,"TABLE"),true);
    return false;
  };
  e = null; // avoid memory leak
});

Behaviour.specify(".global-matrix-authorization-strategy-table TD.stop A.unselectall", 'GlobalMatrixAuthorizationStrategy', 0, function(e) {
  e.onclick = function() {
    var tr = findAncestor(this,"TR");
    var inputs = tr.getElementsByTagName("INPUT");
    for(var i=0; i < inputs.length; i++){
        if(inputs[i].type == "checkbox") inputs[i].checked = false;
    }
    Behaviour.applySubtree(findAncestor(this,"TABLE"),true);
    return false;
  };
  e = null; // avoid memory leak
});

Behaviour.specify(".global-matrix-authorization-strategy-table td input", 'GlobalMatrixAuthorizationStrategy', 0, function(e) {
  var impliedByString = findAncestor(e, "TD").getAttribute('data-implied-by-list');
  var impliedByList = impliedByString.split(" ");
  var tr = findAncestor(e,"TR");
  e.disabled = false;
  e.setAttribute('tooltip', YAHOO.lang.escapeHTML(findAncestor(e, "TD").getAttribute('data-tooltip-enabled')));

  for (var i = 0; i < impliedByList.length; i++) {
    var permissionId = impliedByList[i];
    var reference = tr.querySelector("td[data-permission-id='" + permissionId + "'] input");
    if (reference !== null) {
      if (reference.checked) {
        e.disabled = true;
        e.setAttribute('tooltip', YAHOO.lang.escapeHTML(findAncestor(e, "TD").getAttribute('data-tooltip-disabled')));
      }
    }
  }
  e.onchange = function() {
    Behaviour.applySubtree(findAncestor(this,"TABLE"),true);
    return true;
  };
  e = null; // avoid memory leak
});

// validates the name
Behaviour.specify(".global-matrix-authorization-strategy-table TR.permission-row", 'GlobalMatrixAuthorizationStrategy', 0, function(e) {
  if (e.getAttribute('name') === '__unused__') {
    return;
  }
  if (!e.hasAttribute('data-checked')) {
    FormChecker.delayedCheck(e.getAttribute('data-descriptor-url') + "/checkName?value="+encodeURIComponent(e.getAttribute("name")),"GET",e.firstChild);
    e.setAttribute('data-checked', 'true');
  }
});
