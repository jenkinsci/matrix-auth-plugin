/*
 * This handles the addition of new users/groups to the list.
 */
Behaviour.specify(".matrix-auth-add-button", 'GlobalMatrixAuthorizationStrategy', 0, function(e) {
  makeButton(e, function (e) {
    var dataReference = e.target;
    var master = document.getElementById(dataReference.getAttribute('data-table-id'));
    var table = master.parentNode;
    var type = dataReference.getAttribute('data-type');
    var typeLabel = dataReference.getAttribute('data-type-label');

    var name = prompt(dataReference.getAttribute('data-message-prompt'));
    if (name == null) {
      return;
    }
    if(name=="") {
      alert(dataReference.getAttribute('data-message-empty'));
      return;
    }
    if(findElementsBySelector(table,"TR").find(function(n){return n.getAttribute("name")=='['+type+':'+name+']';})!=null) {
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
    copy.setAttribute("name",'['+type+':'+name+']');

    for(var child = copy.firstChild; child !== null; child = child.nextSibling) {
      if (child.hasAttribute('data-permission-id')) {
        child.setAttribute("data-tooltip-enabled", child.getAttribute("data-tooltip-enabled").replace("__SID__", name).replace("__TYPE__", typeLabel));
        child.setAttribute("data-tooltip-disabled", child.getAttribute("data-tooltip-disabled").replace("__SID__", name).replace("__TYPE__", typeLabel));
      }
    }

    var tooltipAttributeName = getTooltipAttributeName();

    findElementsBySelector(copy, ".stop a").forEach(function(item) {
      let oldTitle = item.getAttribute("title");
      if (oldTitle !== null) {
        item.setAttribute("title", oldTitle.replace("__SID__", name).replace("__TYPE__", typeLabel));
      }
      item.setAttribute(tooltipAttributeName, item.getAttribute(tooltipAttributeName).replace("__SID__", name).replace("__TYPE__", typeLabel));
    });

    findElementsBySelector(copy, "input[type=checkbox]").forEach(function(item) {
      const tooltip = item.getAttribute(tooltipAttributeName);
      if (tooltip) {
        item.setAttribute(tooltipAttributeName, tooltip.replace("__SID__", name).replace("__TYPE__", typeLabel));
      } else {
        item.setAttribute("title", item.getAttribute("title").replace("__SID__", name).replace("__TYPE__", typeLabel));
      }
    });
    table.appendChild(copy);
    Behaviour.applySubtree(findAncestor(table,"TABLE"),true);
  });
});

/*
 * Behavior for the element removing a permission assignment row for a user/group
 */
Behaviour.specify(".global-matrix-authorization-strategy-table TD.stop A.remove", 'GlobalMatrixAuthorizationStrategy', 0, function(e) {
  e.onclick = function() {
    // Run ambiguity warning removal code: If all ambiguous rows are deleted, the warning needs to go as well
    // Order of operations: Find table ancestor, remove row, iterate over leftover rows
    var table = findAncestor(this,"TABLE");

    var tr = findAncestor(this,"TR");
    tr.parentNode.removeChild(tr);

    var tableRows = table.getElementsByTagName('tr');

    var hasAmbiguousRows = false;

    for (var i = 0; i < tableRows.length; i++) {
      if (tableRows[i].getAttribute('name') !== null && tableRows[i].getAttribute('name').startsWith('[EITHER')) {
        hasAmbiguousRows = true;
      }
    }
    if (!hasAmbiguousRows) {
      var alertElements = document.getElementsByClassName("alert");
      for (var i = 0; i < alertElements.length; i++) {
        if (alertElements[i].hasAttribute('data-table-id') && alertElements[i].getAttribute('data-table-id') === table.getAttribute('data-table-id')) {
          alertElements[i].style.display = 'none'; // TODO animate this?
        }
      }
    }

    return false;
  }
  e = null; // avoid memory leak
});

/*
 * Behavior for 'Select all' element that exists for each row of permissions checkboxes
 */
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

/*
 * Behavior for 'Unselect all' element that exists for each row of permissions checkboxes
 */
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

/*
 * Behavior for 'Migrate to user' element that exists for each ambiguous row
 */
Behaviour.specify(".global-matrix-authorization-strategy-table TD.stop A.migrate", 'GlobalMatrixAuthorizationStrategy', 0, function(e) {
  e.onclick = function() {
    var tr = findAncestor(this,"TR");
    var name = tr.getAttribute('name');

    var newName = name.replace('[EITHER:', '[USER:'); // migrate_user behavior
    if (this.classList.contains('migrate_group')) {
      newName = name.replace('[EITHER:', '[GROUP:');
    }

    var table = findAncestor(this,"TABLE");
    var tableRows = table.getElementsByTagName('tr');
    var newNameElement = null;
    for (var i = 0; i < tableRows.length; i++) {
      if (tableRows[i].getAttribute('name') === newName) {
        newNameElement = tableRows[i];
        break;
      }
    }
    if (newNameElement === tr) {
      // uh-oh, we shouldn't be able to find ourselves, so just do nothing
      return false;
    }
    if (newNameElement == null) {
      // no row for this name exists yet, so transform the ambiguous row to unambiguous
      tr.setAttribute('name', newName);
      tr.removeAttribute('data-checked');

      // remove migration buttons from updated row
      var buttonContainer = findAncestor(this, "TD");
      var migrateButtons = buttonContainer.getElementsByClassName('migrate');
      for (var i = migrateButtons.length - 1; i >= 0; i--) {
        buttonContainer.removeChild(migrateButtons[i]);
      }
    } else {
      // there's already a row for the migrated name (unusual but OK), so merge them

      // migrate permissions from this row
      var ambiguousPermissionInputs = tr.getElementsByTagName("INPUT");
      var unambiguousPermissionInputs = newNameElement.getElementsByTagName("INPUT");
      for (var i = 0; i < ambiguousPermissionInputs.length; i++){
        if(ambiguousPermissionInputs[i].type == "checkbox") {
          unambiguousPermissionInputs[i].checked |= ambiguousPermissionInputs[i].checked;
        }
        newNameElement.classList.add('highlight-entry');
      }

      // remove this row
      tr.parentNode.removeChild(tr);
    }
    Behaviour.applySubtree(table, true);

    var hasAmbiguousRows = false;

    for (var i = 0; i < tableRows.length; i++) {
      if (tableRows[i].getAttribute('name') !== null && tableRows[i].getAttribute('name').startsWith('[EITHER')) {
        hasAmbiguousRows = true;
      }
    }
    if (!hasAmbiguousRows) {
      var alertElements = document.getElementsByClassName("alert");
      for (var i = 0; i < alertElements.length; i++) {
        if (alertElements[i].hasAttribute('data-table-id') && alertElements[i].getAttribute('data-table-id') === table.getAttribute('data-table-id')) {
          alertElements[i].style.display = 'none'; // TODO animate this?
        }
      }
    }

    return false;
  };
  e = null; // avoid memory leak
});

/*
 * Determine which attribute to set tooltips in. Changed in Jenkins 2.379 with Tippy and data-html-tooltip support.
 */
function getTooltipAttributeName() {
  let coreVersion = document.body.getAttribute('data-version');
  if (coreVersion === null) {
    return 'tooltip'
  }
  // TODO remove after minimum version is 2.379 or higher
  let tippySupported = coreVersion >= '2.379';
  return tippySupported ? 'data-html-tooltip' : 'tooltip';
}

/*
 * Whenever permission assignments change, this ensures that implied permissions get their checkboxes disabled.
 */
Behaviour.specify(".global-matrix-authorization-strategy-table td input", 'GlobalMatrixAuthorizationStrategy', 0, function(e) {
  var table = findAncestor(e, "TABLE");
  if (table.classList.contains('read-only')) {
    // if this is a read-only UI (ExtendedRead / SystemRead), do not enable checkboxes
    return;
  }

  var tooltipAttributeName = getTooltipAttributeName();

  var impliedByString = findAncestor(e, "TD").getAttribute('data-implied-by-list');
  var impliedByList = impliedByString.split(" ");
  var tr = findAncestor(e,"TR");
  e.disabled = false;
  let tooltip = YAHOO.lang.escapeHTML(findAncestor(e, "TD").getAttribute('data-tooltip-enabled'));
  e.setAttribute(tooltipAttributeName, tooltip); // before 2.335 -- TODO remove once baseline is new enough
  e.nextSibling.setAttribute(tooltipAttributeName, tooltip); // 2.335+

  for (var i = 0; i < impliedByList.length; i++) {
    var permissionId = impliedByList[i];
    var reference = tr.querySelector("td[data-permission-id='" + permissionId + "'] input");
    if (reference !== null) {
      if (reference.checked) {
        e.disabled = true;
        let tooltip = YAHOO.lang.escapeHTML(findAncestor(e, "TD").getAttribute('data-tooltip-disabled'));
        e.setAttribute(tooltipAttributeName, tooltip); // before 2.335 -- TODO remove once baseline is new enough
        e.nextSibling.setAttribute(tooltipAttributeName, tooltip); // 2.335+
      }
    }
  }

  if (window.registerTooltips) {
    window.registerTooltips(e.nextSibling.parentElement);
  }

  e.onchange = function() {
    Behaviour.applySubtree(findAncestor(this,"TABLE"),true);
    return true;
  };
  e = null; // avoid memory leak
});

/*
 * Each newly added row needs to have the name checked. Triggered by explicit Behaviour#applySubtree calls elsewhere.
 */
Behaviour.specify(".global-matrix-authorization-strategy-table TR.permission-row", 'GlobalMatrixAuthorizationStrategy', 0, function(e) {
  if (e.getAttribute('name') === '__unused__') {
    return;
  }
  if (!e.hasAttribute('data-checked')) {
    FormChecker.delayedCheck(e.getAttribute('data-descriptor-url') + "/checkName?value="+encodeURIComponent(e.getAttribute("name")),"GET",e.firstChild);
    e.setAttribute('data-checked', 'true');
  }
});
