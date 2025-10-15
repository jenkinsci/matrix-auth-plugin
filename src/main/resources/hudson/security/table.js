/* global Behaviour, dialog, FormChecker, findElementsBySelector */

function matrixAuthEscapeHtml(html) {
  return html.replace(/'/g, "&apos;").replace(/"/g, "&quot;").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/*
 * This handles the addition of new users/groups to the list.
 */
Behaviour.specify(".matrix-auth-add-button", "GlobalMatrixAuthorizationStrategy", 0, function (e) {
  e.onclick = function (e) {
    const dataReference = e.target;
    const master = document.getElementById(dataReference.getAttribute("data-template-id")).content.firstElementChild.cloneNode(true);
    const table = document.getElementById(dataReference.getAttribute("data-table-id"));
    const tBody = table.tBodies[0];
    const type = dataReference.getAttribute("data-type");
    const typeLabel = dataReference.getAttribute("data-type-label");

    dialog
      .prompt(dataReference.getAttribute("data-message-title"), {
        message: dataReference.getAttribute("data-message-prompt"),
      })
      .then(
        (name) => {
          if (
            findElementsBySelector(tBody, "TR").find(function (n) {
              return n.getAttribute("name") === "[" + type + ":" + name + "]";
            }) != null
          ) {
            dialog.alert(dataReference.getAttribute("data-message-error"));
            return;
          }

          const copy = document.importNode(master, true);
          copy.removeAttribute("id");
          copy.removeAttribute("style");
          copy.firstChild.innerHTML = matrixAuthEscapeHtml(name); // TODO consider setting innerText
          copy.setAttribute("name", "[" + type + ":" + name + "]");

          for (let child = copy.firstChild; child !== null; child = child.nextSibling) {
            if (child.hasAttribute("data-permission-id")) {
              child.setAttribute("data-tooltip-enabled", child.getAttribute("data-tooltip-enabled").replace("__SID__", name).replace("__TYPE__", typeLabel));
              child.setAttribute("data-tooltip-disabled", child.getAttribute("data-tooltip-disabled").replace("__SID__", name).replace("__TYPE__", typeLabel));
            }
          }

          const tooltipAttributeName = "data-html-tooltip";

          findElementsBySelector(copy, ".stop a").forEach(function (item) {
            item.setAttribute(tooltipAttributeName, item.getAttribute(tooltipAttributeName).replace("__SID__", name).replace("__TYPE__", typeLabel));
          });

          findElementsBySelector(copy, "input[type=checkbox]").forEach(function (item) {
            const tooltip = item.nextSibling.getAttribute(tooltipAttributeName);
            if (tooltip) {
              item.nextSibling.setAttribute(tooltipAttributeName, tooltip.replace("__SID__", name).replace("__TYPE__", typeLabel));
            }
          });
          tBody.appendChild(copy);
          Behaviour.applySubtree(table, true);
        },
        () => {},
      );
  };
});

/*
 * Behavior for the element removing a permission assignment row for a user/group
 */
Behaviour.specify(".global-matrix-authorization-strategy-table TD.stop A.remove", "GlobalMatrixAuthorizationStrategy", 0, function (e) {
  e.onclick = function () {
    // Run ambiguity warning removal code: If all ambiguous rows are deleted, the warning needs to go as well
    // Order of operations: Find table ancestor, remove row, iterate over leftover rows
    const table = this.closest("TABLE");

    const tr = this.closest("TR");
    tr.parentNode.removeChild(tr);

    const tableRows = table.getElementsByTagName("tr");

    let hasAmbiguousRows = false;

    for (let i = 0; i < tableRows.length; i++) {
      if (tableRows[i].getAttribute("name") !== null && tableRows[i].getAttribute("name").startsWith("[EITHER")) {
        hasAmbiguousRows = true;
      }
    }
    if (!hasAmbiguousRows) {
      const alertElements = document.getElementsByClassName("alert");
      for (let i = 0; i < alertElements.length; i++) {
        if (alertElements[i].hasAttribute("data-table-id") && alertElements[i].getAttribute("data-table-id") === table.getAttribute("data-table-id")) {
          alertElements[i].style.display = "none"; // TODO animate this?
        }
      }
    }

    return false;
  };
});

/*
 * Behavior for 'Select all' element that exists for each row of permissions checkboxes
 */
Behaviour.specify(".global-matrix-authorization-strategy-table TD.stop A.selectall", "GlobalMatrixAuthorizationStrategy", 0, function (e) {
  e.onclick = function () {
    const tr = this.closest("TR");
    const inputs = tr.getElementsByTagName("INPUT");
    for (let i = 0; i < inputs.length; i++) {
      if (inputs[i].type === "checkbox") {
        inputs[i].checked = true;
      }
    }
    Behaviour.applySubtree(this.closest("TABLE"), true);
    return false;
  };
});

/*
 * Behavior for 'Unselect all' element that exists for each row of permissions checkboxes
 */
Behaviour.specify(".global-matrix-authorization-strategy-table TD.stop A.unselectall", "GlobalMatrixAuthorizationStrategy", 0, function (e) {
  e.onclick = function () {
    const tr = this.closest("TR");
    const inputs = tr.getElementsByTagName("INPUT");
    for (let i = 0; i < inputs.length; i++) {
      if (inputs[i].type === "checkbox") {
        inputs[i].checked = false;
      }
    }
    Behaviour.applySubtree(this.closest("TABLE"), true);
    return false;
  };
});

/*
 * Behavior for 'Migrate to user' element that exists for each ambiguous row
 */
Behaviour.specify(".global-matrix-authorization-strategy-table TD.stop A.migrate", "GlobalMatrixAuthorizationStrategy", 0, function (e) {
  e.onclick = function () {
    const tr = this.closest("TR");
    const name = tr.getAttribute("name");

    let newName = name.replace("[EITHER:", "[USER:"); // migrate_user behavior
    if (this.classList.contains("migrate_group")) {
      newName = name.replace("[EITHER:", "[GROUP:");
    }

    const table = this.closest("TABLE");
    const tableRows = table.getElementsByTagName("tr");
    let newNameElement = null;
    for (let i = 0; i < tableRows.length; i++) {
      if (tableRows[i].getAttribute("name") === newName) {
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
      tr.setAttribute("name", newName);
      tr.removeAttribute("data-checked");

      // remove migration buttons from updated row
      const buttonContainer = this.closest("DIV");
      const migrateButtons = buttonContainer.getElementsByClassName("migrate");
      for (let i = migrateButtons.length - 1; i >= 0; i--) {
        buttonContainer.removeChild(migrateButtons[i]);
      }
    } else {
      // there's already a row for the migrated name (unusual but OK), so merge them

      // migrate permissions from this row
      const ambiguousPermissionInputs = tr.getElementsByTagName("INPUT");
      const unambiguousPermissionInputs = newNameElement.getElementsByTagName("INPUT");
      for (let i = 0; i < ambiguousPermissionInputs.length; i++) {
        if (ambiguousPermissionInputs[i].type === "checkbox") {
          unambiguousPermissionInputs[i].checked |= ambiguousPermissionInputs[i].checked;
        }
        newNameElement.classList.add("highlight-entry");
      }

      // remove this row
      tr.parentNode.removeChild(tr);
    }
    Behaviour.applySubtree(table, true);

    let hasAmbiguousRows = false;

    for (let i = 0; i < tableRows.length; i++) {
      if (tableRows[i].getAttribute("name") !== null && tableRows[i].getAttribute("name").startsWith("[EITHER")) {
        hasAmbiguousRows = true;
      }
    }
    if (!hasAmbiguousRows) {
      let alertElements = document.getElementsByClassName("alert");
      for (let i = 0; i < alertElements.length; i++) {
        if (alertElements[i].hasAttribute("data-table-id") && alertElements[i].getAttribute("data-table-id") === table.getAttribute("data-table-id")) {
          alertElements[i].style.display = "none"; // TODO animate this?
        }
      }
    }

    return false;
  };
});

/*
 * Whenever permission assignments change, this ensures that implied permissions get their checkboxes disabled.
 */
Behaviour.specify(".global-matrix-authorization-strategy-table td input", "GlobalMatrixAuthorizationStrategy", 0, function (e) {
  const table = e.closest("TABLE");
  if (table.classList.contains("read-only")) {
    // if this is a read-only UI (ExtendedRead / SystemRead), do not enable checkboxes
    return;
  }

  const tooltipAttributeName = "data-html-tooltip";

  const impliedByString = e.closest("TD").getAttribute("data-implied-by-list");
  const impliedByList = impliedByString.split(" ");
  const tr = e.closest("TR");
  e.disabled = false;
  let tooltip = matrixAuthEscapeHtml(e.closest("TD").getAttribute("data-tooltip-enabled"));
  e.nextSibling.setAttribute(tooltipAttributeName, tooltip);

  for (let i = 0; i < impliedByList.length; i++) {
    let permissionId = impliedByList[i];
    let reference = tr.querySelector("td[data-permission-id='" + permissionId + "'] input");
    if (reference !== null) {
      if (reference.checked) {
        e.disabled = true;
        let tooltip = matrixAuthEscapeHtml(e.closest("TD").getAttribute("data-tooltip-disabled"));
        e.nextSibling.setAttribute(tooltipAttributeName, tooltip);
      }
    }
  }

  e.onchange = function () {
    Behaviour.applySubtree(this.closest("TABLE"), true);
    return true;
  };
});

/*
 * Each newly added row needs to have the name checked. Triggered by explicit Behaviour#applySubtree calls elsewhere.
 */
Behaviour.specify(".global-matrix-authorization-strategy-table TR.permission-row", "GlobalMatrixAuthorizationStrategy", 0, function (e) {
  if (e.getAttribute("name") === "__unused__") {
    return;
  }
  if (!e.hasAttribute("data-checked")) {
    FormChecker.delayedCheck(e.getAttribute("data-descriptor-url") + "/checkName?value=" + encodeURIComponent(e.getAttribute("name")), "GET", e.firstChild);
    e.setAttribute("data-checked", "true");
  }
});
